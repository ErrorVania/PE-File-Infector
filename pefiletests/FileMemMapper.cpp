#include "FileMemMapper.h"

FileMemMapper::FileMemMapper() {
	MappedFileBase = nullptr;
	hFile = 0;
	hFileMapping = 0;
	filesize = 0;
}
FileMemMapper::FileMemMapper(const char* file, DWORD dwDesiredAccess = (FILE_READ_ACCESS | FILE_WRITE_ACCESS)) {
	MappedFileBase = nullptr;
	hFile = hFileMapping = 0;
	filesize = 0;
	open(file,dwDesiredAccess);
}
FileMemMapper::~FileMemMapper() {
	close();
}
bool FileMemMapper::open(const char* file, DWORD dwDesiredAccess = (FILE_READ_ACCESS | FILE_WRITE_ACCESS)) {
	hFile = CreateFileA(file,
		dwDesiredAccess,
		0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_FILE_NOT_FOUND) {
			std::cerr << "File Not Found" << std::endl;
			exit(1);
		}
	}

	filesize = GetFileSize(hFile, 0);
	hFileMapping = CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, filesize, 0);
	if (hFileMapping != 0) {
		MappedFileBase = (unsigned char*)MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, filesize);
		return true;
	}
	return false;
}
void FileMemMapper::close() {
	if (hFile != INVALID_HANDLE_VALUE) { 
		CloseHandle(hFile); 
		hFile = INVALID_HANDLE_VALUE; 
	}
	if (hFileMapping != INVALID_HANDLE_VALUE) {
		CloseHandle(hFileMapping); 
		hFile = INVALID_HANDLE_VALUE;
	}
}