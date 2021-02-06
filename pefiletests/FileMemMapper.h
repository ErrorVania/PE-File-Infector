#pragma once
#include <Windows.h>
#include <iostream>

class FileMemMapper {
private:
	HANDLE hFile, hFileMapping;

public:
	unsigned char* MappedFileBase;
	DWORD filesize;
	FileMemMapper();
	FileMemMapper(const wchar_t* file, DWORD dwDesiredAccess);
	~FileMemMapper();
	bool open(const wchar_t* file, DWORD dwDesiredAccess);
	void close();
};