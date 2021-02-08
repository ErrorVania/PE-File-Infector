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
	FileMemMapper(const char* file, DWORD dwDesiredAccess);
	~FileMemMapper();
	bool open(const char* file, DWORD dwDesiredAccess);
	void close();
};