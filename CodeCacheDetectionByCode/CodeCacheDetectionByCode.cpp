// CodeCacheDetectionByCode.cpp : Defines the entry point for the console application.
//
// WinDBG
// pin.exe -- F:\Binarios\CodeCacheDetectionByCode.exe
// No x32dbg
// findallmem 01211000,90 90 50 58
// s - b 0 L ? 80000000 90 90 50 58

#include<stdlib.h>
#include<stdio.h>


// Origem: https://msdn.microsoft.com/pt-br/library/s58ftw19.aspx
#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION
#include <excpt.h>
#define _CRT_SECURE_NO_WARNINGS
#define UNINITIALIZED 0xFFFFFFFF

#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h> //PROCESSENTRY
// #include "MemUpdateMapInformations.h" vs #include <MemUpdateMapInformations.h>
// http://stackoverflow.com/a/7790180
#include "MemUpdateMapInformations.h"

#include <string.h>

// De acordo com:
// https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf
// Signature can be certain code or data
// #define padrao 1

/*
unsigned char* search(int startAddress)
{
	unsigned char* data;
	int sig_count = 0;
	int j = 0;

	int address = startAddress;
	int endAddress = 0x80000000;

	data = (unsigned char*)address;

	while (data < (unsigned char*)endAddress) {
		__try {
#ifndef padrao
			if (data[0] == 0x90 &&
				data[1] == 0x90 &&
				data[2] == 0x50 &&
				data[3] == 0x58)
#endif
#ifdef padrao
				if (data[0] == 0xBB &&
					data[1] == 0x78 &&
					data[2] == 0x56 &&
					data[3] == 0x34 &&
					data[4] == 0x12)
#endif
				{
					printf("\nAchou padrao asm, @ 0x%x\n", data);
					sig_count++;
					return data;
				}
				else {

					// http://stackoverflow.com/a/7319450
#ifndef padrao
					unsigned char* data_ = (unsigned char*)memchr((const void*)(data + 1), 0x9090, endAddress - startAddress);
#endif
#ifdef padrao
					// 0x5678 Aparece invertido, ja que buscamos 0x7856
					unsigned char* data_ = (unsigned char*)memchr((const void*)(data + 1), 0x5678BB, endAddress - startAddress);
#endif
					if (data_ == 0)
						return 0;
					else if (data == data_)
						return 0;
					else
						data = data_;
				}
		}
		//__except (filter(GetExceptionCode(), GetExceptionInformation())) {
		// Referencias: https://msdn.microsoft.com/pt-br/library/zazxh1a9.aspx
		// __except (puts("in filter"), EXCEPTION_EXECUTE_HANDLER) {
		__except (EXCEPTION_EXECUTE_HANDLER) {
			continue;
		}

	} // for
	return 0;
} 
*/

void printMemoryInformations(std::vector<MEMPAGE> pageVector, int pageCount)
{
	char curMod[MAX_MODULE_SIZE] = "";

	for (int i = pageCount - 1; i > -1; i--)
	{
		auto & currentPage = pageVector.at(i);
		if (!currentPage.info[0]) //there is a module
			continue; //skip non-modules
		strcpy(curMod, pageVector.at(i).info);
		printf("Informacoes da pagina %d : %s\t", i, curMod);
		DWORD newAddress = DWORD(currentPage.mbi.BaseAddress) + currentPage.mbi.RegionSize;
		printf("Tamanho: 0x%x\t", currentPage.mbi.RegionSize);
		printf("End Address 0x%x\n", newAddress);
	}

	system("pause");
}


int main(int argc, char** argv) {
	
	std::vector<MEMPAGE> pageVector = GetPageVector();

	int pagecount = (int)pageVector.size();
	printf("pagecount = %d\n", pagecount);

	for (int i = 0; i < pagecount - 1; i++) {
		auto & currentPage = pageVector.at(i);
		printf("Base address: %x\n", currentPage.mbi.BaseAddress);

		__try{
			//data = *reinterpret_cast<unsigned int *>(currentPage.mbi.BaseAddress);
			printf("%x\n", *reinterpret_cast<unsigned int *>(currentPage.mbi.BaseAddress));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			continue;
		}
	}

	system("pause");

	return 0;
}