#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

int main(void)
{
	/*
	HANDLE hFile = CreateFileW(
		L"C:\\Users\\somansa\\source\\repos\\ReflectiveDllInjectior\\Release\\DllExample.dll",
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (!hFile)
	{
		printf("Cannot find the DLL\n");
		return 1;
	}
	*/

	// 내장된 DLL의 주소 저장
	HRSRC hResInfo = FindResourceW(NULL, MAKEINTRESOURCEW(0x65), L"SHELLCODE");
	HANDLE hResData = LoadResource(NULL, hResInfo);
	BYTE* pFileBuffer = (BYTE*)LockResource(hResData);
	
	// 내장된 DLL의 크기 저장
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)pFileBuffer;
	IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((BYTE*)pDos + pDos->e_lfanew);
	DWORD dwFileSize = SizeofResource(NULL, hResInfo);
	DWORD dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;
	
	// 내장된 DLL의 크기만큼 공간 할당
	BYTE* pMem = (BYTE*)VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	// DLL Manual Mapping
	memcpy(pMem, pFileBuffer, pNt->OptionalHeader.SizeOfHeaders);
	IMAGE_SECTION_HEADER* pSectionHeader[16];
	
	ZeroMemory(pSectionHeader, sizeof(IMAGE_SECTION_HEADER*) * 16);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		pSectionHeader[i] = (IMAGE_SECTION_HEADER*)((BYTE*)pNt + 0x18 + 0x60 + 0x80 + sizeof(IMAGE_SECTION_HEADER) * i);
		memcpy(
			pMem + pSectionHeader[i]->VirtualAddress,
			pFileBuffer + pSectionHeader[i]->PointerToRawData,
			pSectionHeader[i]->SizeOfRawData
		);
	}
	/*
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		printf("%s\n", pSectionHeader[i]->Name);
		printf(
			"%02X %02X %02X %02X\n",
			*(pMem + pSectionHeader[i]->VirtualAddress),
			*(pMem + pSectionHeader[i]->VirtualAddress + 1),
			*(pMem + pSectionHeader[i]->VirtualAddress + 2),
			*(pMem + pSectionHeader[i]->VirtualAddress + 3)
		);
	}
	*/

	// DLL Relocation
	if (pMem != (BYTE*)pNt->OptionalHeader.ImageBase)
	{
		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
		{
			if (!strcmp((const char*)pSectionHeader[i]->Name, ".reloc"))
			{
				DWORD dwBaseDifference = (DWORD)pMem - pNt->OptionalHeader.ImageBase;
				DWORD dwRelocSectionSize = ((IMAGE_DATA_DIRECTORY*)((BYTE*)pNt + 0x18 + 0x88))->Size;
				BYTE* pRelocSection = pMem + pSectionHeader[i]->VirtualAddress;
				DWORD offset = 0;

				//printf("Original Base: 0x%X\n", pNt->OptionalHeader.ImageBase);
				//printf("New Base: 0x%X\n", pMem);
				//printf("Difference: 0x%X\n", (DWORD)pMem - pNt->OptionalHeader.ImageBase);
				//printf("\n");
				while (dwRelocSectionSize > offset)
				{
					IMAGE_BASE_RELOCATION* pRelocBlock = (IMAGE_BASE_RELOCATION*)(pRelocSection + offset);
					BYTE* pRelocBase = pMem + pRelocBlock->VirtualAddress;
					//printf("%X\n", pRelocBlock->VirtualAddress);
					DWORD nTypeOffset = (pRelocBlock->SizeOfBlock - 0x8) / 2;
					offset += 8;
					for (int j = 0; j < nTypeOffset; j++)
					{
						WORD wTypeOffset = *(WORD*)((BYTE*)pRelocSection + offset);
						if (wTypeOffset >> 12 == IMAGE_REL_BASED_HIGHLOW)
						{
							DWORD* ptr = (DWORD*)(pRelocBase + (wTypeOffset & 0xFFF));
							//printf("0x%X: 0x%X -> ", ptr, *ptr);
							*ptr = *ptr + dwBaseDifference;
							//printf("0x%X (%X)\n", *ptr, *(WORD*)((BYTE*)pRelocSection + offset));
						}
						offset += 2;
						//printf("%X/%X (%X %X)\n", offset, dwRelocSectionSize, pRelocBlock->SizeOfBlock, nTypeOffset);
					}
				}
			}
		}
	}

	// IAT Processing
	IMAGE_DATA_DIRECTORY* pImportDirectory = (IMAGE_DATA_DIRECTORY*)&pNt->OptionalHeader.DataDirectory[1];
	IMAGE_IMPORT_DESCRIPTOR* pIID = (IMAGE_IMPORT_DESCRIPTOR*)(pMem + pImportDirectory->VirtualAddress);
	while (*(DWORD*)pIID)	// IMAGE_IMPORT_DESCRIPTOR 구조체 배열의 끝은 NULL로 끝난다 (IID 배열 크기는 임포트하는 라이브러리 개수만큼)
	{
		HMODULE hModule = LoadLibraryA((LPCSTR)pMem + pIID->Name);
		IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)(pMem + pIID->OriginalFirstThunk);
		IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)(pMem + pIID->FirstThunk);
		while (*(DWORD*)pINT)	// IMAGE_THUNK_DATA 구조체 배열도 마찬가지로 NULL로 끝난다 (배열 크기는 해당 라이브러리의 API 개수만큼)
		{
			IMAGE_IMPORT_BY_NAME* pImportByName = (IMAGE_IMPORT_BY_NAME*)(pMem + pINT->u1.AddressOfData);
			DWORD dwFunctionAddress = (DWORD)GetProcAddress(hModule, pImportByName->Name);
			*(DWORD*)&pIAT->u1.Function = dwFunctionAddress;
			
			pINT += 1;
			pIAT += 1;
		}

		pIID += 1;
	}
	
	// DLL EntryPoint 호출
	printf("DLL Start\n");
	void(*pEntryPoint)() = (void(*)())(pMem + pNt->OptionalHeader.AddressOfEntryPoint);
	pEntryPoint();

	return 0;
}
