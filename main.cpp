#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

int main(void)
{
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

				while (dwRelocSectionSize > offset)
				{
					IMAGE_BASE_RELOCATION* pRelocBlock = (IMAGE_BASE_RELOCATION*)(pRelocSection + offset);
					BYTE* pRelocBase = pMem + pRelocBlock->VirtualAddress;
					DWORD nTypeOffset = (pRelocBlock->SizeOfBlock - 0x8) / 2;
					offset += 8;
					for (int j = 0; j < nTypeOffset; j++)
					{
						WORD wTypeOffset = *(WORD*)((BYTE*)pRelocSection + offset);
						if (wTypeOffset >> 12 == IMAGE_REL_BASED_HIGHLOW)
						{
							DWORD* ptr = (DWORD*)(pRelocBase + (wTypeOffset & 0xFFF));
							*ptr = *ptr + dwBaseDifference;
						}
						offset += 2;
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
