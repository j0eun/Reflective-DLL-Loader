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
	
	// DLL Relocation
	if (pMem != (BYTE*)pNt->OptionalHeader.ImageBase)
	{
		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
		{
			if (!strcmp((const char*)pSectionHeader[i]->Name, ".reloc"))
			{
				DWORD dwRelocSectionSize = ((IMAGE_DATA_DIRECTORY*)((BYTE*)pNt + 0x18 + 0x88))->Size;
				BYTE* pRelocSection = pMem + pSectionHeader[i]->VirtualAddress;
				printf("%X\n", pRelocSection);
				DWORD offset = 0;

				printf("Original Base: 0x%X\n", pNt->OptionalHeader.ImageBase);
				printf("New Base: 0x%X\n", pMem);
				printf("Difference: 0x%X\n", (DWORD)pMem - pNt->OptionalHeader.ImageBase);
				printf("\n");
				while (dwRelocSectionSize > offset)
				{
					IMAGE_BASE_RELOCATION* pRelocBlock = (IMAGE_BASE_RELOCATION*)(pRelocSection + offset);
					BYTE* pRelocBase = pMem + pRelocBlock->VirtualAddress;
					DWORD nTypeOffset = (pRelocBlock->SizeOfBlock - 0x8) / 2;
					DWORD dwBaseDifference = (DWORD)pMem - pNt->OptionalHeader.ImageBase;
					offset += 8;
					for (int j = 0; j < nTypeOffset; j++)
					{
						WORD wTypeOffset = *(WORD*)((BYTE*)pRelocBlock + offset);
						if (wTypeOffset >> 12 == IMAGE_REL_BASED_HIGHLOW)
						{
							DWORD* ptr = (DWORD*)(pRelocBase + (wTypeOffset & 0xFFF));
							printf("0x%X: 0x%X -> ", ptr, *ptr);
							*ptr = *ptr + dwBaseDifference;
							printf("0x%X (%X)\n", *ptr, *(WORD*)((BYTE*)pRelocBlock + offset));
						}
						offset += 2;
					}
				}
			}
		}
	}

	/*
	HANDLE hProc = GetCurrentProcess();
	DWORD dwPid = GetProcessId(hProc);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPid);
	THREADENTRY32 te32;
	HANDLE hThread = NULL;

	ZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);
	Thread32First(hSnap, &te32);
	do
	{
		if (te32.th32OwnerProcessID == dwPid)
		{
			hThread = te32.th32ThreadID;
			break;
		}
	} while (Thread32Next(hSnap, &te32));
	*/

	HANDLE hThread = CreateThread(
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)(pMem + pNt->OptionalHeader.AddressOfEntryPoint),
		//(LPTHREAD_START_ROUTINE)(pMem + 0x1009),
		NULL,
		0,
		NULL
	);
	printf("%d\n", hThread);
	WaitForSingleObject(hThread, INFINITE);

	return 0;
}