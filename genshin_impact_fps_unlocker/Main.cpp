#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <ntstatus.h>
#include "signature.h"

#pragma comment(lib, "ntdll")

ULONG GetProcessId(LPCWSTR lpProcessName);

#define FPS_LIMIT 120

int main() {
	printf(">>> Initializing...\n");

	Sleep(10000); // for loading game

	ULONG ProcessId = 0;
	
	do {
		ProcessId = GetProcessId(L"GenshinImpact.exe");

		Sleep(1000);
	} while (ProcessId == 0);

	printf(">>> ProcessId : %lu\n", ProcessId);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, ProcessId);

	if (hProcess == INVALID_HANDLE_VALUE)
		return -1;

	do {

		printf(">>> hProcess : %p\n", hProcess);

		uintptr_t ModuleBase = 0;

		{
			PROCESS_BASIC_INFORMATION pbi = {}; ULONG usize = 0;

			if (!NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &usize))) break;

			if (!pbi.PebBaseAddress) break;

			PEB peb = {};
			if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) break;

			ModuleBase = (uintptr_t)peb.Reserved3[1];

			if (!ModuleBase) break;
		}

		printf(">>> ModuleBase : 0x%016llX\n", ModuleBase);

		unsigned char _headers[0x1000];
		if (!ReadProcessMemory(hProcess, (PVOID)ModuleBase, _headers, sizeof(_headers), nullptr)) break;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_headers;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

		printf(">>> SizeOfImage : 0x%08lX\n", pNtHeaders->OptionalHeader.SizeOfImage);

		uintptr_t fps_offset = 0;

		if (unsigned char* _image = new unsigned char[pNtHeaders->OptionalHeader.SizeOfImage]) {

			printf(">>> _image : 0x%p\n", _image);

			do {
				for (size_t i = 0; i < pNtHeaders->OptionalHeader.SizeOfImage; i += 0x1000)
					ReadProcessMemory(hProcess, (PBYTE)ModuleBase + i, _image + i, 0x1000, nullptr);

				PBYTE pattern = _image + 0x1000;

				do {
					pattern = jm::memory_signature("B9 3C 00 00 00 E8").find(pattern, _image + pNtHeaders->OptionalHeader.SizeOfImage);

					if (pattern == _image + pNtHeaders->OptionalHeader.SizeOfImage) break;

					pattern += 5;

					//printf(">>> pattern : 0x%p\n", pattern - _image + (PBYTE)ModuleBase);

					PBYTE ptr = pattern + *(int32_t*)(pattern + 1) + 5;

					if (ptr - _image < pNtHeaders->OptionalHeader.SizeOfCode && *ptr == 0xE9) {
						//printf(">>> ptr : 0x%p, %02X\n", ptr - _image, *ptr);

						do {
							ptr = ptr + *(int32_t*)(ptr + 1) + 5;

							if (ptr - _image >= pNtHeaders->OptionalHeader.SizeOfCode) break;
						} while (*ptr == 0xE9);


						if (ptr - _image < pNtHeaders->OptionalHeader.SizeOfCode) {
							ptr = ptr + *(int32_t*)(ptr + 2) + 6;

							fps_offset = ptr - _image;

							break;
						}
					}

					pattern += 5;
				} while (pattern);



			} while (false);


			delete[] _image;
		}

		if (fps_offset) {
			printf(">>> fps_offset : +0x%08lX\n", fps_offset);


			while (true) {
				uint32_t fps_limit = 0;

				if (!ReadProcessMemory(hProcess, (PBYTE)ModuleBase + fps_offset, &fps_limit, sizeof(fps_limit), nullptr))
					break;


				if (fps_limit != FPS_LIMIT) {
					printf(">>> applying fps_limit : %lu to %lu\n", fps_limit, FPS_LIMIT);

					fps_limit = FPS_LIMIT;

					if (!WriteProcessMemory(hProcess, (PBYTE)ModuleBase + fps_offset, &fps_limit, sizeof(fps_limit), nullptr)) break;
				}

				Sleep(500);
			}
		}

		CloseHandle(hProcess);
	} while (false);

	return 0;
}


ULONG GetProcessId(LPCWSTR lpProcessName)
{
	ULONG result = 0;

	PSYSTEM_PROCESS_INFORMATION pProcesses = NULL;
	ULONG Length = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	while ((status = NtQuerySystemInformation(SystemProcessInformation, pProcesses, Length, &Length)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (pProcesses) free(pProcesses);
		pProcesses = (PSYSTEM_PROCESS_INFORMATION)malloc(Length);
	}

	if (pProcesses)
	{
		if (NT_SUCCESS(status))
		{
			for (PSYSTEM_PROCESS_INFORMATION pSPI_ = pProcesses; pSPI_->NextEntryOffset; pSPI_ = (PSYSTEM_PROCESS_INFORMATION)(pSPI_->NextEntryOffset + (PBYTE)pSPI_))
			{
				if (pSPI_->ImageName.Length && !wcscmp(pSPI_->ImageName.Buffer, lpProcessName))
				{
					result = (ULONG)pSPI_->UniqueProcessId;

					break;
				}
			}
		}

		free(pProcesses);
	}

	return result;
}