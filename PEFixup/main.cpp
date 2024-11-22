#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "pe.hpp"
#include "sigs.hpp"

enum Mode_t : BYTE {
	UNSET,
	PRE,
	DUMP,
	POST,
};

struct {
	Mode_t mode = UNSET;
	char* input = NULL;
	char* output = "a.exe";

	struct {
		bool bDisableASLR : 1 = true;
		bool bRemoveBrokenTLS : 1 = true;
	} Pre;

	struct {
		bool bPID : 1 = false;
		bool bName : 1 = false;
		char* headers = NULL;
		char* module = NULL;
		uint64_t RunningAddr = 0;
	} Dump;
	
	struct {
		bool bScanEntry : 1 = true;
		bool bScanTLS : 1 = true;
		bool bFixLayout : 1 = false;
		bool bIgnoreNonExecutable : 1 = false;
		bool bRemoveDebug : 1 = true;
	} Post;
} Settings;

void HelpMenu(char* argv0);
size_t FindSig(Buffer buf, BYTE* pattern, char* mask);
PE* DumpPEFromMemory(_In_ HANDLE hProcess, _In_opt_ uint64_t u64Base = 0, _In_opt_ PE* pHeaders = NULL);
PE* AdjustPE(_In_ Buffer raw);

// Entry point
int main(int argc, char** argv) {
	// Check num arguments
	if (argc < 3) {
		HelpMenu(argv[0]);
		return 0;
	}


	/***** PARSE ARGUMENTS *****/

	// Get command
	if (!lstrcmpA(argv[1], "pre")) {
		Settings.mode = PRE;
	} else if (!lstrcmpA(argv[1], "post")) {
		Settings.mode = POST;
	} else if (!lstrcmpA(argv[1], "dump")) {
		Settings.mode = DUMP;
	} else if (!lstrcmpA(argv[1], "--help") || !lstrcmpA(argv[1], "-h")) {
		HelpMenu(argv[0]);
		return 0;
	} else {
		printf("Unknown command: %s\n", argv[1]);
		return 1;
	}

	// Get file
	Settings.input = argv[2];
	
	// Command line args
	for (int i = 3; i < argc; i++) {
		if (!lstrcmpA(argv[i], "--help") || !lstrcmpA(argv[i], "-h")) {
			HelpMenu(argv[0]);
			return 0;
		} else if (!lstrcmpA(argv[i], "-o")) {
			if (i == argc - 1) {
				printf("OUTPUT required\n");
				return 1;
			}
			Settings.output = argv[i + 1];
			i++;
		} else if (!lstrcmpA(argv[i], "--no-aslr")) {
			Settings.Pre.bDisableASLR = false;
		} else if (!lstrcmpA(argv[i], "--no-tls")) {
			Settings.Pre.bRemoveBrokenTLS = false;
		} else if (!lstrcmpA(argv[i], "--pid")) {
			Settings.Dump.bPID = true;
		} else if (!lstrcmpA(argv[i], "--name")) {
			Settings.Dump.bName = true;
		} else if (!lstrcmpA(argv[i], "--base")) {
			if (i == argc - 1) {
				printf("ADDRESS required\n");
				return 1;
			}
			Settings.Dump.RunningAddr = strtoull(argv[i + 1], NULL, 16);
			if (!Settings.Dump.RunningAddr) Settings.Dump.RunningAddr = strtoull(argv[i + 1], NULL, 0);
			i++;
		} else if (!lstrcmpA(argv[i], "--headers")) {
			if (i == argc - 1) {
				printf("FILE required\n");
				return 1;
			}
			Settings.Dump.headers = argv[i + 1];
			i++;
		} else if (!lstrcmpA(argv[i], "--no-debug")) {
			Settings.Post.bRemoveDebug = false;
		} else if (!lstrcmpA(argv[i], "--no-oep")) {
			Settings.Post.bScanEntry = false;
		} else if (!lstrcmpA(argv[i], "--no-tls")) {
			Settings.Post.bScanTLS = false;
		} else if (!lstrcmpA(argv[i], "--dumped")) {
			Settings.Post.bFixLayout = true;
		} else if (!lstrcmpA(argv[i], "--x-only")) {
			Settings.Post.bIgnoreNonExecutable = true;
		} else if (!lstrcmpA(argv[i], "--module")) {
			if (i == argc - 1) {
				printf("NAME required\n");
				return 1;
			}
			Settings.Dump.module = argv[i + 1];
			i++;
		} else {
			printf("Unrecognized parameter \'%s\'\n", argv[i]);
			return 1;
		}
 	}


	/***** DO STUFF *****/
	PE* file = NULL;

	// Pre mode
	if (Settings.mode == PRE) {
		file = new PE(Settings.input);
		switch (file->GetStatus()) {
		case NoFile:
			printf("Cannot read file \'%s\'\n", Settings.input);
			return 1;
		case NotPE:
			printf("Cannot parser PE, did you mean to use post?\n");
			return 1;
		case Unsupported:
			printf("Unsupported architecture\n");
			return 1;
		default:
			break;
		}

		// Disable ASLR
		if (Settings.Pre.bDisableASLR) {
			if (!(file->GetNtHeaders()->x64.FileHeader.Characteristics & IMAGE_FILE_DLL) && file->GetNtHeaders()->x64.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
				if (file->x86) {
					file->GetNtHeaders()->x86.OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
				} else {
					file->GetNtHeaders()->x64.OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
				}
				file->GetNtHeaders()->x64.FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
				printf("Disabled ASLR\n");
			} else {
				printf("Cannot disable ASLR or ASLR already disabled\n");
			}
		}

		// Fix TLS callbacks
		if (Settings.Pre.bRemoveBrokenTLS) {
			uint64_t* pTLS = file->GetTLSCallbacks();
			int tr = 0;
			for (int i = 0; pTLS && pTLS[i]; i++) {
				if (pTLS[i] < file->GetBaseAddress() || pTLS[i] > file->GetBaseAddress() + (file->x86 ? file->GetNtHeaders()->x86.OptionalHeader.SizeOfImage : file->GetNtHeaders()->x64.OptionalHeader.SizeOfImage)) {
					printf("Removed invalid TLS callback: %p\n", pTLS[i]);
					pTLS[i] = 0;
				} else {
					pTLS[tr] = pTLS[i];
					if (tr != i) pTLS[i] = 0;
					tr++;
				}
			}
		}
	}

	// Dump mode
	else if (Settings.mode == DUMP) {
		// Have --base override --module
		if (Settings.Dump.module && Settings.Dump.RunningAddr) {
			printf("Both --module and --base were specified, ignoring module\n");
			Settings.Dump.module = NULL;
		}

		// Get handle to running process
		HANDLE hProc = NULL;
		DWORD dwPID = 0;
		if (Settings.Dump.bPID) {
			dwPID = strtoul(Settings.input, NULL, 0);
			hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwPID);
			if (!hProc || hProc == INVALID_HANDLE_VALUE) {
				printf("Could not open process with PID %d (Reason: %d)\n", dwPID, GetLastError());
				return 1;
			}
		} else if (Settings.Dump.bName) {
			// Find process
			PROCESSENTRY32 entry = { 0 };
			entry.dwSize = sizeof(PROCESSENTRY32);
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!hSnap || hSnap == INVALID_HANDLE_VALUE) {
				printf("Could not get list of processes (%d)\n", GetLastError());
				return 1;
			}
			Process32First(hSnap, &entry);
			do {
				if (!lstrcmpA(entry.szExeFile, Settings.input)) break;
			} while (Process32Next(hSnap, &entry));
			CloseHandle(hSnap);
			if (lstrcmpA(entry.szExeFile, Settings.input)) {
				printf("Could not find process \'%s\'\n", Settings.input);
				return 1;
			}

			// Open process
			dwPID = entry.th32ProcessID;
			hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, dwPID);
			if (!hProc || hProc == INVALID_HANDLE_VALUE) {
				printf("Could not open process \'%s\' (Reason: %d)\n", Settings.input, GetLastError());
				return 1;
			}
		} else {
			printf("--name or --pid must be selected when dumping\n");
			return 1;
		}

		// Get module address
		if (Settings.Dump.module) {
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
			while ((!hSnap || hSnap == INVALID_HANDLE_VALUE) && GetLastError() == ERROR_BAD_LENGTH) {
				hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
			}
			if (!hSnap || hSnap == INVALID_HANDLE_VALUE) {
				printf("Could not get list of modules (%d)\n", GetLastError());
				return 1;
			}
			MODULEENTRY32 entry = { 0 };
			entry.dwSize = sizeof(MODULEENTRY32);
			Module32First(hSnap, &entry);
			do {
				if (!lstrcmpA(entry.szModule, Settings.Dump.module)) break;
			} while (Module32Next(hSnap, &entry));
			CloseHandle(hSnap);
			if (lstrcmpA(entry.szModule, Settings.Dump.module)) {
				printf("Could not find module \'%s\'\n", Settings.Dump.module);
				return 1;
			}
			Settings.Dump.RunningAddr = reinterpret_cast<uint64_t>(entry.modBaseAddr);
			printf("Address of %s: 0x%p\n", Settings.Dump.module, Settings.Dump.RunningAddr);
			if (!Settings.Dump.headers) {
				Settings.Dump.headers = reinterpret_cast<char*>(malloc(lstrlenA(entry.szExePath) + 1)); // Leaking memory here but guess what, I don't care
				strcpy_s(Settings.Dump.headers, lstrlenA(entry.szExePath) + 1, entry.szExePath);
				printf("Path for %s: %s\n", Settings.Dump.module, Settings.Dump.headers);
			}
		}

		// Dump process
		PE* pHeaders = NULL;
		if (Settings.Dump.headers) {
			pHeaders = new PE(Settings.Dump.headers);
			switch (pHeaders->GetStatus()) {
			case NoFile:
				printf("Cannot read file \'%s\'\n", Settings.Dump.headers);
				return 1;
			case NotPE:
				printf("Cannot parser headers for \'%s\'\n", Settings.Dump.headers);
				return 1;
			case Unsupported:
				printf("Unsupported architecture\n");
				return 1;
			default:
				break;
			}
		}
		file = DumpPEFromMemory(hProc, Settings.Dump.RunningAddr, pHeaders);
		if (pHeaders) delete pHeaders;
		if (!file) {
			printf("Failed to dump process\n");
			return 1;
		}
	}

	// Post mode
	else if (Settings.mode == POST) {
		// Load from disk
		HANDLE hFile = CreateFileA(Settings.input, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE) {
			printf("Failed to read file \'%s\' (Reason: %d)\n", Settings.input, GetLastError());
			return 1;
		}

		// Guess if it's too large
		DWORD Size = GetFileSize(hFile, NULL);
		IMAGE_DOS_HEADER DosHeader = { 0 };
		ComboNTHeaders NtHeaders = { 0 };
		ReadFile(hFile, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL, NULL);
		SetFilePointer(hFile, DosHeader.e_lfanew, NULL, FILE_BEGIN);
		ReadFile(hFile, &NtHeaders, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL, NULL);
		ReadFile(hFile, &NtHeaders.x64.OptionalHeader, NtHeaders.x64.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32), NULL, NULL);
		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

		// Adjust if too large
		if (Settings.Post.bFixLayout) {
			Buffer bytes = { 0 };
			bytes.u64Size = Size;
			bytes.pBytes = reinterpret_cast<BYTE*>(malloc(Size));
			SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
			ReadFile(hFile, bytes.pBytes, Size, NULL, NULL);
			file = AdjustPE(bytes);
			if (Settings.Dump.RunningAddr) {
				if (file->x86) {
					file->NTHeaders.x86.OptionalHeader.ImageBase = Settings.Dump.RunningAddr;
				} else {
					file->NTHeaders.x64.OptionalHeader.ImageBase = Settings.Dump.RunningAddr;
				}
			}
			free(bytes.pBytes);
		}
		
		// Load like normal
		else {
			file = new PE(hFile);
		}

		// Remove debug info
		if (Settings.Post.bRemoveDebug) {
			file->NTHeaders.x64.FileHeader.NumberOfSymbols = 0;
			file->NTHeaders.x64.FileHeader.PointerToSymbolTable = 0;
			if (file->x86) {
				file->NTHeaders.x86.OptionalHeader.DataDirectory[6].Size = 0;
				file->NTHeaders.x86.OptionalHeader.DataDirectory[6].VirtualAddress = 0;
			} else {
				file->NTHeaders.x64.OptionalHeader.DataDirectory[6].Size = 0;
				file->NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress = 0;
			}
			printf("Removed debugging info\n");
		}

		// Scan for entry points
		if (Settings.Post.bScanEntry) {
			for (int sec = 0; sec < file->NTHeaders.x64.FileHeader.NumberOfSections; sec++) {
				// Skip non-executable sections
				if (Settings.Post.bIgnoreNonExecutable && !(file->pSectionHeaders[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
				
				for (int i = 0; i < (file->x86 ? sizeof(Sigs::EPs_32) : sizeof(Sigs::EPs_64)) / sizeof(Sig); i++) {
					Buffer data = { 0 };
					data.pBytes = file->pSectionData[sec];
					data.u64Size = file->pSectionHeaders[sec].SizeOfRawData;
					uint64_t nOff = FindSig(data, file->x86 ? Sigs::EPs_32[i].raw : Sigs::EPs_64[i].raw, file->x86 ? Sigs::EPs_32[i].mask : Sigs::EPs_64[i].mask);
					if (nOff != _UI64_MAX) {
						printf("EP match: %p (%s)\n", file->GetBaseAddress() + file->pSectionHeaders[sec].VirtualAddress + nOff, file->x86 ? Sigs::EPs_32[i].name : Sigs::EPs_64[i].name);
					}
				}
			}
		}

		// Scan for TLS callbacks
		if (Settings.Post.bScanTLS) {
			for (int sec = 0; sec < file->NTHeaders.x64.FileHeader.NumberOfSections; sec++) {
				// Skip non-executable sections
				if (Settings.Post.bIgnoreNonExecutable && !(file->pSectionHeaders[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

				for (int i = 0; i < (file->x86 ? sizeof(Sigs::TLS_32) : sizeof(Sigs::TLS_64)) / sizeof(Sig); i++) {
					Buffer data = { 0 };
					data.pBytes = file->pSectionData[sec];
					data.u64Size = file->pSectionHeaders[sec].SizeOfRawData;
					uint64_t nOff = FindSig(data, file->x86 ? Sigs::TLS_32[i].raw : Sigs::TLS_64[i].raw, file->x86 ? Sigs::TLS_32[i].mask : Sigs::TLS_64[i].mask);
					if (nOff != _UI64_MAX) {
						printf("Callback match: %p (%s)\n", file->GetBaseAddress() + file->pSectionHeaders[sec].VirtualAddress + nOff, file->x86 ? Sigs::TLS_32[i].name : Sigs::TLS_64[i].name);
					}
				}
			}
		}

		CloseHandle(hFile);
	}

	// Output file
	if (!file || !file->ProduceBinary(Settings.output)) {
		printf("Failed to write to %s\n", Settings.output);
		return 1;
	}

	if (file) delete file;
	return 0;
}


/// <summary>
/// Loads a PE from a running process
/// </summary>
/// <param name="hProcess">Handle to the process to read from</param>
/// <param name="u64Base">Optional base address to read from</param>
/// <param name="pHeaders">Optional headers of PE to be read, in case original headers destroyed</param>
/// <returns>Pointer to dumped process, or NULL on failure</returns>
PE* DumpPEFromMemory(_In_ HANDLE hProcess, _In_opt_ uint64_t u64Base, _In_opt_ PE* pHeaders) {
	// Find base address
	if (!u64Base) {
		PROCESS_BASIC_INFORMATION info = { 0 };
		NtQueryInformationProcess(hProcess, ProcessBasicInformation, &info, sizeof(info), NULL);
		ReadProcessMemory(hProcess, ((BYTE*)info.PebBaseAddress) + 0x10, &u64Base, sizeof(uint64_t), NULL);
		printf("ImageBase: %p\n", u64Base);
	}

	// Load headers
	bool bUnloadHeaders = false;
	if (!pHeaders) {
		bUnloadHeaders = true;
		pHeaders = new PE(false);
		pHeaders->Status = Normal;
		ReadProcessMemory(hProcess, (LPVOID)u64Base, &pHeaders->DosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
		pHeaders->DosStub.u64Size = pHeaders->DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
		pHeaders->DosStub.pBytes = reinterpret_cast<BYTE*>(malloc(pHeaders->DosStub.u64Size));
		ReadProcessMemory(hProcess, (LPVOID)(u64Base + sizeof(IMAGE_DOS_HEADER)), pHeaders->DosStub.pBytes, pHeaders->DosStub.u64Size, NULL);
		ReadProcessMemory(hProcess, (LPVOID)(u64Base + pHeaders->DosHeader.e_lfanew), &pHeaders->NTHeaders, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL);
		pHeaders->x86 = pHeaders->NTHeaders.x64.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE;
		ReadProcessMemory(hProcess, (LPVOID)(u64Base + pHeaders->DosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)), &pHeaders->NTHeaders.x64.OptionalHeader, pHeaders->x86 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64), NULL);
		if (pHeaders->DosHeader.e_magic != IMAGE_DOS_SIGNATURE || pHeaders->NTHeaders.x64.Signature != IMAGE_NT_SIGNATURE) {
			printf("Failed to read process headers!\n");
			return NULL;
		}
		pHeaders->pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(malloc(sizeof(IMAGE_SECTION_HEADER) * pHeaders->NTHeaders.x64.FileHeader.NumberOfSections));
		ReadProcessMemory(hProcess, (LPVOID)(u64Base + pHeaders->DosHeader.e_lfanew + (pHeaders->x86 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64))), pHeaders->pSectionHeaders, sizeof(IMAGE_SECTION_HEADER) * pHeaders->NTHeaders.x64.FileHeader.NumberOfSections, NULL);
		pHeaders->pSectionData = reinterpret_cast<BYTE**>(calloc(pHeaders->NTHeaders.x64.FileHeader.NumberOfSections, sizeof(BYTE*)));
	}

	// Create thingy
	PE* ret = new PE(pHeaders);

	// Read process memory
	for (int i = 0; i < ret->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		ret->pSectionHeaders[i].SizeOfRawData = ret->pSectionHeaders[i].Misc.VirtualSize;
		ret->pSectionData[i] = reinterpret_cast<BYTE*>(malloc(ret->pSectionHeaders[i].SizeOfRawData));
		DWORD dwOld = 0;
		VirtualProtectEx(hProcess, (LPVOID)(u64Base + ret->pSectionHeaders[i].VirtualAddress), ret->pSectionHeaders[i].SizeOfRawData, PAGE_EXECUTE_READWRITE, &dwOld);
		if (!ReadProcessMemory(hProcess, (LPVOID)(u64Base + ret->pSectionHeaders[i].VirtualAddress), ret->pSectionData[i], ret->pSectionHeaders[i].SizeOfRawData, NULL)) {
			printf("Failed to read section \'%.8s\'! (%d) (%p -> %p)\n", ret->pSectionHeaders[i].Name, GetLastError(), u64Base + ret->pSectionHeaders[i].VirtualAddress, u64Base + ret->pSectionHeaders[i].VirtualAddress + ret->pSectionHeaders[i].SizeOfRawData);
			if (dwOld & PAGE_GUARD) printf("Memory had PAGE_GUARD set\n");
			return NULL;
		}
		VirtualProtectEx(hProcess, (LPVOID)(u64Base + ret->pSectionHeaders[i].VirtualAddress), ret->pSectionHeaders[i].SizeOfRawData, dwOld, &dwOld);
		printf("Dumped section \'%.8s\', %p -> %p\n", ret->pSectionHeaders[i].Name, u64Base + ret->pSectionHeaders[i].VirtualAddress, u64Base + ret->pSectionHeaders[i].VirtualAddress + ret->pSectionHeaders[i].SizeOfRawData);
	}

	// return
	//if (bUnloadHeaders && pHeaders) delete pHeaders;
	if (ret->x86) {
		ret->NTHeaders.x86.OptionalHeader.ImageBase = u64Base;
	} else {
		ret->NTHeaders.x64.OptionalHeader.ImageBase = u64Base;
	}
	ret->FixHeaders();
	return ret;
}


/// <summary>
/// Takes a mapped PE's memory and converts it to disk format
/// </summary>
/// <param name="raw">Mapped PE's memory</param>
/// <returns>Pointer to fixed PE, or NULL on error</returns>
PE* AdjustPE(_In_ Buffer raw) {
	// Sanity check
	if (!raw.pBytes || raw.u64Size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
		return NULL;

	// Load headers from other file
	if (Settings.Dump.headers) {
		HANDLE hFile = CreateFileA(Settings.Dump.headers, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE) {
			printf("Failed to open file \'%s\'\n", Settings.Dump.headers);
			return NULL;
		}
		ReadFile(hFile, raw.pBytes, sizeof(IMAGE_DOS_HEADER), NULL, NULL);
		IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(raw.pBytes);
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			printf("Invalid headers!\n");
			return NULL;
		}
		ReadFile(hFile, raw.pBytes + sizeof(IMAGE_DOS_HEADER), pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD), NULL, NULL);
		IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(raw.pBytes + pDosHeader->e_lfanew);
		if (reinterpret_cast<IMAGE_FILE_HEADER*>(raw.pBytes + pDosHeader->e_lfanew + sizeof(DWORD))->Characteristics & IMAGE_FILE_32BIT_MACHINE) {
			ReadFile(hFile, raw.pBytes + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), sizeof(IMAGE_OPTIONAL_HEADER32), NULL, NULL);
			ReadFile(hFile, raw.pBytes + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32), pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), NULL, NULL);
		} else {
			ReadFile(hFile, raw.pBytes + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), sizeof(IMAGE_OPTIONAL_HEADER64), NULL, NULL);
			ReadFile(hFile, raw.pBytes + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64), pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), NULL, NULL);
		}
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			printf("Invalid headers!\n");
			return NULL;
		}
		CloseHandle(hFile);
	}

	// Load headers
	PE* pAdjusted = new PE(false);
	pAdjusted->Status = Normal;
	memcpy(&pAdjusted->DosHeader, raw.pBytes, sizeof(IMAGE_DOS_HEADER));
	pAdjusted->DosStub.u64Size = pAdjusted->DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if (pAdjusted->DosStub.u64Size) {
		pAdjusted->DosStub.pBytes = reinterpret_cast<BYTE*>(malloc(pAdjusted->DosStub.u64Size));
		memcpy(pAdjusted->DosStub.pBytes, raw.pBytes + sizeof(IMAGE_DOS_HEADER), pAdjusted->DosStub.u64Size);
	}
	memcpy(&pAdjusted->NTHeaders, raw.pBytes + pAdjusted->DosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
	if (pAdjusted->DosHeader.e_magic != IMAGE_DOS_SIGNATURE || pAdjusted->NTHeaders.x64.Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid headers!\n");
		delete pAdjusted;
		return NULL;
	}
	pAdjusted->pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(malloc(pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
	memcpy(pAdjusted->pSectionHeaders, raw.pBytes + pAdjusted->DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64), pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	pAdjusted->x86 = pAdjusted->NTHeaders.x64.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE;

	// Load sections
	pAdjusted->pSectionData = reinterpret_cast<BYTE**>(malloc(pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections * sizeof(BYTE*)));
	DWORD dwOff = pAdjusted->pSectionHeaders[0].PointerToRawData;
	for (int i = 0; i < pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		pAdjusted->pSectionHeaders[i].SizeOfRawData = pAdjusted->pSectionHeaders[i].Misc.VirtualSize;
		pAdjusted->pSectionData[i] = reinterpret_cast<BYTE*>(malloc(pAdjusted->pSectionHeaders[i].SizeOfRawData));
		memcpy(pAdjusted->pSectionData[i], raw.pBytes + pAdjusted->pSectionHeaders[i].VirtualAddress, pAdjusted->pSectionHeaders[i].SizeOfRawData);
		printf("Copied section \'%.8s\', %p -> %p\n", pAdjusted->pSectionHeaders[i].Name, pAdjusted->GetBaseAddress() + pAdjusted->pSectionHeaders[i].VirtualAddress, pAdjusted->GetBaseAddress() + pAdjusted->pSectionHeaders[i].VirtualAddress + pAdjusted->pSectionHeaders[i].SizeOfRawData);
	}

	pAdjusted->FixHeaders();
	return pAdjusted;
}


/// <summary>
/// Outputs help menu
/// </summary>
/// <param name="argv0">Process name</param>
void HelpMenu(_In_ char* argv0) {
	printf("Usage: %s COMMAND FILE [OPTIONS]\n\n", argv0);
	
	printf("COMMAND\n");
	printf("\tpre\t\tIntended for use before running and dumping an application\n");
	printf("\tdump\t\tDump a running process to disk\n");
	printf("\tpost\t\tIntended for use on a dumped application\n\n");

	printf("GENERAL OPTIONS\n");
	printf("\t-o OUTPUT\tSelect output path\n");
	printf("\t--help\t\tDisplay this menu\n\n");

	printf("PRE OPTIONS\n");
	printf("\t--no-aslr\tDon\'t touch ASLR, leave as is\n");
	printf("\t--no-tls\tDon\'t remove invalid TLS callbacks\n\n");

	printf("DUMP OPTIONS\n");
	printf("\t--pid\t\tFILE is the PID of a running process\n");
	printf("\t--name\t\tFILE is the name of a running process\n");
	printf("\t--base ADDRESS\tBase address of running process/dumped PE\n");
	printf("\t--headers FILE\tSpecify PE that contains dumped PE\'s headers\n");
	printf("\t--module NAME\tDump a loaded module in the process, instead of the process itself\n\n");

	printf("POST OPTIONS\n");
	printf("\t--headers FILE\tSpecify PE that contains dumped PE\'s headers\n");
	printf("\t--no-oep\tDon\'t scan for possible OEP\n");
	printf("\t--no-tls\tDon\'t scan for possible TLS callbacks\n");
	printf("\t--no-debug\tDon\'t remove debugging information\n");
	printf("\t--dumped\tFILE is a raw dump and needs to be adjusted to disk format\n");
	printf("\t--x-only\tOnly scan executable memory\n");
}


/// <summary>
/// Find offset of a sig.
/// </summary>
/// <param name="buf">Buffer to search</param>
/// <param name="pattern">Byte pattern to look for</param>
/// <param name="mask">Pattern mask (i.e. "xxx???xx", matches all bytes except "?")</param>
/// <returns>_UI64_MAX if not found, otherwise it's the offset to it</returns>
size_t FindSig(Buffer buf, BYTE* pattern, char* mask) {
	if (!pattern || !mask || !buf.pBytes || !buf.u64Size) return _UI64_MAX;

	BYTE patternlen = lstrlenA(mask);
	size_t off = 0;
	bool found;
	while (buf.u64Size >= patternlen) {
		found = true;
		for (int i = 0; i < patternlen; i++) {
			if (mask[i] != '?' && pattern[i] != buf.pBytes[i]) {
				found = false;
				break;
			}
		}

		if (found) return off;
		
		off++;
		buf.pBytes++;
		buf.u64Size--;
	}

	return _UI64_MAX;
}