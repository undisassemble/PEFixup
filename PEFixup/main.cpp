#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "pe.hpp"

struct {
	BYTE mode = 0; // 0 - Unset, 1 - pre, 2 - post
	char* input = NULL;
	char* output = "a.exe";

	struct {
		bool bDisableASLR : 1 = true;
		bool bRemoveBrokenTLS : 1 = true;
	} Pre;
	
	struct {
		bool bPID : 1 = false;
		bool bName : 1 = false;
		bool bSetIfFound : 1 = true;
		bool bScanEntry : 1 = true;
		bool bScanTLS : 1 = true;
		bool bFixLayout : 1 = true;
		bool bIgnoreNonExecutable : 1 = false;
		char* headers = NULL;
		uint64_t RunningAddr = 0;
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
		Settings.mode = 1;
	} else if (!lstrcmpA(argv[1], "post")) {
		Settings.mode = 2;
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
			Settings.Post.bPID = true;
		} else if (!lstrcmpA(argv[i], "--name")) {
			Settings.Post.bName = true;
		} else if (!lstrcmpA(argv[i], "--base")) {
			if (i == argc - 1) {
				printf("ADDRESS required\n");
				return 1;
			}
			Settings.Post.RunningAddr = strtoull(argv[i + 1], NULL, 0);
			i++;
		} else if (!lstrcmpA(argv[i], "--headers")) {
			if (i == argc - 1) {
				printf("FILE required\n");
				return 1;
			}
			Settings.Post.headers = argv[i];
			i++;
		} else if (!lstrcmpA(argv[i], "--no-oep")) {
			Settings.Post.bScanEntry = false;
		} else if (!lstrcmpA(argv[i], "--no-tls")) {
			Settings.Post.bScanTLS = false;
		} else if (!lstrcmpA(argv[i], "--disk")) {
			Settings.Post.bFixLayout = false;
		} else if (!lstrcmpA(argv[i], "--x-only")) {
			Settings.Post.bIgnoreNonExecutable = true;
		} else {
			printf("Unrecognized parameter \'%s\'\n", argv[i]);
			return 1;
		}
 	}


	/***** DO STUFF *****/
	PE* file = NULL;

	// Pre mode
	if (Settings.mode == 1) {
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
				file->GetNtHeaders()->x64.OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
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
				if (pTLS[i] < file->GetBaseAddress() || pTLS[i] > file->GetBaseAddress() + file->GetNtHeaders()->x64.OptionalHeader.SizeOfImage) {
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

	// Post mode
	else if (Settings.mode == 2) {
		
		// Get handle to running process
		HANDLE hProc = NULL;
		if (Settings.Post.bPID) {
			DWORD PID = strtoul(Settings.input, NULL, 0);
			hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, PID);
			if (!hProc || hProc == INVALID_HANDLE_VALUE) {
				printf("Could not open process with PID %d (Reason: %d)\n", PID, GetLastError());
				return 1;
			}
		} else if (Settings.Post.bName) {
			// Find process
			PROCESSENTRY32 entry = { 0 };
			entry.dwSize = sizeof(PROCESSENTRY32);
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!hSnap || hSnap == INVALID_HANDLE_VALUE) {
				printf("Could not get list of processes\n");
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
			hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
			if (!hProc || hProc == INVALID_HANDLE_VALUE) {
				printf("Could not open process \'%s\' (Reason: %d)\n", Settings.input, GetLastError());
			}
		}

		// Dump process (if applicable)
		if (hProc) {
			PE* pHeaders = NULL;
			if (Settings.Post.headers) {
				pHeaders = new PE(Settings.Post.headers);
				switch (pHeaders->GetStatus()) {
				case NoFile:
					printf("Cannot read file \'%s\'\n", Settings.Post.headers);
					return 1;
				case NotPE:
					printf("Cannot parser headers for \'%s\'\n", Settings.Post.headers);
					return 1;
				case Unsupported:
					printf("Unsupported architecture\n");
					return 1;
				default:
					break;
				}
			}
			file = DumpPEFromMemory(hProc, Settings.Post.RunningAddr, pHeaders);
			if (pHeaders) delete pHeaders;
			if (!file) {
				printf("Failed to dump process\n");
				return 1;
			}
		}

		// Load from disk
		else {
			HANDLE hFile = CreateFileA(Settings.input, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (!hFile || hFile == INVALID_HANDLE_VALUE) {
				printf("Failed to read file \'%s\' (Reason: %d)\n", Settings.input, GetLastError());
				return 1;
			}

			// Guess if it's too large
			DWORD Size = GetFileSize(hFile, NULL);
			IMAGE_DOS_HEADER DosHeader = { 0 };
			IMAGE_NT_HEADERS64 NtHeaders = { 0 };
			ReadFile(hFile, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL, NULL);
			SetFilePointer(hFile, DosHeader.e_lfanew, NULL, FILE_BEGIN);
			ReadFile(hFile, &NtHeaders, sizeof(IMAGE_NT_HEADERS64), NULL, NULL);

			// Adjust if too large
			if (Size >= NtHeaders.OptionalHeader.SizeOfImage) {
				Buffer bytes = { 0 };
				bytes.u64Size = Size;
				bytes.pBytes = reinterpret_cast<BYTE*>(malloc(Size));
				SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
				ReadFile(hFile, bytes.pBytes, Size, NULL, NULL);
				file = AdjustPE(bytes);
				if (Settings.Post.RunningAddr) file->NTHeaders.x64.OptionalHeader.ImageBase = Settings.Post.RunningAddr;
				free(bytes.pBytes);
			}
			
			// Load like normal
			else {
				file = new PE(hFile);
			}

			CloseHandle(hFile);
		}
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
		ReadProcessMemory(hProcess, (LPVOID)u64Base, &pHeaders->DosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
		pHeaders->DosStub.u64Size = pHeaders->DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
		pHeaders->DosStub.pBytes = reinterpret_cast<BYTE*>(malloc(pHeaders->DosStub.u64Size));
		ReadProcessMemory(hProcess, (LPVOID)(u64Base + sizeof(IMAGE_DOS_HEADER)), pHeaders->DosStub.pBytes, pHeaders->DosStub.u64Size, NULL);
		ReadProcessMemory(hProcess, (LPVOID)(u64Base + pHeaders->DosHeader.e_lfanew), &pHeaders->NTHeaders, sizeof(IMAGE_NT_HEADERS64), NULL);
	}

	// Read process memory
	Buffer mem = { 0 };
	mem.u64Size = pHeaders->NTHeaders.x64.OptionalHeader.SizeOfImage;
	mem.pBytes = reinterpret_cast<BYTE*>(malloc(mem.u64Size));
	ReadProcessMemory(hProcess, (LPVOID)u64Base, mem.pBytes, mem.u64Size, NULL);
	
	// Copy headers
	if (pHeaders) {
		memcpy(mem.pBytes, &pHeaders->DosHeader, sizeof(IMAGE_DOS_HEADER));
		memcpy(mem.pBytes + sizeof(IMAGE_DOS_HEADER), pHeaders->DosStub.pBytes, pHeaders->DosStub.u64Size);
		memcpy(mem.pBytes + pHeaders->DosHeader.e_lfanew, &pHeaders->NTHeaders, sizeof(IMAGE_NT_HEADERS64));
		memcpy(mem.pBytes + pHeaders->DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64), pHeaders->pSectionHeaders, pHeaders->NTHeaders.x64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	}

	// Adjust and return
	if (bUnloadHeaders && pHeaders) delete pHeaders;
	PE* ret = AdjustPE(mem);
	ret->NTHeaders.x64.OptionalHeader.ImageBase = u64Base;
	free(mem.pBytes);
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

	// Load headers
	PE* pAdjusted = new PE(false);
	memcpy(&pAdjusted->DosHeader, raw.pBytes, sizeof(IMAGE_DOS_HEADER));
	pAdjusted->DosStub.u64Size = pAdjusted->DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	pAdjusted->DosStub.pBytes = reinterpret_cast<BYTE*>(malloc(pAdjusted->DosStub.u64Size));
	memcpy(pAdjusted->DosStub.pBytes, raw.pBytes + sizeof(IMAGE_DOS_HEADER), pAdjusted->DosStub.u64Size);
	memcpy(&pAdjusted->NTHeaders, raw.pBytes + pAdjusted->DosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
	pAdjusted->pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(malloc(pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
	memcpy(pAdjusted->pSectionHeaders, raw.pBytes + pAdjusted->DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64), pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

	// Load sections
	pAdjusted->pSectionData = reinterpret_cast<BYTE**>(malloc(pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections * sizeof(BYTE*)));
	DWORD dwOff = pAdjusted->pSectionHeaders[0].PointerToRawData;
	for (int i = 0; i < pAdjusted->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		pAdjusted->pSectionHeaders[i].SizeOfRawData = pAdjusted->pSectionHeaders[i].Misc.VirtualSize;
		dwOff += pAdjusted->pSectionHeaders[i].SizeOfRawData;
		dwOff += (dwOff % pAdjusted->NTHeaders.x64.OptionalHeader.FileAlignment) ? pAdjusted->NTHeaders.x64.OptionalHeader.FileAlignment - (dwOff % pAdjusted->NTHeaders.x64.OptionalHeader.FileAlignment) : 0;
		pAdjusted->pSectionData[i] = reinterpret_cast<BYTE*>(malloc(pAdjusted->pSectionHeaders[i].SizeOfRawData));
		memcpy(pAdjusted->pSectionData[i], raw.pBytes + pAdjusted->pSectionHeaders[i].VirtualAddress, pAdjusted->pSectionHeaders[i].SizeOfRawData);
	}

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
	printf("\tpost\t\tIntended for use on a dumped application\n\n");

	printf("GENERAL OPTIONS\n");
	printf("\t-o OUTPUT\tSelect output path\n\n");

	printf("PRE OPTIONS\n");
	printf("\t--no-aslr\tDon\'t touch ASLR, leave as is\n");
	printf("\t--no-tls\tDon\'t remove invalid TLS callbacks\n\n");

	printf("POST OPTIONS\n");
	printf("\t--pid\t\tFILE is the PID of a running process\n");
	printf("\t--name\t\tFILE is the name of a running process\n");
	printf("\t--base ADDRESS\tBase address of running process/dumped PE\n");
	printf("\t--headers FILE\tSpecify PE that contains dumped PE\'s headers\n");
	printf("\t--dont-set\tDon\'t change EP or TLS entry points, even if matching sig is found\n");
	printf("\t--no-oep\tDon\'t scan for possible OEP\n");
	printf("\t--no-tls\tDon\'t scan for possible TLS callbacks\n");
	printf("\t--disk\t\tFILE has already been adjusted to disk format (i.e. Scylla dump)\n");
	printf("\t--x-only\tOnly scan memory in executable ranges\n");
}


/// <summary>
/// Find offset of a sig.
/// </summary>
/// <param name="buf">Buffer to search</param>
/// <param name="pattern">Byte pattern to look for</param>
/// <param name="mask">Pattern mask (i.e. "xxx???xx", matches all bytes except "?")</param>
/// <returns>_UI64_MAX if not found, otherwise it's the offset to it</returns>
size_t FindSig(Buffer buf, BYTE* pattern, char* mask) {
	if (!pattern || !mask || buf.pBytes || buf.u64Size) return _UI64_MAX;

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