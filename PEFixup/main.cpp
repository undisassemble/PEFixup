#include <Windows.h>
#include <stdio.h>
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

	// Get files
	Settings.input = argv[2];
	
	// Check for --help or -h
	for (int i = 3; i < argc; i++) {
		if (!lstrcmpA(argv[i], "--help") || !lstrcmpA(argv[i], "-h")) {
			HelpMenu(argv[0]);
			return 0;
		}
	}


	/***** DO STUFF *****/
	PE* file = NULL;

	// Pre mode
	if (Settings.mode == 1) {
		file = new PE(Settings.input);
		PEStatus_t status = file->GetStatus();
		switch (status) {
		case NoFile:
			printf("Cannot read file %s\n", Settings.input);
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
		
	}

	// Output file
	if (!file || !file->ProduceBinary(Settings.output)) {
		printf("Failed to write to %s\n", Settings.output);
		return 1;
	}

	if (file) delete file;
	return 0;
}

void HelpMenu(char* argv0) {
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
	printf("\t--base ADDRESS\tBase address of running process\n");
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