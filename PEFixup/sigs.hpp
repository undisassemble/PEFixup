#pragma once
#include <Windows.h>

struct Sig {
	BYTE* raw = NULL;
	char* mask = NULL;
	char* name = NULL;
};

namespace _Sigs {
	Sig EP_MSVC = { (BYTE*)"\x48\x89\x4C\x24\x08\x48\x83\xEC\x28\xE8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3", "xxxxxxxxxx????xxxxx", "MSVC"};

	Sig EP_MINGW = { (BYTE*)"\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\xC7\x00\x01\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x90\x48\x83\xC4\x28\xC3", "xxxxxxx????xxxxxxx????xxxxxxx", "MinGW G++" };
}

namespace Sigs {
	Sig EPs[] = {
		_Sigs::EP_MSVC,
		_Sigs::EP_MINGW
	};

	Sig TLS[];
}