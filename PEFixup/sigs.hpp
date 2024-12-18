#pragma once
#include <Windows.h>

struct Sig {
	BYTE* raw = NULL;
	char* mask = NULL;
	char* name = NULL;
};

namespace _Sigs {
	namespace x64 {
		Sig EP_MSVC = { (BYTE*)"\x48\x89\x4C\x24\x08\x48\x83\xEC\x28\xE8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3", "xxxxxxxxxx????xxxxx", "MSVC" };
		Sig EP_MSVC_DLL = { (BYTE*)"\x48\x89\x44\x24\x18\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x48\x83\xEC\x28\x83\x7C\x24\x38\x01\x75\x00\xE8\x00\x00\x00\x00\x4C\x8B\x44\x24\x40\x8B\x54\x24\x38\x48\x8B\x4C\x24\x30\xE8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3", "xxxxxxxxxxxxxxxxxxxxxxxx?x????xxxxxxxxxxxxxxx????xxxxx", "MSVC, DLL" };
		Sig EP_MINGW = { (BYTE*)"\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\xC7\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x90\x48\x83\xC4\x28\xC3", "xxxxxxx????xxxxxxx????xxxxxxx", "MinGW G++" };
		Sig EP_MINGW_DLL = { (BYTE*)"\x41\x54\x55\x57\x56\x53\x48\x83\xEC\x20\x4C\x8B\x25\x00\x00\x00\x00\x48\x89\xCE\x41\x89\x14\x24\x89\xD3\x4C\x89\xC7\x85\xD2\x75", "xxxxxxxxxxxxx????xxxxxxxxxxxxxxx", "MinGW G++, DLL" };
		Sig EP_CLANG = { (BYTE*)"\x48\x83\xEC\x28\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x45\x31\xC0\x31\xD2\x31\xC9", "xxxxxxx????x????xxxxxxx", "Clang" };
		Sig EP_CLANG_DLL = { (BYTE*)"\x48\x83\xEC\x38\x83\xFA\x02\x74\x00\x77\x00\x85\xD2\x0F\x84\x00\x00\x00\x00\x31\xC0\x4D\x85\xC0\x48\x8D\x15", "xxxxxxxx?x?xxxx????xxxxxxxx", "Clang, DLL" };

		Sig TLS1_MINGW = { (BYTE*)"\x56\x53\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x83\x38\x02\x74\x00\xC7\x00\x02\x00\x00\x00\x83\xFA\x02\x74\x00\x83\xFA\x01\x74\x00\xB8\x01\x00\x00\x00\x48\x83\xC4\x28\x5B\x5E\xC3", "xxxxxxxxx????xxxx?xxxxxxxxxx?xxxx?xxxxxxxxxxxx", "MinGW G++" };
		Sig TLS2_MINGW = { (BYTE*)"\x48\x83\xEC\x28\x83\xFA\x03\x74\x00\x85\xD2\x74\x00\xB8\x01\x00\x00\x00\x48\x83\xC4\x28\xC3", "xxxxxxxx?xxx?xxxxxxxxxx", "MinGW G++" };
	}

	namespace x86 {
		Sig EP_MINGW = { (BYTE*)"\x8D\x4C\x24\x04\x83\xE4\xF0\xFF\x71\xFC\x55\x89\xE5\x57\x56\x53\x31\xDB\x51\x83\xEC\x28\x8B\x35\x00\x00\x00\x00\x64\xA1\x18\x00\x00\x00\x8B\x78\x04\xEB", "xxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxx", "MinGW G++" };
	
		Sig TLS1_MINGW = { (BYTE*)"\x56\x53\x83\xEC\x14\x83\x3D\x00\x00\x00\x00\x02\x8B\x44\x24\x24\x74\x00\xC7\x05\x00\x00\x00\x00\x02\x00\x00\x00", "xxxxxxx????xxxxxx?xx????xxxx", "MinGW G++" };
		Sig TLS2_MINGW = { (BYTE*)"\x83\xEC\x1C\x8B\x44\x24\x24\x83\xF8\x03\x74\x00\x85\xC0\x74\x00\xB8\x01\x00\x00\x00\x83\xC4\x1C\xC2\x0C\x00", "xxxxxxxxxxx?xxx?xxxxxxxxxxx", "MinGW G++" };
	}
}

namespace Sigs {
	// 64 bit entry points
	Sig EPs_64[] = {
		_Sigs::x64::EP_MSVC,
		_Sigs::x64::EP_MSVC_DLL,
		_Sigs::x64::EP_MINGW,
		_Sigs::x64::EP_MINGW_DLL,
		_Sigs::x64::EP_CLANG,
		_Sigs::x64::EP_CLANG_DLL
	};

	// 64 bit TLS callbacks
	Sig TLS_64[] = {
		_Sigs::x64::TLS1_MINGW,
		_Sigs::x64::TLS2_MINGW
	};

	// 32 bit entry points
	Sig EPs_32[] = {
		_Sigs::x86::EP_MINGW
	};

	// 32 bit TLS callbacks
	Sig TLS_32[] = {
		_Sigs::x86::TLS1_MINGW,
		_Sigs::x86::TLS2_MINGW
	};
}