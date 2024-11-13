#pragma once

#include <Windows.h>
#include <stdint.h>

struct Buffer {
	BYTE* pBytes;
	uint64_t u64Size;

	void Merge(_In_ Buffer Other, _In_ bool bDontFree = false) {
		if (!Other.pBytes || !Other.u64Size) {
			return;
		}
		else if (!pBytes || !u64Size) {
			pBytes = Other.pBytes;
			u64Size = Other.u64Size;
		}
		else {
			u64Size += Other.u64Size;
			pBytes = reinterpret_cast<BYTE*>(realloc(pBytes, u64Size));
			memcpy(pBytes + u64Size - Other.u64Size, Other.pBytes, Other.u64Size);
			if (!bDontFree) {
				free(Other.pBytes);
				Other.pBytes = NULL;
				Other.u64Size = 0;
			}
		}
	}
};

template <typename T>
struct Vector {
	Buffer raw = { 0 };
	DWORD nItems = 0;
	bool bExponentialGrowth : 1 = false; // Faster on larger vectors
	bool bCannotBeReleased : 1 = false; // If the buffer is within another memory block

	void Merge(_In_ Vector<T> Other, _In_ bool bDontFree = false) {
		raw.u64Size = nItems * sizeof(T);
		raw.Merge(Other.raw, bDontFree);
		nItems += Other.nItems;
	}

	size_t Size() {
		return nItems;
	}

	size_t Capacity() {
		return raw.u64Size / sizeof(T);
	}

	void Grow() {
		if (bCannotBeReleased) return;

		// Create buffer
		if (raw.u64Size < sizeof(T) || !raw.pBytes || !raw.u64Size) {
			raw.u64Size = sizeof(T) * (bExponentialGrowth ? 10 : 1);
			raw.pBytes = reinterpret_cast<BYTE*>(realloc(raw.pBytes, raw.u64Size));
			ZeroMemory(raw.pBytes, raw.u64Size);
		}

		// Expand buffer
		else if (raw.u64Size < nItems * sizeof(T)) {
			uint64_t OldSize = raw.u64Size;
			if (bExponentialGrowth) {
				while (raw.u64Size < nItems * sizeof(T)) {
					raw.u64Size = sizeof(T) * (raw.u64Size / sizeof(T)) * 1.1;
				}
			}
			else {
				raw.u64Size = nItems * sizeof(T);
			}
			raw.pBytes = reinterpret_cast<BYTE*>(realloc(raw.pBytes, raw.u64Size));
			ZeroMemory(raw.pBytes + OldSize, raw.u64Size - OldSize);
		}
	}

	T At(_In_ DWORD i) {
		if (!raw.pBytes || !raw.u64Size || Size() <= i) {
			T ret;
			ZeroMemory(&ret, sizeof(T));
			return ret;
		}
		return ((T*)raw.pBytes)[i];
	}

	void Push(_In_ T Item) {
		if (bCannotBeReleased) return;
		nItems++;
		Grow();
		memcpy(raw.pBytes + (nItems - 1) * sizeof(T), &Item, sizeof(T));
	}

	void Push(Vector<T> Items) {
		for (int i = 0; i < Items.Size(); i++) {
			Push(Items.At(i));
		}
	}

	T Pop() {
		if (!raw.u64Size || !raw.pBytes || bCannotBeReleased) {
			T ret;
			ZeroMemory(&ret, sizeof(T));
			return ret;
		}
		T ret = At(Size() - 1);
		if (Size() == 1) {
			Release();
		}
		else {
			nItems--;
		}
		return ret;
	}

	void Replace(_In_ DWORD i, _In_ T Item) {
		if (i < Size()) {
			((T*)raw.pBytes)[i] = Item;
		}
	}

	// Replaces first instruction, inserts the remainder
	void Replace(_In_ DWORD i, _In_ Vector<T> Item) {
		if (!Item.Size() || i >= Size()) return;
		Replace(i, Item.At(0));
		Item.nItems--;
		Item.raw.pBytes += sizeof(T);
		Item.raw.u64Size -= sizeof(T);
		Insert(i + 1, Item);
		Item.raw.u64Size += sizeof(T);
		Item.raw.pBytes -= sizeof(T);
		Item.nItems++;
	}

	void Release() {
		if (raw.pBytes && !bCannotBeReleased) free(raw.pBytes);
		raw.pBytes = NULL;
		raw.u64Size = 0;
		nItems = 0;
	}

	void Insert(_In_ DWORD i, _In_ T Item) {
		if (i > Size() || bCannotBeReleased) return;
		if (i == Size()) {
			Push(Item);
			return;
		}
		nItems++;
		Grow();

		// Shift memory
		memmove(raw.pBytes + (i + 1) * sizeof(T), raw.pBytes + i * sizeof(T), (nItems - i - 1) * sizeof(T));

		// Insert item
		Replace(i, Item);
	}

	void Insert(_In_ DWORD i, _In_ Vector<T> Items) {
		if (i > Size() || bCannotBeReleased) return;

		// Size stuff
		nItems += Items.nItems;
		Grow();

		// Add to end
		if (i == Size()) {
			memcpy(raw.pBytes + i * sizeof(T), Items.raw.pBytes, Items.nItems * sizeof(T));
		}

		// Shift and insert
		else {
			memmove(raw.pBytes + (i + Items.nItems) * sizeof(T), raw.pBytes + i * sizeof(T), (nItems - i - Items.nItems) * sizeof(T));
			memcpy(raw.pBytes + i * sizeof(T), Items.raw.pBytes, Items.nItems * sizeof(T));
		}
	}

	void Remove(_In_ DWORD i) {
		if (!raw.u64Size || !raw.pBytes || i >= Size() || bCannotBeReleased) return;
		memcpy(raw.pBytes + sizeof(T) * i, raw.pBytes + sizeof(T) * (i + 1), (nItems * sizeof(T)) - sizeof(T) * (i + 1));
		nItems--;
	}

	bool Includes(_In_ T Item) {
		for (int i = 0, n = Size(); i < n; i++) {
			if (!memcmp(&Item, &((T*)raw.pBytes)[i], sizeof(T))) return true;
		}
		return false;
	}
};

enum PEStatus_t : BYTE {
	Normal = 0,								// No noticed errors
	NotSet = 1,								// Parser has not been given a file
	NoFile = 2,								// File provided does not exist
	NotPE = 3,								// File provided is not a PE or is corrupt
	Unsupported = 4							// PE is an unsupported architecture or format
};

typedef union {
	IMAGE_NT_HEADERS32 x86;
	IMAGE_NT_HEADERS64 x64;
} ComboNTHeaders;

typedef struct {
	DWORD LookupRVA;
	DWORD TimeStamp;
	DWORD Forward;
	DWORD NameRVA;
	DWORD ThunkRVA;
} IAT_ENTRY;

/// <summary>
/// Parses portable executable formats
/// </summary>
class PE {
public:
	PEStatus_t Status = NotSet;
	Buffer DosStub = { 0 };
	Buffer Overlay = { 0 };
	DWORD OverlayOffset = 0;
	BYTE** pSectionData = NULL;
	IMAGE_DOS_HEADER DosHeader = { 0 };
	ComboNTHeaders NTHeaders = { 0 };
	IMAGE_SECTION_HEADER* pSectionHeaders = NULL;
	bool x86 = false;

	/// <summary>
	/// Creates PE object with given file
	/// </summary>
	/// <param name="sFileName">Path to the file to be read</param>
	PE(_In_ char* sFileName);
	
	/// <summary>
	/// Creates PE object with given file
	/// </summary>
	/// <param name="hFile">Handle to a file with GENERIC_READ permissions</param>
	PE(_In_ HANDLE hFile);

	/// <summary>
	/// Creates empty PE object
	/// </summary>
	/// <param name="x86">True if the binary is 32-bit</param>
	PE(_In_ bool x86);

	/// <summary>
	/// Duplicates a PE object
	/// </summary>
	/// <param name="pOther">Object to duplicate</param>
	PE(_In_ PE* pOther);

	~PE();

	void OverrideStatus(_In_ PEStatus_t NewStatus) { Status = NewStatus; }

	/// <summary>
	/// Retrieves the TLS callback array (can be written to/modified)
	/// </summary>
	/// <returns>Pointer to TLS callbacks</returns>
	uint64_t* GetTLSCallbacks();

	/// <summary>
	/// Parses a file
	/// </summary>
	/// <param name="hFile">Handle to a file with GENERIC_READ permissions</param>
	bool ParseFile(_In_ HANDLE hFile);

	/// <summary>
	/// Changes a PEs base address (and handles relocations)
	/// </summary>
	/// <param name="u64NewBase">New base address</param>
	void RebaseImage(_In_ uint64_t u64NewBase);

	/// <summary>
	/// Gets the raw bytes of a section
	/// </summary>
	/// <param name="sName">Name of the section</param>
	/// <returns>Raw section bytes and size</returns>
	Buffer GetSectionBytes(_In_ char* sName);

	/// <summary>
	/// Gets the raw bytes of a section
	/// </summary>
	/// <param name="wIndex">Index of the section</param>
	/// <returns>Raw section bytes and size</returns>
	Buffer GetSectionBytes(_In_ WORD wIndex);

	/// <summary>
	/// Finds section header with given name
	/// </summary>
	/// <param name="sName">Name of section to look for</param>
	/// <returns>Pointer to the section header, or NULL on failure</returns>
	IMAGE_SECTION_HEADER* GetSectionHeader(_In_opt_ char* sName);

	/// <summary>
	/// Gets the section header at specified index
	/// </summary>
	/// <param name="wIndex">Index of the section</param>
	/// <returns>Pointer to the section header</returns>
	IMAGE_SECTION_HEADER* GetSectionHeader(_In_ WORD wIndex);

	/// <summary>
	/// Gets array of section headers
	/// </summary>
	/// <returns>Pointer to section headers</returns>
	IMAGE_SECTION_HEADER* GetSectionHeaders();

	void WriteRVA(_In_ DWORD dwRVA, _In_ void* pData, _In_ size_t szData);
	void ReadRVA(_In_ DWORD dwRVA, _Out_ void* pData, _In_ size_t szData);

	/// <summary>
	/// Writes data to a given RVA
	/// </summary>
	/// <typeparam name="T">Data type</typeparam>
	/// <param name="u64Address">RVA to write to</param>
	/// <param name="Data">Data to write</param>
	template <typename T>
	void WriteRVA(_In_ DWORD dwRVA, _In_ T Data) {
		WriteRVA(dwRVA, &Data, sizeof(T));
	}

	/// <summary>
	/// Read bytes from binary using a RVA
	/// </summary>
	/// <typeparam name="T">Data type</typeparam>
	/// <param name="u64Address">Address of value to be read</param>
	/// <returns>Value at address</returns>
	template <typename T>
	T ReadRVA(_In_ DWORD dwRVA) {
		T ret;
		ReadRVA(dwRVA, &ret, sizeof(T));
		return ret;
	}

	/// <summary>
	/// Retrieves the images DOS header
	/// </summary>
	/// <returns>Pointer to DOS header</returns>
	IMAGE_DOS_HEADER* GetDosHeader();

	/// <summary>
	/// Retrieves the images NT headers
	/// </summary>
	/// <returns>Pointer to NT headers</returns>
	ComboNTHeaders* GetNtHeaders();

	/// <summary>
	/// Gets PE parse status
	/// </summary>
	/// <returns>Status of parser</returns>
	PEStatus_t GetStatus();

	/// <summary>
	/// Fixes headers
	/// </summary>
	void FixHeaders();

	/// <summary>
	/// Will move & reorder section data and headers to avoid issues
	/// </summary>
	void MoveSections();

	virtual void DeleteSection(_In_ WORD wIndex);
	void OverwriteSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_opt_ size_t szBytes);
	void InsertSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_ IMAGE_SECTION_HEADER Header);
	WORD FindSection(_In_ char* sName);
	WORD FindSectionByRaw(_In_ DWORD dwRaw);
	Buffer* GetDosStub();
	void StripDosStub();
	IAT_ENTRY* GetIAT();
	Buffer* GetOverlay();
	void DiscardOverlay();
	DWORD GetOverlayOffset();
	
	/// <summary>
	/// Finds a section by RVA
	/// </summary>
	/// <param name="dwRVA">RVA</param>
	/// <returns>Section index (or -1 if not found)</returns>
	WORD FindSectionByRVA(_In_ DWORD dwRVA);

	/// <summary>
	/// Retrieves the (prefered) base address when the image is loaded into memory
	/// </summary>
	/// <returns>Base address of the image</returns>
	uint64_t GetBaseAddress();

	/// <summary>
	/// Translates a runtime offset to a file offset
	/// </summary>
	/// <param name="dwRVA">Runtime offset</param>
	/// <returns>File offset</returns>
	DWORD RVAToRaw(_In_ DWORD dwRVA);

	/// <summary>
	/// Translates a file offset to a runtime offset
	/// </summary>
	/// <param name="dwRaw">File offset</param>
	/// <returns>Runtime offset</returns>
	DWORD RawToRVA(_In_ DWORD dwRaw);

	/// <summary>
	/// Dumps all data into a single binary
	/// </summary>
	/// <param name="hFile">Handle to output file (must have GENERIC_WRITE perms)</param>
	/// <returns>true on success</returns>
	bool ProduceBinary(_In_ HANDLE hFile);

	/// <summary>
	/// Dumps all data into a single binary
	/// </summary>
	/// <param name="sName">Name of the output file</param>
	/// <returns>true on success</returns>
	bool ProduceBinary(_In_ char* sName);

	Vector<DWORD> GetExportedFunctionRVAs();
	Vector<char*> GetExportedFunctionNames();
	Vector<IMAGE_IMPORT_DESCRIPTOR> GetImportedDLLs();
	char* ReadRVAString(_In_ DWORD dwRVA);
	Vector<DWORD> GetRelocations();
};