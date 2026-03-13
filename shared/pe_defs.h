#pragma once
#include <cstdint>

namespace sakura {

#pragma pack(push, 1)

struct DosHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectories[16];
};

struct NtHeaders64 {
    uint32_t Signature;
    FileHeader FileHeader;
    OptionalHeader64 OptionalHeader;
};

struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct BaseRelocation {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

struct ImportDescriptor {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct ImportByName {
    uint16_t Hint;
    char     Name[1];
};

struct TlsDirectory64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

#pragma pack(pop)

constexpr uint16_t DOS_MAGIC = 0x5A4D;
constexpr uint32_t NT_SIGNATURE = 0x00004550;
constexpr uint16_t OPTIONAL_HDR64_MAGIC = 0x20B;
constexpr uint16_t MACHINE_AMD64 = 0x8664;

constexpr int DIR_EXPORT    = 0;
constexpr int DIR_IMPORT    = 1;
constexpr int DIR_RESOURCE  = 2;
constexpr int DIR_EXCEPTION = 3;
constexpr int DIR_SECURITY  = 4;
constexpr int DIR_BASERELOC = 5;
constexpr int DIR_DEBUG     = 6;
constexpr int DIR_TLS       = 9;
constexpr int DIR_IAT       = 12;

constexpr uint16_t RELOC_ABSOLUTE = 0;
constexpr uint16_t RELOC_DIR64    = 10;

constexpr uint64_t ORDINAL_FLAG64 = 0x8000000000000000ULL;

} // namespace sakura
