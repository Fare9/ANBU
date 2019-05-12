#pragma once

#ifndef STRUCTURES_AND_ENUMS_H
#define STRUCTURES_AND_ENUMS_H


/// @brief The Import Directory Table.
///
/// There is a single array of these and one entry per imported DLL.
struct pe_import
{
	uint32_t ImportLookupTableRVA;
	uint32_t TimeDateStamp;
	uint32_t ForwarderChain;
	uint32_t NameRVA;
	uint32_t ImportAddressTableRVA;
};

// values
static const uint16_t mz_signature = 0x5a4d; // MZ in little-endian


static const uint32_t correct_pe_signature_k = 0x4550;	// PE in little-endian


static const int32_t MaxNumberOfSections16 = 65279;


static const uint32_t NameSize = 8;

// enums
enum MACHINE_TYPES {
	IMAGE_FILE_MACHINE_UNKNOWN_k = 0x0,
	IMAGE_FILE_MACHINE_AM33_k = 0x1d3,
	IMAGE_FILE_MACHINE_AMD64_k = 0x8664,
	IMAGE_FILE_MACHINE_ARM_k = 0x1c0,
	IMAGE_FILE_MACHINE_ARM64_k = 0xaa64,
	IMAGE_FILE_MACHINE_ARMNT_k = 0x1c4,
	IMAGE_FILE_MACHINE_EBC_k = 0xebc,
	IMAGE_FILE_MACHINE_I386_k = 0x014C,
	IMAGE_FILE_MACHINE_IA64_k = 0x0200,
	IMAGE_FILE_MACHINE_M32R_k = 0x9041,
	IMAGE_FILE_MACHINE_MIPS16_k = 0x266,
	IMAGE_FILE_MACHINE_MIPSFPU_k = 0x366,
	IMAGE_FILE_MACHINE_MIPSFPU16_k = 0x466,
	IMAGE_FILE_MACHINE_POWERPC_k = 0x1f0,
	IMAGE_FILE_MACHINE_POWERPCFP_k = 0x1f1,
	IMAGE_FILE_MACHINE_R4000_k = 0x166,
	IMAGE_FILE_MACHINE_RISCV32_k = 0x5032,
	IMAGE_FILE_MACHINE_RISCV64_k = 0x5064,
	IMAGE_FILE_MACHINE_RISCV128_k = 0x5128,
	IMAGE_FILE_MACHINE_SH3_k = 0x1a2,
	IMAGE_FILE_MACHINE_SH3DSP_k = 0x1a3,
	IMAGE_FILE_MACHINE_SH4_k = 0x1a6,
	IMAGE_FILE_MACHINE_SH5_k = 0x1a8,
	IMAGE_FILE_MACHINE_THUMB_k = 0x1c2,
	IMAGE_FILE_MACHINE_WCEMIPSV2_k = 0x169
};


enum HEADER_CHARACTERISTICS
{
	IMAGE_FILE_INVALID_k = 0x0000,
	IMAGE_FILE_RELOCS_STRIPPED_k = 0x0001,
	IMAGE_FILE_EXECUTABLE_IMAGE_k = 0x0002,
	IMAGE_FILE_LINE_NUMS_STRIPPED_k = 0x0004,
	IMAGE_FILE_LOCAL_SYMS_STRIPPED_k = 0x0008,
	IMAGE_FILE_AGGRESSIVE_WS_TRIM_k = 0x0010,
	IMAGE_FILE_LARGE_ADDRESS_AWARE_k = 0x0020,
	RESERVED_CHARACTERISTIC_k = 0x0040,
	IMAGE_FILE_BYTES_REVERSED_LO_k = 0x0080,
	IMAGE_FILE_32BIT_MACHINE_k = 0x0100,
	IMAGE_FILE_DEBUG_STRIPPED_k = 0x0200,
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP_k = 0x0400,
	IMAGE_FILE_NET_RUN_FROM_SWAP_k = 0x0800,
	IMAGE_FILE_SYSTEM_k = 0x1000,
	IMAGE_FILE_DLL_k = 0x2000,
	IMAGE_FILE_UP_SYSTEM_ONLY_k = 0x4000,
	IMAGE_FILE_BYTES_REVERSED_HI_k = 0x8000
};


enum class PE_TYPE : uint16_t
{
	rom_image_k = 0x107,
	pe32_k = 0x10B,
	pe64_k = 0x20B
};


enum class SUBSYSTEM : uint16_t
{
	IMAGE_SUBSYSTEM_UNKNOWN_k = 0,
	IMAGE_SUBSYSTEM_NATIVE_k = 1,
	IMAGE_SUBSYSTEM_WINDOWS_GUI_k = 2,
	IMAGE_SUBSYSTEM_WINDOWS_CUI_k = 3,
	IMAGE_SUBSYSTEM_OS2_CUI_k = 5,
	IMAGE_SUBSYSTEM_POSIX_CUI_k = 7,
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS_k = 8,
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI_k = 9,
	IMAGE_SUBSYSTEM_EFI_APPLICATION_k = 10,
	IMAGE_SUBSYSTEM_EFI_BOOT__k = 11,
	IMAGE_SUBSYSTEM_EFI_RUNTIME__k = 12,
	IMAGE_SUBSYSTEM_EFI_ROM_k = 13,
	IMAGE_SUBSYSTEM_XBOX_k = 14,
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION_k = 16
};


enum class DLL_CHARACTERISTICS : uint16_t
{
	RESERVED_DLL_CHARACTERISTICS_1_k = 0x0001,
	RESERVED_DLL_CHARACTERISTICS_2_k = 0x0002,
	RESERVED_DLL_CHARACTERISTICS_4_k = 0x0004,
	RESERVED_DLL_CHARACTERISTICS_8_k = 0x0008,
	IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA_k = 0x0020,
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE_k = 0x0040,
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY_k = 0x0080,
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT_k = 0x0100,
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION_k = 0x0200,
	IMAGE_DLLCHARACTERISTICS_NO_SEH_k = 0x0400,
	IMAGE_DLLCHARACTERISTICS_NO_BIND_k = 0x0800,
	IMAGE_DLLCHARACTERISTICS_APPCONTAINER_k = 0x1000,
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER_k = 0x2000,
	IMAGE_DLLCHARACTERISTICS_GUARD_CF_k = 0x4000,
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE_k = 0x8000
};


enum class DATA_DIRECTORY : size_t
{
	export_table_k = 0,
	import_table_k,
	resource_table_k,
	exception_table_k,
	certificate_table_k,
	base_relocation_table_k,
	debug_k,
	architecture_k,
	global_ptr_k,
	tls_table_k,
	load_config_table_k,
	bound_import_k,
	iat_k,
	delay_import_descriptor_k,
	clr_runtime_header_k,
	reserved_k
};


enum class SECTION_CHARACTERISTICS : uint32_t
{
	RESERVED_SECTION_FLAG_0_k = 0x00000000,
	RESERVED_SECTION_FLAG_1_k = 0x00000001,
	RESERVED_SECTION_FLAG_2_k = 0x00000002,
	RESERVED_SECTION_FLAG_4_k = 0x00000004,
	RESERVED_SECTION_FLAG_10_k = 0x00000010,
	RESERVED_SECTION_FLAG_400_k = 0x00000400,
	IMAGE_SCN_TYPE_NO_PAD_k = 0x00000008,
	IMAGE_SCN_CNT_CODE_k = 0x00000020,
	IMAGE_SCN_CNT_INITIALIZED_DATA_k = 0x00000040,
	IMAGE_SCN_CNT_UNINITIALIZED_DATA_k = 0x00000080,
	IMAGE_SCN_LNK_OTHER_k = 0x00000100,
	IMAGE_SCN_LNK_INFO_k = 0x00000200,
	IMAGE_SCN_LNK_REMOVE_k = 0x00000800,
	IMAGE_SCN_LNK_COMDAT_k = 0x00001000,
	IMAGE_SCN_GPREL_k = 0x00008000,
	IMAGE_SCN_MEM_PURGEABLE_k = 0x00020000,
	IMAGE_SCN_MEM_16BIT_k = 0x00020000,
	IMAGE_SCN_MEM_LOCKED_k = 0x00040000,
	IMAGE_SCN_MEM_PRELOAD_k = 0x00080000,
	IMAGE_SCN_ALIGN_1BYTES_k = 0x00100000,
	IMAGE_SCN_ALIGN_2BYTES_k = 0x00200000,
	IMAGE_SCN_ALIGN_4BYTES_k = 0x00300000,
	IMAGE_SCN_ALIGN_8BYTES_k = 0x00400000,
	IMAGE_SCN_ALIGN_16BYTES_k = 0x00500000,
	IMAGE_SCN_ALIGN_32BYTES_k = 0x00600000,
	IMAGE_SCN_ALIGN_64BYTES_k = 0x00700000,
	IMAGE_SCN_ALIGN_128BYTES_k = 0x00800000,
	IMAGE_SCN_ALIGN_256BYTES_k = 0x00900000,
	IMAGE_SCN_ALIGN_512BYTES_k = 0x00A00000,
	IMAGE_SCN_ALIGN_1024BYTES_k = 0x00B00000,
	IMAGE_SCN_ALIGN_2048BYTES_k = 0x00C00000,
	IMAGE_SCN_ALIGN_4096BYTES_k = 0x00D00000,
	IMAGE_SCN_ALIGN_8192BYTES_k = 0x00E00000,
	IMAGE_SCN_LNK_NRELOC_OVFL_k = 0x01000000,
	IMAGE_SCN_MEM_DISCARDABLE_k = 0x02000000,
	IMAGE_SCN_MEM_NOT_CACHED_k = 0x04000000,
	IMAGE_SCN_MEM_NOT_PAGED_k = 0x08000000,
	IMAGE_SCN_MEM_SHARED_k = 0x10000000,
	IMAGE_SCN_MEM_EXECUTE_k = 0x20000000,
	IMAGE_SCN_MEM_READ_k = 0x40000000,
	IMAGE_SCN_MEM_WRITE_k = 0x80000000
};


#pragma pack(push,1)
struct pe_dos_header
{
	uint16_t Magic;
	uint16_t UsedBytesInTheLastPage;
	uint16_t FileSizeInPages;
	uint16_t NumberOfRelocationItems;
	uint16_t HeaderSizeInParagraphs;
	uint16_t MinimumExtraParagraphs;
	uint16_t MaximumExtraParagraphs;
	uint16_t InitialRelativeSS;
	uint16_t InitialSP;
	uint16_t Checksum;
	uint16_t InitialIP;
	uint16_t InitialRelativeCS;
	uint16_t AddressOfRelocationTable;
	uint16_t OverlayNumber;
	uint16_t Reserved[4];
	uint16_t OEMid;
	uint16_t OEMinfo;
	uint16_t Reserved2[10];
	uint32_t AddressOfNewExeHeader;
};


struct pe_header
{
	uint32_t signature;
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
};


struct pe64_optional_header
{
	uint16_t Magic;
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint; // RVA
	uint32_t BaseOfCode; // RVA
	//uint32_t BaseOfData; // RVA
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
	uint16_t DLLCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSize;
};


struct pe32_optional_header
{
	uint16_t Magic;
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint; // RVA
	uint32_t BaseOfCode; // RVA
	uint32_t BaseOfData; // RVA
	uint32_t ImageBase;
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
	uint16_t DLLCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSize;
};


struct pe_data_directory
{
	uint32_t RelativeVirtualAddress;
	uint32_t Size;
};


struct pe_section {
	char     Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLineNumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLineNumbers;
	uint32_t Characteristics;
};
#pragma pack(pop)



#endif // !STRUCTURES_AND_ENUMS_H
