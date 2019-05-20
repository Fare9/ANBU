
#include "optional_header.h"

namespace pe_parser
{
	optional_header_t::optional_header_t(const pe32_optional_header *header) :
		magic_(static_cast<PE_TYPE>(header->Magic)),
		majorLinkerVersion_(header->MajorLinkerVersion),
		minorLinkerVersion_(header->MinorLinkerVersion),
		sizeOfCode_(header->SizeOfCode),
		sizeOfInitializedData_(header->SizeOfInitializedData),
		sizeOfUninitializedData_(header->SizeOfUninitializedData),
		addressOfEntryPoint_(header->AddressOfEntryPoint),
		baseOfCode_(header->BaseOfCode),
		baseOfData_(header->BaseOfData),
		imageBase_(header->ImageBase),
		sectionAlignment_(header->SectionAlignment),
		fileAlignment_(header->FileAlignment),
		majorOperatingSystemVersion_(header->MajorOperatingSystemVersion),
		minorOperatingSystemVersion_(header->MinorOperatingSystemVersion),
		majorImageVersion_(header->MajorImageVersion),
		minorImageVersion_(header->MinorImageVersion),
		majorSubsystemVersion_(header->MajorSubsystemVersion),
		minorSubsystemVersion_(header->MinorSubsystemVersion),
		win32VersionValue_(header->Win32VersionValue),
		sizeOfImage_(header->SizeOfImage),
		sizeOfHeaders_(header->SizeOfHeaders),
		checkSum_(header->CheckSum),
		subsystem_(static_cast<SUBSYSTEM>(header->Subsystem)),
		DLLCharacteristics_(static_cast<DLL_CHARACTERISTICS>(header->DLLCharacteristics)),
		sizeOfStackReserve_(header->SizeOfStackReserve),
		sizeOfStackCommit_(header->SizeOfStackCommit),
		sizeOfHeapReserve_(header->SizeOfHeapReserve),
		sizeOfHeapCommit_(header->SizeOfHeapCommit),
		loaderFlags_(header->LoaderFlags),
		numberOfRvaAndSize_(header->NumberOfRvaAndSize),
		is_64_bit(false)
	{}


	optional_header_t::optional_header_t(const pe64_optional_header *header) :
		magic_(static_cast<PE_TYPE>(header->Magic)),
		majorLinkerVersion_(header->MajorLinkerVersion),
		minorLinkerVersion_(header->MinorLinkerVersion),
		sizeOfCode_(header->SizeOfCode),
		sizeOfInitializedData_(header->SizeOfInitializedData),
		sizeOfUninitializedData_(header->SizeOfUninitializedData),
		addressOfEntryPoint_(header->AddressOfEntryPoint),
		baseOfCode_(header->BaseOfCode),
		baseOfData_(0), // Not in PE64
		imageBase_(header->ImageBase),
		sectionAlignment_(header->SectionAlignment),
		fileAlignment_(header->FileAlignment),
		majorOperatingSystemVersion_(header->MajorOperatingSystemVersion),
		minorOperatingSystemVersion_(header->MinorOperatingSystemVersion),
		majorImageVersion_(header->MajorImageVersion),
		minorImageVersion_(header->MinorImageVersion),
		majorSubsystemVersion_(header->MajorSubsystemVersion),
		minorSubsystemVersion_(header->MinorSubsystemVersion),
		win32VersionValue_(header->Win32VersionValue),
		sizeOfImage_(header->SizeOfImage),
		sizeOfHeaders_(header->SizeOfHeaders),
		checkSum_(header->CheckSum),
		subsystem_(static_cast<SUBSYSTEM>(header->Subsystem)),
		DLLCharacteristics_(static_cast<DLL_CHARACTERISTICS>(header->DLLCharacteristics)),
		sizeOfStackReserve_(header->SizeOfStackReserve),
		sizeOfStackCommit_(header->SizeOfStackCommit),
		sizeOfHeapReserve_(header->SizeOfHeapReserve),
		sizeOfHeapCommit_(header->SizeOfHeapCommit),
		loaderFlags_(header->LoaderFlags),
		numberOfRvaAndSize_(header->NumberOfRvaAndSize),
		is_64_bit(true)
	{}


	bool optional_header_t::is_64_bit_binary()
	{
		return is_64_bit;
	}


	/********** GETTERS ************/

	/*
	*	Sadly I'm not using templates, but these 2 functions
	*	correspond to LIEF builder template:
		template<typename PE_T>
		void Builder::build_optional_header(const OptionalHeader& optional_header) {
		  using uint__             = typename PE_T::uint;
		  using pe_optional_header = typename PE_T::pe_optional_header;

		  // Build optional header
		  this->optional_header().sizeof_image(static_cast<uint32_t>(this->virtual_size()));
		  this->optional_header().sizeof_headers(static_cast<uint32_t>(this->sizeof_headers()));

		  pe_optional_header optional_header_raw;
		  optional_header_raw.Magic                   = static_cast<uint16_t>(optional_header.magic());
		  optional_header_raw.MajorLinkerVersion      = static_cast<uint8_t> (optional_header.major_linker_version());
		  optional_header_raw.MinorLinkerVersion      = static_cast<uint8_t> (optional_header.minor_linker_version());
		  optional_header_raw.SizeOfCode              = static_cast<uint32_t>(optional_header.sizeof_code());
		  optional_header_raw.SizeOfInitializedData   = static_cast<uint32_t>(optional_header.sizeof_initialized_data());
		  optional_header_raw.SizeOfUninitializedData = static_cast<uint32_t>(optional_header.sizeof_uninitialized_data());
		  optional_header_raw.AddressOfEntryPoint     = static_cast<uint32_t>(optional_header.addressof_entrypoint());
		  optional_header_raw.BaseOfCode              = static_cast<uint32_t>(optional_header.baseof_code());

		  if (std::is_same<PE_T, PE32>::value) {
			// Trick to avoid compilation error
			reinterpret_cast<pe32_optional_header*>(&optional_header_raw)->BaseOfData = static_cast<uint32_t>(optional_header.baseof_data());
		  }
		  optional_header_raw.ImageBase                    = static_cast<uint__>(optional_header.imagebase());
		  optional_header_raw.SectionAlignment             = static_cast<uint32_t>(optional_header.section_alignment());
		  optional_header_raw.FileAlignment                = static_cast<uint32_t>(optional_header.file_alignment());
		  optional_header_raw.MajorOperatingSystemVersion  = static_cast<uint16_t>(optional_header.major_operating_system_version());
		  optional_header_raw.MinorOperatingSystemVersion  = static_cast<uint16_t>(optional_header.minor_operating_system_version());
		  optional_header_raw.MajorImageVersion            = static_cast<uint16_t>(optional_header.major_image_version());
		  optional_header_raw.MinorImageVersion            = static_cast<uint16_t>(optional_header.minor_image_version());
		  optional_header_raw.MajorSubsystemVersion        = static_cast<uint16_t>(optional_header.major_subsystem_version());
		  optional_header_raw.MinorSubsystemVersion        = static_cast<uint16_t>(optional_header.minor_subsystem_version());
		  optional_header_raw.Win32VersionValue            = static_cast<uint16_t>(optional_header.win32_version_value());
		  optional_header_raw.SizeOfImage                  = static_cast<uint32_t>(optional_header.sizeof_image());
		  optional_header_raw.SizeOfHeaders                = static_cast<uint32_t>(optional_header.sizeof_headers());
		  optional_header_raw.CheckSum                     = static_cast<uint32_t>(optional_header.checksum());
		  optional_header_raw.Subsystem                    = static_cast<uint16_t>(optional_header.subsystem());
		  optional_header_raw.DLLCharacteristics           = static_cast<uint16_t>(optional_header.dll_characteristics());
		  optional_header_raw.SizeOfStackReserve           = static_cast<uint__>(optional_header.sizeof_stack_reserve());
		  optional_header_raw.SizeOfStackCommit            = static_cast<uint__>(optional_header.sizeof_stack_commit());
		  optional_header_raw.SizeOfHeapReserve            = static_cast<uint__>(optional_header.sizeof_heap_reserve());
		  optional_header_raw.SizeOfHeapCommit             = static_cast<uint__>(optional_header.sizeof_heap_commit());
		  optional_header_raw.LoaderFlags                  = static_cast<uint32_t>(optional_header.loader_flags());
		  optional_header_raw.NumberOfRvaAndSize           = static_cast<uint32_t>(optional_header.numberof_rva_and_size());


		  const uint32_t address_next_header = this->dos_header().addressof_new_exeheader() + sizeof(pe_header);
		  this->ios_.seekp(address_next_header);
		  this->ios_.write(reinterpret_cast<const uint8_t*>(&optional_header_raw), sizeof(pe_optional_header));

		}
	*/

	pe32_optional_header optional_header_t::optional_header_pe32()
	{
		pe32_optional_header optional_header;

		optional_header.Magic							= static_cast<uint16_t>(this->magic_);
		optional_header.MajorLinkerVersion				= this->majorLinkerVersion_;;
		optional_header.MinorLinkerVersion				= this->minorLinkerVersion_;;
		optional_header.SizeOfCode						= this->sizeOfCode_;
		optional_header.SizeOfInitializedData			= this->sizeOfInitializedData_;
		optional_header.SizeOfUninitializedData			= this->sizeOfUninitializedData_;
		optional_header.AddressOfEntryPoint				= this->addressOfEntryPoint_;
		optional_header.BaseOfCode						= this->baseOfCode_;
		optional_header.BaseOfData						= this->baseOfData_; // only in PE32
		optional_header.ImageBase						= static_cast<uint32_t>(this->imageBase_);
		optional_header.SectionAlignment				= this->sectionAlignment_;
		optional_header.FileAlignment					= this->fileAlignment_;
		optional_header.MajorOperatingSystemVersion		= this->majorOperatingSystemVersion_;
		optional_header.MinorOperatingSystemVersion		= this->minorOperatingSystemVersion_;
		optional_header.MajorImageVersion				= this->majorImageVersion_;
		optional_header.MinorImageVersion				= this->minorImageVersion_;
		optional_header.MajorSubsystemVersion			= this->majorSubsystemVersion_;
		optional_header.MinorSubsystemVersion			= this->minorSubsystemVersion_;
		optional_header.Win32VersionValue				= this->win32VersionValue_;
		optional_header.SizeOfImage						= this->sizeOfImage_;
		optional_header.SizeOfHeaders					= this->sizeOfHeaders_;
		optional_header.CheckSum						= this->checkSum_;
		optional_header.Subsystem						= static_cast<uint16_t>(this->subsystem_);
		optional_header.DLLCharacteristics				= static_cast<uint16_t>(this->DLLCharacteristics_);
		optional_header.SizeOfStackReserve				= static_cast<uint32_t>(this->sizeOfStackReserve_);
		optional_header.SizeOfStackCommit				= static_cast<uint32_t>(this->sizeOfStackCommit_);
		optional_header.SizeOfHeapReserve				= static_cast<uint32_t>(this->sizeOfHeapReserve_);
		optional_header.SizeOfHeapCommit				= static_cast<uint32_t>(this->sizeOfHeapCommit_);
		optional_header.LoaderFlags						= this->loaderFlags_;
		optional_header.NumberOfRvaAndSize				= this->numberOfRvaAndSize_;

		return optional_header;
	}


	pe64_optional_header optional_header_t::optional_header_pe64()
	{
		pe64_optional_header optional_header;

		optional_header.Magic							= static_cast<uint16_t>(this->magic_);
		optional_header.MajorLinkerVersion				= this->majorLinkerVersion_;;
		optional_header.MinorLinkerVersion				= this->minorLinkerVersion_;;
		optional_header.SizeOfCode						= this->sizeOfCode_;
		optional_header.SizeOfInitializedData			= this->sizeOfInitializedData_;
		optional_header.SizeOfUninitializedData			= this->sizeOfUninitializedData_;
		optional_header.AddressOfEntryPoint				= this->addressOfEntryPoint_;
		optional_header.BaseOfCode						= this->baseOfCode_;
		//optional_header.BaseOfData						= this->baseOfData_; // only in PE32
		optional_header.ImageBase						= this->imageBase_;
		optional_header.SectionAlignment				= this->sectionAlignment_;
		optional_header.FileAlignment					= this->fileAlignment_;
		optional_header.MajorOperatingSystemVersion		= this->majorOperatingSystemVersion_;
		optional_header.MinorOperatingSystemVersion		= this->minorOperatingSystemVersion_;
		optional_header.MajorImageVersion				= this->majorImageVersion_;
		optional_header.MinorImageVersion				= this->minorImageVersion_;
		optional_header.MajorSubsystemVersion			= this->majorSubsystemVersion_;
		optional_header.MinorSubsystemVersion			= this->minorSubsystemVersion_;
		optional_header.Win32VersionValue				= this->win32VersionValue_;
		optional_header.SizeOfImage						= this->sizeOfImage_;
		optional_header.SizeOfHeaders					= this->sizeOfHeaders_;
		optional_header.CheckSum						= this->checkSum_;
		optional_header.Subsystem						= static_cast<uint16_t>(this->subsystem_);
		optional_header.DLLCharacteristics				= static_cast<uint16_t>(this->DLLCharacteristics_);
		optional_header.SizeOfStackReserve				= this->sizeOfStackReserve_;
		optional_header.SizeOfStackCommit				= this->sizeOfStackCommit_;
		optional_header.SizeOfHeapReserve				= this->sizeOfHeapReserve_;
		optional_header.SizeOfHeapCommit				= this->sizeOfHeapCommit_;
		optional_header.LoaderFlags						= this->loaderFlags_;
		optional_header.NumberOfRvaAndSize				= this->numberOfRvaAndSize_;

		return optional_header;
	}


	PE_TYPE optional_header_t::magic(void) const 
	{
		return this->magic_;
	}


	uint8_t optional_header_t::major_linker_version(void) const 
	{
		return this->majorLinkerVersion_;
	}


	uint8_t optional_header_t::minor_linker_version(void) const 
	{
		return this->minorLinkerVersion_;
	}


	uint32_t optional_header_t::sizeof_code(void) const 
	{
		return this->sizeOfCode_;
	}


	uint32_t optional_header_t::sizeof_initialized_data(void) const 
	{
		return this->sizeOfInitializedData_;
	}


	uint32_t optional_header_t::sizeof_uninitialized_data(void) const
	{
		return this->sizeOfUninitializedData_;
	}


	uint32_t optional_header_t::addressof_entrypoint(void) const 
	{
		return this->addressOfEntryPoint_;
	}


	uint32_t optional_header_t::baseof_code(void) const 
	{
		return this->baseOfCode_;
	}


	uint32_t optional_header_t::baseof_data(void) const {
		if (this->magic() == PE_TYPE::pe32_k) {
			return this->baseOfData_;
		}
		else {
			return 0;
		}
	}


	uint64_t optional_header_t::imagebase(void) const 
	{
		return this->imageBase_;
	}


	uint32_t optional_header_t::section_alignment(void) const 
	{
		return this->sectionAlignment_;
	}


	uint32_t optional_header_t::file_alignment(void) const 
	{
		return this->fileAlignment_;
	}


	uint16_t optional_header_t::major_operating_system_version(void) const 
	{
		return this->majorOperatingSystemVersion_;
	}


	uint16_t optional_header_t::minor_operating_system_version(void) const 
	{
		return this->minorOperatingSystemVersion_;
	}


	uint16_t optional_header_t::major_image_version(void) const 
	{
		return this->majorImageVersion_;
	}


	uint16_t optional_header_t::minor_image_version(void) const 
	{
		return this->minorImageVersion_;
	}


	uint16_t optional_header_t::major_subsystem_version(void) const 
	{
		return this->majorSubsystemVersion_;
	}


	uint16_t optional_header_t::minor_subsystem_version(void) const 
	{
		return this->minorSubsystemVersion_;
	}


	uint32_t optional_header_t::win32_version_value(void) const 
	{
		return this->win32VersionValue_;
	}


	uint32_t optional_header_t::sizeof_image(void) const 
	{
		return this->sizeOfImage_;
	}


	uint32_t optional_header_t::sizeof_headers(void) const 
	{
		return this->sizeOfHeaders_;
	}


	uint32_t optional_header_t::checksum(void) const 
	{
		return this->checkSum_;
	}


	SUBSYSTEM optional_header_t::subsystem(void) const 
	{
		return this->subsystem_;
	}


	DLL_CHARACTERISTICS optional_header_t::dll_characteristics(void) const 
	{
		return this->DLLCharacteristics_;
	}


	uint64_t optional_header_t::sizeof_stack_reserve(void) const 
	{
		return this->sizeOfStackReserve_;
	}


	uint64_t optional_header_t::sizeof_stack_commit(void) const 
	{
		return this->sizeOfStackCommit_;
	}


	uint64_t optional_header_t::sizeof_heap_reserve(void) const 
	{
		return this->sizeOfHeapReserve_;
	}


	uint64_t optional_header_t::sizeof_heap_commit(void) const 
	{
		return this->sizeOfHeapCommit_;
	}


	uint32_t optional_header_t::loader_flags(void) const 
	{
		return this->loaderFlags_;
	}


	uint32_t optional_header_t::numberof_rva_and_size(void) const 
	{
		return this->numberOfRvaAndSize_;
	}


	bool optional_header_t::has(DLL_CHARACTERISTICS c) const 
	{
		return (static_cast<uint32_t>(this->dll_characteristics()) & static_cast<uint32_t>(c)) > 0;
	}


	/********** SETTERS ************/
	void optional_header_t::magic(PE_TYPE magic) 
	{
		this->magic_ = static_cast<PE_TYPE>(magic);
	}


	void optional_header_t::major_linker_version(uint8_t majorLinkerVersion) 
	{
		this->majorLinkerVersion_ = majorLinkerVersion;
	}


	void optional_header_t::minor_linker_version(uint8_t minorLinkerVersion) 
	{
		this->minorLinkerVersion_ = minorLinkerVersion;
	}


	void optional_header_t::sizeof_code(uint32_t sizeOfCode) 
	{
		this->sizeOfCode_ = sizeOfCode;
	}


	void optional_header_t::sizeof_initialized_data(uint32_t sizeOfInitializedData) 
	{
		this->sizeOfInitializedData_ = sizeOfInitializedData;
	}


	void optional_header_t::sizeof_uninitialized_data(uint32_t sizeOfUninitializedData) 
	{
		this->sizeOfUninitializedData_ = sizeOfUninitializedData;
	}


	void optional_header_t::addressof_entrypoint(uint32_t addressOfEntryPoint) 
	{
		this->addressOfEntryPoint_ = addressOfEntryPoint;
	}


	void optional_header_t::baseof_code(uint32_t baseOfCode) 
	{
		this->baseOfCode_ = baseOfCode;
	}


	void optional_header_t::baseof_data(uint32_t baseOfData) 
	{
		if (this->magic() == PE_TYPE::pe32_k) {
			this->baseOfData_ = baseOfData;
		}
		else {
			return;
		}

	}


	void optional_header_t::imagebase(uint64_t imageBase) 
	{
		this->imageBase_ = imageBase;
	}


	void optional_header_t::section_alignment(uint32_t sectionAlignment) 
	{
		this->sectionAlignment_ = sectionAlignment;
	}


	void optional_header_t::file_alignment(uint32_t fileAlignment) 
	{
		this->fileAlignment_ = fileAlignment;
	}


	void optional_header_t::major_operating_system_version(uint16_t majorOperatingSystemVersion) 
	{
		this->majorOperatingSystemVersion_ = majorOperatingSystemVersion;
	}


	void optional_header_t::minor_operating_system_version(uint16_t minorOperatingSystemVersion) 
	{
		this->minorOperatingSystemVersion_ = minorOperatingSystemVersion;
	}


	void optional_header_t::major_image_version(uint16_t majorImageVersion) 
	{
		this->majorImageVersion_ = majorImageVersion;
	}


	void optional_header_t::minor_image_version(uint16_t minorImageVersion) 
	{
		this->minorImageVersion_ = minorImageVersion;
	}


	void optional_header_t::major_subsystem_version(uint16_t majorSubsystemVersion) 
	{
		this->majorSubsystemVersion_ = majorSubsystemVersion;
	}


	void optional_header_t::minor_subsystem_version(uint16_t minorSubsystemVersion) 
	{
		this->minorSubsystemVersion_ = minorSubsystemVersion;
	}


	void optional_header_t::win32_version_value(uint32_t win32VersionValue) 
	{
		this->win32VersionValue_ = win32VersionValue;
	}


	void optional_header_t::sizeof_image(uint32_t sizeOfImage) 
	{
		this->sizeOfImage_ = sizeOfImage;
	}


	void optional_header_t::sizeof_headers(uint32_t sizeOfHeaders) 
	{
		this->sizeOfHeaders_ = sizeOfHeaders;
	}


	void optional_header_t::checksum(uint32_t checkSum) 
	{
		this->checkSum_ = checkSum;
	}


	void optional_header_t::subsystem(SUBSYSTEM subsystem) 
	{
		this->subsystem_ = subsystem;
	}


	void optional_header_t::dll_characteristics(DLL_CHARACTERISTICS DLLCharacteristics) 
	{
		this->DLLCharacteristics_ = DLLCharacteristics;
	}


	void optional_header_t::sizeof_stack_reserve(uint64_t sizeOfStackReserve) 
	{
		this->sizeOfStackReserve_ = sizeOfStackReserve;
	}


	void optional_header_t::sizeof_stack_commit(uint64_t sizeOfStackCommit) 
	{
		this->sizeOfStackCommit_ = sizeOfStackCommit;
	}


	void optional_header_t::sizeof_heap_reserve(uint64_t sizeOfHeapReserve) 
	{
		this->sizeOfHeapReserve_ = sizeOfHeapReserve;
	}


	void optional_header_t::sizeof_heap_commit(uint64_t sizeOfHeapCommit) 
	{
		this->sizeOfHeapCommit_ = sizeOfHeapCommit;
	}


	void optional_header_t::loader_flags(uint32_t loaderFlags) 
	{
		this->loaderFlags_ = loaderFlags;
	}


	void optional_header_t::numberof_rva_and_size(uint32_t numberOfRvaAndSize) 
	{
		this->numberOfRvaAndSize_ = numberOfRvaAndSize;
	}


	void optional_header_t::add(DLL_CHARACTERISTICS c) 
	{
		this->dll_characteristics(static_cast<DLL_CHARACTERISTICS>(static_cast<uint32_t>(this->dll_characteristics()) | static_cast<uint32_t>(c)));
	}


	void optional_header_t::remove(DLL_CHARACTERISTICS c) 
	{
		this->dll_characteristics(static_cast<DLL_CHARACTERISTICS>(static_cast<uint32_t>(this->dll_characteristics()) & (~static_cast<uint32_t>(c))));
	}


	size_t optional_header_t::get_optional_header_size()
	{
		if (this->is_64_bit_binary())
			return sizeof(pe64_optional_header);
		else
			return sizeof(pe32_optional_header);
	}


	bool optional_header_t::dump_optional_image(FILE *output_file)
	{
		if (!optional_header_correct)
			return false;

		ANBU::LOGGER(output_file, "================== DUMP OPTIONAL HEADER ===================\n");
		if (is_64_bit)
		{
			ANBU::LOGGER(output_file, "\t+Magic: 0x%x\n", magic_);
			ANBU::LOGGER(output_file, "\t+MajorLinkerVersion: 0x%x\n", majorLinkerVersion_);
			ANBU::LOGGER(output_file, "\t+MenorLinkerVersion: 0x%x\n", minorLinkerVersion_);
			ANBU::LOGGER(output_file, "\t+SizeOfCode: 0x%x\n", sizeOfCode_);
			ANBU::LOGGER(output_file, "\t+SizeOfInitializedData: 0x%x\n", sizeOfInitializedData_);
			ANBU::LOGGER(output_file, "\t+SizeOfUnItializedData: 0x%x\n", sizeOfUninitializedData_);
			ANBU::LOGGER(output_file, "\t+AddressOfEntryPoint: 0x%x\n", addressOfEntryPoint_);
			ANBU::LOGGER(output_file, "\t+BaseOfCode: 0x%x\n", baseOfCode_);
			ANBU::LOGGER(output_file, "\t+ImageBase: 0x%llu\n", imageBase_);
			ANBU::LOGGER(output_file, "\t+SectionAlignment: 0x%x\n", sectionAlignment_);
			ANBU::LOGGER(output_file, "\t+FileAlignment: 0x%x\n", fileAlignment_);
			ANBU::LOGGER(output_file, "\t+MajorOperatingSystemVersion: 0x%x\n", majorOperatingSystemVersion_);
			ANBU::LOGGER(output_file, "\t+MinorOperatingSystemVersion: 0x%x\n", minorOperatingSystemVersion_);
			ANBU::LOGGER(output_file, "\t+MajorImageVersion: 0x%x\n", majorImageVersion_);
			ANBU::LOGGER(output_file, "\t+MinorImageVersion: 0x%x\n", minorImageVersion_);
			ANBU::LOGGER(output_file, "\t+MajorSubsystemVersion: 0x%x\n", majorSubsystemVersion_);
			ANBU::LOGGER(output_file, "\t+MinorSubsystemVersion: 0x%x\n", minorSubsystemVersion_);
			ANBU::LOGGER(output_file, "\t+Win32VersionValue: 0x%x\n", win32VersionValue_);
			ANBU::LOGGER(output_file, "\t+SizeOfImage: 0x%x\n", sizeOfImage_);
			ANBU::LOGGER(output_file, "\t+SizeOfHeaders: 0x%x\n", sizeOfHeaders_);
			ANBU::LOGGER(output_file, "\t+Checksum: 0x%x\n", checkSum_);
			ANBU::LOGGER(output_file, "\t+Subsystem: 0x%x\n", static_cast<uint16_t>(subsystem_));
			ANBU::LOGGER(output_file, "\t+DllCharacteristics: 0x%x\n", static_cast<uint16_t>(DLLCharacteristics_));
			ANBU::LOGGER(output_file, "\t+SizeOfStackReserve: 0x%llu\n", sizeOfStackReserve_);
			ANBU::LOGGER(output_file, "\t+SizeOfStackCommit: 0x%llu\n", sizeOfStackCommit_);
			ANBU::LOGGER(output_file, "\t+SizeOfHeapReserve: 0x%llu\n", sizeOfHeapReserve_);
			ANBU::LOGGER(output_file, "\t+SizeOfHeapCommit: 0x%llu\n", sizeOfHeapCommit_);
			ANBU::LOGGER(output_file, "\t+LoaderFlags: 0x%x\n", loaderFlags_);
			ANBU::LOGGER(output_file, "\t+NumberOfRvaAndSizes: 0x%x\n", numberOfRvaAndSize_);
		}
		else
		{
			ANBU::LOGGER(output_file, "\t+Magic: 0x%x\n", magic_);
			ANBU::LOGGER(output_file, "\t+MajorLinkerVersion: 0x%x\n", majorLinkerVersion_);
			ANBU::LOGGER(output_file, "\t+MenorLinkerVersion: 0x%x\n", minorLinkerVersion_);
			ANBU::LOGGER(output_file, "\t+SizeOfCode: 0x%x\n", sizeOfCode_);
			ANBU::LOGGER(output_file, "\t+SizeOfInitializedData: 0x%x\n", sizeOfInitializedData_);
			ANBU::LOGGER(output_file, "\t+SizeOfUnItializedData: 0x%x\n", sizeOfUninitializedData_);
			ANBU::LOGGER(output_file, "\t+AddressOfEntryPoint: 0x%x\n", addressOfEntryPoint_);
			ANBU::LOGGER(output_file, "\t+BaseOfCode: 0x%x\n", baseOfCode_);
			ANBU::LOGGER(output_file, "\t+BaseOfData: 0x%x\n", baseOfData_);
			ANBU::LOGGER(output_file, "\t+ImageBase: 0x%llu\n", imageBase_);
			ANBU::LOGGER(output_file, "\t+SectionAlignment: 0x%x\n", sectionAlignment_);
			ANBU::LOGGER(output_file, "\t+FileAlignment: 0x%x\n", fileAlignment_);
			ANBU::LOGGER(output_file, "\t+MajorOperatingSystemVersion: 0x%x\n", majorOperatingSystemVersion_);
			ANBU::LOGGER(output_file, "\t+MinorOperatingSystemVersion: 0x%x\n", minorOperatingSystemVersion_);
			ANBU::LOGGER(output_file, "\t+MajorImageVersion: 0x%x\n", majorImageVersion_);
			ANBU::LOGGER(output_file, "\t+MinorImageVersion: 0x%x\n", minorImageVersion_);
			ANBU::LOGGER(output_file, "\t+MajorSubsystemVersion: 0x%x\n", majorSubsystemVersion_);
			ANBU::LOGGER(output_file, "\t+MinorSubsystemVersion: 0x%x\n", minorSubsystemVersion_);
			ANBU::LOGGER(output_file, "\t+Win32VersionValue: 0x%x\n", win32VersionValue_);
			ANBU::LOGGER(output_file, "\t+SizeOfImage: 0x%x\n", sizeOfImage_);
			ANBU::LOGGER(output_file, "\t+SizeOfHeaders: 0x%x\n", sizeOfHeaders_);
			ANBU::LOGGER(output_file, "\t+Checksum: 0x%x\n", checkSum_);
			ANBU::LOGGER(output_file, "\t+Subsystem: 0x%x\n", static_cast<uint16_t>(subsystem_));
			ANBU::LOGGER(output_file, "\t+DllCharacteristics: 0x%x\n", static_cast<uint16_t>(DLLCharacteristics_));
			ANBU::LOGGER(output_file, "\t+SizeOfStackReserve: 0x%llu\n", sizeOfStackReserve_);
			ANBU::LOGGER(output_file, "\t+SizeOfStackCommit: 0x%llu\n", sizeOfStackCommit_);
			ANBU::LOGGER(output_file, "\t+SizeOfHeapReserve: 0x%llu\n", sizeOfHeapReserve_);
			ANBU::LOGGER(output_file, "\t+SizeOfHeapCommit: 0x%llu\n", sizeOfHeapCommit_);
			ANBU::LOGGER(output_file, "\t+LoaderFlags: 0x%x\n", loaderFlags_);
			ANBU::LOGGER(output_file, "\t+NumberOfRvaAndSizes: 0x%x\n", numberOfRvaAndSize_);
		}

		return true;
	}
}