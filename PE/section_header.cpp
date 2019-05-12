
#include "section_header.h"

/************* EXTERN VARIABLES *************/
extern FILE *logfile; // log file handler


namespace pe_parser
{
	section_header_t::section_header_t(const pe_section* header) :
		virtualSize_{ header->VirtualSize },
		pointerToRelocations_{ header->PointerToRelocations },
		pointerToLineNumbers_{ header->PointerToLineNumbers },
		numberOfRelocations_{ header->NumberOfRelocations },
		numberOfLineNumbers_{ header->NumberOfLineNumbers },
		characteristics_{ header->Characteristics }
	{
		this->name_ = std::string(header->Name, sizeof(header->Name)).c_str();
		this->virtual_address_ = header->VirtualAddress;
		this->size_ = header->SizeOfRawData;
		this->offset_ = header->PointerToRawData;

	}

	section_header_t::section_header_t(const std::vector<uint8_t>& data, const pe_section* header) :
		virtualSize_{ header->VirtualSize },
		pointerToRelocations_{ header->PointerToRelocations },
		pointerToLineNumbers_{ header->PointerToLineNumbers },
		numberOfRelocations_{ header->NumberOfRelocations },
		numberOfLineNumbers_{ header->NumberOfLineNumbers },
		characteristics_{ header->Characteristics }
	{
		this->name_ = std::string(header->Name, sizeof(header->Name)).c_str();
		this->virtual_address_ = header->VirtualAddress;
		this->size_ = data.size();
		this->offset_ = header->PointerToRawData;
		this->content_ = data;
	}

	/********* GETTERS ***********/
	pe_section	section_header_t::section_header(void) const
	{
		/*
		*	This part corresponds to the first part of this function:
			Builder& Builder::operator<<(const Section& section) {

			  pe_section header;
			  std::fill(
				  reinterpret_cast<uint8_t*>(&header),
				  reinterpret_cast<uint8_t*>(&header) + sizeof(pe_section),
				  0);

			  header.VirtualAddress       = static_cast<uint32_t>(section.virtual_address());
			  header.VirtualSize          = static_cast<uint32_t>(section.virtual_size());
			  header.SizeOfRawData        = static_cast<uint32_t>(section.size());
			  header.PointerToRawData     = static_cast<uint32_t>(section.pointerto_raw_data());
			  header.PointerToRelocations = static_cast<uint32_t>(section.pointerto_relocation());
			  header.PointerToLineNumbers = static_cast<uint32_t>(section.pointerto_line_numbers());
			  header.NumberOfRelocations  = static_cast<uint16_t>(section.numberof_relocations());
			  header.NumberOfLineNumbers  = static_cast<uint16_t>(section.numberof_line_numbers());
			  header.Characteristics      = static_cast<uint32_t>(section.characteristics());
			  const char* name            = section.name().c_str();
		*/
		pe_section section_header;

		strncpy(section_header.Name, this->name_.c_str(), 8);
		section_header.VirtualSize			= this->virtualSize_;
		section_header.VirtualAddress		= this->virtual_address_;
		section_header.SizeOfRawData		= this->size_;
		section_header.PointerToRawData		= this->offset_;
		section_header.PointerToRelocations = this->pointerToRelocations_;
		section_header.PointerToLineNumbers = this->pointerToLineNumbers_;
		section_header.NumberOfRelocations	= this->numberOfRelocations_;
		section_header.NumberOfLineNumbers	= this->numberOfLineNumbers_;
		section_header.Characteristics		= static_cast<uint32_t>(this->characteristics_);

		return section_header;
	}


	std::vector<uint8_t> section_header_t::content(void) const 
	{
		return this->content_;
	}


	std::vector<uint8_t>& section_header_t::content_ref(void) 
	{
		return this->content_;
	}


	const char* section_header_t::name(void) const
	{
		return this->name_.c_str();
	}


	uint32_t	section_header_t::virtual_size(void) const
	{
		return this->virtualSize_;
	}


	uint32_t	section_header_t::virtual_address(void) const
	{
		return this->virtual_address_;
	}


	uint32_t	section_header_t::sizeof_raw_data(void) const
	{
		return this->size_;
	}


	uint32_t	section_header_t::pointerto_raw_data(void) const
	{
		return this->offset_;
	}


	uint32_t	section_header_t::pointerto_relocation(void) const
	{
		return this->pointerToRelocations_;
	}


	uint32_t	section_header_t::pointerto_line_numbers(void) const
	{
		return this->pointerToLineNumbers_;
	}


	uint16_t	section_header_t::numberof_relocations(void) const
	{
		return this->numberOfRelocations_;
	}


	uint16_t	section_header_t::numberof_line_numbers(void) const
	{
		return this->numberOfLineNumbers_;
	}


	uint32_t	section_header_t::characteristics(void) const
	{
		return this->characteristics_;
	}


	/************ SETTERS *************/
	void section_header_t::content(const std::vector<uint8_t>& data)
	{
		this->content_ = data;
	}

	void section_header_t::name(const std::string& name) 
	{
		if (name.size() > NameSize) {
			return;
		}
		this->name_ = name;
	}

	void section_header_t::virtual_address(uint32_t virtualAddress)
	{
		this->virtual_address_ = virtualAddress;
	}

	void section_header_t::virtual_size(uint32_t virtualSize) 
	{
		this->virtualSize_ = virtualSize;
	}


	void section_header_t::pointerto_raw_data(uint32_t pointerToRawData) 
	{
		this->offset_ = pointerToRawData;
	}


	void section_header_t::pointerto_relocation(uint32_t pointerToRelocation) 
	{
		this->pointerToRelocations_ = pointerToRelocation;
	}


	void section_header_t::pointerto_line_numbers(uint32_t pointerToLineNumbers) 
	{
		this->pointerToLineNumbers_ = pointerToLineNumbers;
	}


	void section_header_t::numberof_relocations(uint16_t numberOfRelocations) 
	{
		this->numberOfRelocations_ = numberOfRelocations;
	}


	void section_header_t::numberof_line_numbers(uint16_t numberOfLineNumbers) 
	{
		this->numberOfLineNumbers_ = numberOfLineNumbers;
	}


	void section_header_t::sizeof_raw_data(uint32_t sizeOfRawData) 
	{
		this->size_ = sizeOfRawData;
	}


	void section_header_t::characteristics(uint32_t characteristics) 
	{
		this->characteristics_ = characteristics;
	}


	void section_header_t::remove_characteristic(SECTION_CHARACTERISTICS characteristic) 
	{
		this->characteristics_ &= ~static_cast<uint32_t>(characteristic);
	}


	void section_header_t::add_characteristic(SECTION_CHARACTERISTICS characteristic) 
	{
		this->characteristics_ |= static_cast<uint32_t>(characteristic);
	}


	bool section_header_t::has_characteristic(SECTION_CHARACTERISTICS c) const 
	{
		return (this->characteristics_ & static_cast<uint32_t>(c)) > 0;
	}


	bool section_header_t::dump_sections(FILE *output_file)
	{
		fprintf(output_file, "\t+Name: %s\n", name_.c_str());
		fprintf(output_file, "\t+Virtual Size: 0x%x\n", this->virtualSize_);
		fprintf(output_file, "\t+Virtual Address: 0x%x\n", this->virtual_address_);
		fprintf(output_file, "\t+Pointer to Raw Data: 0x%x\n", this->offset_);
		fprintf(output_file, "\t+Size of Raw Data: 0x%x\n", this->size_);
		fprintf(output_file, "\t+Pointer to relocations: 0x%x\n", this->pointerToRelocations_);
		fprintf(output_file, "\t+Pointer to line numbers: 0x%x\n", this->pointerToLineNumbers_);
		fprintf(output_file, "\t+Number of relocations: 0x%x\n", this->numberOfRelocations_);
		fprintf(output_file, "\t+Number of line numbers: 0x%x\n", this->numberOfLineNumbers_);
		fprintf(output_file, "\t+Characteristics: 0x%x\n", this->characteristics_);

		return true;
	}

}