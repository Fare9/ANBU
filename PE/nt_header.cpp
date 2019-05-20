
#include "nt_header.h"

namespace pe_parser
{
	nt_header_t::nt_header_t(pe_header * header) :
		signature_(header->signature),
		machine_(static_cast<MACHINE_TYPES>(header->Machine)),
		numberOfSections_(header->NumberOfSections),
		timeDateStamp_(header->TimeDateStamp),
		pointerToSymbolTable_(header->PointerToSymbolTable),
		numberOfSymbols_(header->NumberOfSymbols),
		sizeOfOptionalHeader_(header->SizeOfOptionalHeader),
		characteristics_(static_cast<HEADER_CHARACTERISTICS>(header->Characteristics))

	{
		if (signature_ != correct_pe_signature_k)
			pe_header_correct = false;
	}
	
	bool nt_header_t::is_pe_header_correct()
	{
		return pe_header_correct;
	}

	bool nt_header_t::has_characteristic(HEADER_CHARACTERISTICS c) const {
		return (this->characteristics_ & c) != HEADER_CHARACTERISTICS::IMAGE_FILE_INVALID_k;
	}

	/******** GETTERS *********/
	pe_header nt_header_t::nt_header(void) const
	{
		/*
		*	This part corresponds to LIEF builder:
			Builder& Builder::operator<<(const Header& bHeader) {
			  VLOG(VDEBUG) << "Building standard Header" << std::endl;
			  // Standard Header
			  pe_header header;
			  header.Machine               = static_cast<uint16_t>(bHeader.machine());
			  header.NumberOfSections      = static_cast<uint16_t>(this->sections_.size());
			  //TODO: use current
			  header.TimeDateStamp         = static_cast<uint32_t>(bHeader.time_date_stamp());
			  header.PointerToSymbolTable  = static_cast<uint32_t>(bHeader.pointerto_symbol_table());
			  header.NumberOfSymbols       = static_cast<uint32_t>(bHeader.numberof_symbols());
			  //TODO: Check
			  header.SizeOfOptionalHeader  = static_cast<uint16_t>(bHeader.sizeof_optional_header());
			  header.Characteristics       = static_cast<uint16_t>(bHeader.characteristics());

			  const Header::signature_t& signature = this->header_.signature();
			  std::copy(std::begin(signature), std::end(signature), std::begin(header.signature));

			  const uint32_t address_next_header = this->dos_header().addressof_new_exeheader();

			  this->ios_.seekp(address_next_header);
			  this->ios_.write(reinterpret_cast<const uint8_t*>(&header), sizeof(pe_header));
			  return *this;
			}
		*/
		pe_header nt_header;

		nt_header.signature				= this->signature_;
		nt_header.Machine				= this->machine_;
		nt_header.NumberOfSections		= this->numberOfSections_;
		nt_header.TimeDateStamp			= this->timeDateStamp_;
		nt_header.PointerToSymbolTable	= this->pointerToSymbolTable_;
		nt_header.NumberOfSymbols		= this->numberOfSymbols_;
		nt_header.SizeOfOptionalHeader	= this->sizeOfOptionalHeader_;
		nt_header.Characteristics		= this->characteristics_;

		return nt_header;
	}


	const uint32_t nt_header_t::signature(void) const 
	{
		return this->signature_;
	}


	MACHINE_TYPES nt_header_t::machine(void) const 
	{
		return this->machine_;
	}


	uint16_t nt_header_t::numberof_sections(void) const 
	{
		return this->numberOfSections_;
	}


	uint32_t nt_header_t::time_date_stamp(void) const 
	{
		return this->timeDateStamp_;
	}


	uint32_t nt_header_t::pointerto_symbol_table(void) const 
	{
		return this->pointerToSymbolTable_;
	}


	uint32_t nt_header_t::numberof_symbols(void) const 
	{
		return this->numberOfSymbols_;
	}


	uint16_t nt_header_t::sizeof_optional_header(void) const 
	{
		return this->sizeOfOptionalHeader_;
	}


	HEADER_CHARACTERISTICS nt_header_t::characteristics(void) const 
	{
		return this->characteristics_;
	}
	/******** SETTERS *********/
	void nt_header_t::machine(MACHINE_TYPES type) 
	{
		this->machine_ = type;
	}


	void nt_header_t::numberof_sections(uint16_t nbOfSections) 
	{
		this->numberOfSections_ = nbOfSections;
	}


	void nt_header_t::time_date_stamp(uint32_t timestamp) 
	{
		this->timeDateStamp_ = timestamp;
	}


	void nt_header_t::pointerto_symbol_table(uint32_t pointerToSymbol) 
	{
		this->pointerToSymbolTable_ = pointerToSymbol;
	}


	void nt_header_t::numberof_symbols(uint32_t nbOfSymbols) 
	{
		this->numberOfSymbols_ = nbOfSymbols;
	}


	void nt_header_t::sizeof_optional_header(uint16_t sizeOfOptionalHdr) 
	{
		this->sizeOfOptionalHeader_ = sizeOfOptionalHdr;
	}


	void nt_header_t::characteristics(HEADER_CHARACTERISTICS characteristics) 
	{
		this->characteristics_ = characteristics;
	}


	void nt_header_t::signature(const uint32_t sig)
	{
		this->signature_ = sig;
	}


	bool nt_header_t::dump_nt_header(FILE *file_to_dump)
	{
		if (!pe_header_correct)
			return false;
		ANBU::LOGGER(file_to_dump, "================== DUMP NT HEADER ===================\n");
		ANBU::LOGGER(file_to_dump, "\t+Signature: 0x%x\n", signature_);
		ANBU::LOGGER(file_to_dump, "\t+Machine: 0x%x\n", machine_);
		ANBU::LOGGER(file_to_dump, "\t+Number Of Sections: 0x%x\n", numberOfSections_);
		ANBU::LOGGER(file_to_dump, "\t+TimeDateStamp: 0x%x\n", timeDateStamp_);
		ANBU::LOGGER(file_to_dump, "\t+Pointer to Symbol Table: 0x%x\n", pointerToSymbolTable_);
		ANBU::LOGGER(file_to_dump, "\t+Number of symbols: 0x%x\n", numberOfSymbols_);
		ANBU::LOGGER(file_to_dump, "\t+Size of optional header: 0x%x\n", sizeOfOptionalHeader_);
		ANBU::LOGGER(file_to_dump, "\t+Characteristics: 0x%x\n", characteristics_);

		return true;
	}
}