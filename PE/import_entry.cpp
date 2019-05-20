#include "import_entry.h"

import_entry_t::import_entry_t(const import_entry_t&) = default;


import_entry_t::~import_entry_t(void) = default;


import_entry_t::import_entry_t(void) :
	data_{ 0 },
	name_{ "" },
	hint_{ 0 },
	iat_value_{ 0 },
	rva_{ 0 },
	type_{PE_TYPE::pe32_k}
{}


import_entry_t::import_entry_t(uint64_t data, const std::string& name) :
	data_{ data },
	name_{ name },
	hint_{ 0 },
	iat_value_{ 0 },
	rva_{ 0 },
	type_{PE_TYPE::pe32_k}
{}

import_entry_t::import_entry_t(const std::string& name) :
	import_entry_t{ 0, name }
{}

bool import_entry_t::is_ordinal(void) const
{
	// See: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-idata-section
	const uint64_t ORDINAL_MASK = this->type_ == PE_TYPE::pe32_k ? 0x80000000 : 0x8000000000000000;
	bool ordinal_bit_is_set		= static_cast<bool>(this->data_ & ORDINAL_MASK);

	// Check that bit 31 / 63 is set
	if (!ordinal_bit_is_set)
		return false;

	// Check that bits 30-15 / 62-15 are set to 0.
	uint64_t val = (this->data_ & ~ORDINAL_MASK) >> 15;

	if (val != 0)
		return false;

	return true;
}


uint16_t import_entry_t::ordinal(void) const
{
	if (!this->is_ordinal())
		return -1;

	return static_cast<uint16_t>(this->data_ & 0xFFFF);
}


uint16_t import_entry_t::hint(void) const
{
	return this->hint_;
}


uint64_t import_entry_t::iat_value(void) const
{
	return this->iat_value_;
}


uint64_t import_entry_t::hint_name_rva(void) const
{
	return this->data();
}


const std::string& import_entry_t::name(void) const
{
	return this->name_;
}


uint64_t import_entry_t::data(void) const
{
	return this->data_;
}


uint64_t import_entry_t::iat_address(void) const
{
	return this->rva_;
}


void import_entry_t::name(const std::string& name)
{
	this->name_ = name;
}


void import_entry_t::data(uint64_t data)
{
	this->data_ = data;
}


bool import_entry_t::dump_import_entry(FILE *output_file)
{
	ANBU::LOGGER(output_file, "%s\n", this->name().c_str());
	ANBU::LOGGER(output_file, "%llu\n", this->data());
	ANBU::LOGGER(output_file, "%llu\n", this->iat_value());
	ANBU::LOGGER(output_file, "%x\n", this->hint());

	return true;
}