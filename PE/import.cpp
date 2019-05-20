#include "import.h"

lief_import_t::~lief_import_t(void) = default;


lief_import_t::lief_import_t(const lief_import_t& other) :
	entries_{ other.entries_ },
	directory_{ nullptr },
	iat_directory_{ nullptr },
	import_lookup_table_RVA_{ other.import_lookup_table_RVA_ },
	timedatestamp_{ other.timedatestamp_ },
	forwarder_chain_{ other.forwarder_chain_ },
	name_RVA_{ other.name_RVA_ },
	import_address_table_RVA_{ other.import_address_table_RVA_ },
	name_{ other.name_ },
	type_{ other.type_ }
{}

lief_import_t& lief_import_t::operator=(lief_import_t other)
{
	this->swap(other);
	return *this;
}

void lief_import_t::swap(lief_import_t& other)
{
	std::swap(this->entries_, other.entries_);
	std::swap(this->directory_, other.directory_);
	std::swap(this->iat_directory_, other.iat_directory_);
	std::swap(this->import_lookup_table_RVA_, other.import_lookup_table_RVA_);
	std::swap(this->timedatestamp_, other.timedatestamp_);
	std::swap(this->forwarder_chain_, other.forwarder_chain_);
	std::swap(this->name_RVA_, other.name_RVA_);
	std::swap(this->import_address_table_RVA_, other.import_address_table_RVA_);
	std::swap(this->name_, other.name_);
	std::swap(this->type_, other.type_);
}


lief_import_t::lief_import_t(void) :
	entries_{},
	directory_{ nullptr },
	iat_directory_{ nullptr },
	import_lookup_table_RVA_{ 0 },
	timedatestamp_{ 0 },
	forwarder_chain_{ 0 },
	name_RVA_{ 0 },
	import_address_table_RVA_{ 0 },
	name_{ "" },
	type_{ PE_TYPE::pe32_k } // Arbitrary value
{}


lief_import_t::lief_import_t(const pe_import *import) :
	entries_{},
	directory_{ nullptr },
	iat_directory_{ nullptr },
	import_lookup_table_RVA_(import->ImportLookupTableRVA),
	timedatestamp_(import->TimeDateStamp),
	forwarder_chain_(import->ForwarderChain),
	name_RVA_(import->NameRVA),
	import_address_table_RVA_(import->ImportAddressTableRVA),
	name_{ "" },
	type_{ PE_TYPE::pe32_k } // Arbitrary value
{}

lief_import_t::lief_import_t(const std::string& name) :
	entries_{},
	directory_{ nullptr },
	iat_directory_{ nullptr },
	import_lookup_table_RVA_{ 0 },
	timedatestamp_{ 0 },
	forwarder_chain_{ 0 },
	name_RVA_{ 0 },
	name_{ name },
	type_{ PE_TYPE::pe32_k } // Arbitrary value
{}

const import_entry_t* lief_import_t::get_entry(const std::string& name) const
{
	for (size_t i = 0; i < this->entries_.size(); i++)
	{
		if (this->entries_.at(i).name() == name)
		{
			return &entries_.at(i);
		}
	}

	ANBU::LOGGER_ERROR("Unable to find entry '%s'\n", name.c_str());
	return nullptr;
}


import_entry_t* lief_import_t::get_entry(const std::string& name)
{
	return const_cast<import_entry_t*>(static_cast<const lief_import_t*>(this)->get_entry(name));
}


std::vector<import_entry_t> lief_import_t::entries(void)
{
	return this->entries_;
}


void lief_import_t::entries(std::vector<import_entry_t> entries)
{
	this->entries_ = entries;
}


uint32_t lief_import_t::import_address_table_rva(void) const
{
	return this->import_address_table_RVA_;
}


uint32_t lief_import_t::import_lookup_table_rva(void) const
{
	return this->import_lookup_table_RVA_;
}


uint32_t lief_import_t::get_function_rva_from_iat(const std::string& function) const
{
	int64_t idx = -1;

	for (size_t i = 0; this->entries_.size(); i++)
	{
		if (this->entries_.at(i).name() == function)
		{
			idx = static_cast<int64_t>(i);
			break;
		}
	}

	if (idx == -1)
	{
		ANBU::LOGGER_ERROR("Function not found\n");
		return -1;
	}

	if (this->type_ == PE_TYPE::pe32_k)
		return static_cast<uint32_t>(idx * sizeof(uint32_t));
	else
		return static_cast<uint32_t>(idx * sizeof(uint64_t));
}


const std::string& lief_import_t::name(void) const
{
	return this->name_;
}


void lief_import_t::name(const std::string& name)
{
	this->name_ = name;
}


const pe_parser::data_directory_header_t* lief_import_t::directory(void) const
{
	if (this->directory_ != nullptr)
		return this->directory_;
	else
		return nullptr;
}


pe_parser::data_directory_header_t* lief_import_t::directory(void)
{
	return const_cast<pe_parser::data_directory_header_t*>(static_cast<const lief_import_t*>(this)->directory());
}


const pe_parser::data_directory_header_t* lief_import_t::iat_directory(void) const
{
	if (this->iat_directory_ != nullptr)
		return this->iat_directory_;
	else
		return nullptr;
}


pe_parser::data_directory_header_t* lief_import_t::iat_directory(void)
{
	return const_cast<pe_parser::data_directory_header_t*>(static_cast<const lief_import_t*>(this)->iat_directory());
}


void lief_import_t::import_lookup_table_rva(uint32_t rva)
{
	this->import_lookup_table_RVA_ = rva;
}


void lief_import_t::import_address_table_rva(uint32_t rva)
{
	this->import_address_table_RVA_ = rva;
}


import_entry_t& lief_import_t::add_entry(const import_entry_t& entry)
{
	this->entries_.push_back(entry);
	return this->entries_.back();
}


import_entry_t& lief_import_t::add_entry(const std::string& name) {
	this->entries_.push_back(import_entry_t(name));
	return this->entries_.back();
}


uint32_t lief_import_t::forwarder_chain(void) const
{
	return this->forwarder_chain_;
}


uint32_t lief_import_t::timedatestamp(void) const
{
	return this->timedatestamp_;
}


bool lief_import_t::dump_import(FILE *output_file)
{
	ANBU::LOGGER(output_file, "%s\n", this->name_.c_str());
	ANBU::LOGGER(output_file, "%s\n", this->import_lookup_table_RVA_);
	ANBU::LOGGER(output_file, "%x\n", this->import_address_table_RVA_);
	ANBU::LOGGER(output_file, "%x\n", this->forwarder_chain_);
	ANBU::LOGGER(output_file, "%x\n", this->timedatestamp_);

	for (size_t i = 0; i < this->entries_.size(); i++)
		this->entries_.at(i).dump_import_entry(output_file);

	return true;
}