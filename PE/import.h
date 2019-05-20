#pragma once
#ifndef IMPORT_H
#define IMPORT_H

#include "common.h"
#include "utils.h"
#include "structures_and_enums.h"
#include "import_entry.h"
#include "data_directory_header.h"

/*
using imports_t = std::vector<Import>;
using it_imports = ref_iterator<imports_t&>;
using it_const_imports = const_ref_iterator<const imports_t&>;

using import_entries_t = std::vector<ImportEntry>;
using it_import_entries = ref_iterator<import_entries_t&>;
using it_const_import_entries = const_ref_iterator<const import_entries_t&>;
*/

class lief_import_t
{
public:
	lief_import_t(const pe_import *import);
	lief_import_t(const std::string& name);
	lief_import_t(void);
	~lief_import_t(void);

	lief_import_t(const lief_import_t& other);
	lief_import_t& operator=(lief_import_t other);
	void swap(lief_import_t& other);

	uint32_t forwarder_chain(void) const;
	uint32_t timedatestamp(void) const;

	//! @brief Return a vector of @link PE::ImportEntry Import entries @endlink
	std::vector<import_entry_t> entries(void);
	void entries(std::vector<import_entry_t>);
	//! @brief Return the relative virtual address of the import address table (`IAT`)
	//
	//! @warning
	//! This address could be change when re-building the binary
	//!
	uint32_t import_address_table_rva(void) const;

	//! @brief Return the relative virtual address of the import lookup table
	//!
	//! @warning
	//! This address could be change when re-building the binary
	//!
	uint32_t import_lookup_table_rva(void) const;

	//! @brief Return the Function's RVA from the import address table (`IAT`)
	//!
	//! @warning
	//! This address could be change when re-building the binary
	//!
	uint32_t get_function_rva_from_iat(const std::string& function) const;


	//! @brief Return the imported function with the given name
	import_entry_t*		get_entry(const std::string& name);
	const import_entry_t*	get_entry(const std::string& name) const;

	//! @brief Return the library's name
	//!
	//! e.g. `kernel32.dll`
	const std::string& name(void) const;
	void name(const std::string& name);


	//! @brief Return the @link PE::DataDirectory Data directory@endlink associated.
	//! It should be the one at index PE::DATA_DIRECTORY::IMPORT_TABLE
	//!
	pe_parser::data_directory_header_t*       directory(void);
	const pe_parser::data_directory_header_t* directory(void) const;

	//! @brief Return the @link PE::DataDirectory Data directory@endlink associated.
	//! It should be the one at index PE::DATA_DIRECTORY::IAT
	//!
	pe_parser::data_directory_header_t*			iat_directory(void);
	const pe_parser::data_directory_header_t*	iat_directory(void) const;


	//! @brief Add a function
	import_entry_t& add_entry(const import_entry_t& entry);


	//! @brief Add a function from name
	import_entry_t& add_entry(const std::string& name);

	void import_lookup_table_rva(uint32_t rva);
	void import_address_table_rva(uint32_t rva);

	bool dump_import(FILE *output_file);


private:
	std::vector<import_entry_t>				entries_;
	pe_parser::data_directory_header_t*		directory_;
	pe_parser::data_directory_header_t*		iat_directory_;
	uint32_t								import_lookup_table_RVA_;
	uint32_t								timedatestamp_;
	uint32_t								forwarder_chain_;
	uint32_t								name_RVA_;
	uint32_t								import_address_table_RVA_;
	std::string								name_;
	PE_TYPE						type_;
};


#endif // !IMPORT_H
