#pragma once

#ifndef PE_FILE_H
#define PE_FILE_H

#include "common.h"
#include "dos_header.h"
#include "nt_header.h"
#include "optional_header.h"
#include "data_directory_header.h"
#include "section_header.h"


#include "import.h"
#include "import_entry.h"
#include "utils.h"


class binary_t
{
public:
	binary_t(std::vector<uint8_t>* buffer);
	binary_t(ADDRINT binary_address);
	binary_t(IMG binary_img);
	~binary_t();

	//! @brief Return `PE32` or `PE32+`
	PE_TYPE type(void) const;

	bool		analyze_binary(void);
	bool		has_section_changed_entropy(ADDRINT address_of_section);
	bool		on_pe_file(ADDRINT address);

	//! @brief Convert Relative Virtual Address to offset
	//!
	//! We try to get the get section wich hold the given
	//! `RVA` and convert it to offset. If the section
	//! does not exist, we assume that `RVA` = `offset`
	uint64_t rva_to_offset(uint64_t RVA);

	//! @brief Convert Virtual address to offset
	uint64_t va_to_offset(uint64_t VA);


	//! @brief Find the section associated with the `offset`
	pe_parser::section_header_t* section_from_offset(uint64_t offset);

	//! @brief Find the section associated with the `virtual address`
	pe_parser::section_header_t* section_from_rva(uint64_t virtual_address);


	// getters
	pe_parser::dos_header_t*								dos_header(void);
	uint8_t*												dos_stub(void);
	pe_parser::nt_header_t*									nt_coff_header(void);
	pe_parser::optional_header_t*							optional_header(void);
	
	bool has(DATA_DIRECTORY index);
	uint64_t	realign_pe();

	//! @brief Compute the size of all headers
	uint32_t sizeof_headers(void) const;

	//! @brief Compute the binary's virtual size.
	//! It should match with OptionalHeader::sizeof_image
	uint64_t virtual_size(void) const;

	// ==========================
	// Methods to manage data directories
	// ==========================
	std::vector<pe_parser::data_directory_header_t>			data_directory(void);

	pe_parser::data_directory_header_t*						data_directory(DATA_DIRECTORY index);

	void													data_directory(std::vector<pe_parser::data_directory_header_t> data_directory_header);

	// ==========================
	// Methods to manage sections
	// ==========================
	std::vector<pe_parser::section_header_t>					section_table_header(void);

	void														section_table_header(std::vector<pe_parser::section_header_t> sections);
	//! @brief Return binary's section from its name
	//!
	//! @param[in] name Name of the Section
	pe_parser::section_header_t*								get_section( std::string& name) ;

	//! @brief Return the section associated with import table
	pe_parser::section_header_t*								import_section(void) ;

	//! @brief Delete the section with the given name
    //!
	//! @param[in] name Name of section to delete
	void														remove_section(std::string& name);

	//! Remove the given section
	void														remove(pe_parser::section_header_t* section);

	//! @brief Add a section to the binary and return the section added.
	pe_parser::section_header_t*								add_section(pe_parser::section_header_t* section);

	//! @brief Make space between the last section header and the beginning of the
	//! content of first section
	void														make_space_for_new_section(void);


	// =========================
	// Methods to manage Imports
	// =========================
	bool has_imports(void) const;

	//! @brief return binary's @link PE::Import imports @endlink
	std::vector<lief_import_t>       imports(void);
	void imports(std::vector<lief_import_t> imports);

	//! @brief Returns the PE::Import from the given name
	//!
	//! @param[in] import_name Name of the import
	lief_import_t*          get_import(const std::string& import_name);
	const lief_import_t*    get_import(const std::string& import_name) const;

	//! @brief ``True`` if the binary import the given library name
	//!
	//! @param[in] import_name Name of the import
	bool has_import(const std::string& import_name) const;

	//! @brief Add the function @p function of the library @p library
	//!
	//! @param[in] library library name of the function
	//! @param[in] function function's name from the library to import
	import_entry_t* add_import_function(const std::string& library, const std::string& function);

	//! @brief add an imported library (i.e. `DLL`) to the binary
	lief_import_t* add_library(const std::string& name);

	//! @brief Remove the library with the given `name`
	void remove_library(const std::string& name);

	//! @brief Remove all libraries in the binary
	void remove_all_libraries(void);

	//! @brief Try to predict the RVA of the function `function` in the import library `library`
	//!
	//! @warning
	//! The value could be chang if imports change
	//!
	//! @note
	//! It should be used with:
	//! LIEF::PE::Builder::build_imports set to ``true``
	//!
	//! @param[in] library  Library name in which the function is located
	//! @param[in] function Function name
	//! @return The address of the function (``IAT``)  in the new import table
	uint32_t predict_function_rva(const std::string& library, const std::string& function);


	//! @brief Reconstruct the binary object and write it in  `filename`
	//!
	//! Rebuild a PE binary from the current Binary object.
	//! When rebuilding, import table and relocations are not rebuilt.
	bool write(const std::string& filename, ADDRINT target);

	bool write(const std::string& filename, std::vector<uint8_t> file_base_in_vector, std::vector<write_memory_t> file_data);
private:
	float		calculate_entropy_section(pe_parser::section_header_t section);
	bool		calculate_initial_entropy(void);
	bool		parse(void);
	bool		parse_headers(void);
	bool		parse_dos_stub(void);
	bool		parse_data_directories(void);
	bool		parse_sections(void);
	bool		entropy_higher_than_HE(uint32_t entropy);
	bool		entropy_lower_than_LE(uint32_t entropy);

	const float							entropy_threshold = 10.0;

	PE_TYPE								type_;
	ADDRINT								binary_base_address;
	IMG									binary_img;
	bool								binary_is_okay;
	bool								headers_are_correct;
	bool								has_imports_;
	int32_t								available_sections_space_;

	
	float*								initial_entropies			= nullptr;




	pe_parser::dos_header_t*							dos_header_					= nullptr;
	uint8_t*											dos_stub_					= nullptr;
	pe_parser::nt_header_t*								nt_coff_header_				= nullptr;
	pe_parser::optional_header_t*						optional_header_			= nullptr;
	std::vector<pe_parser::data_directory_header_t>		data_directory_header_;
	std::vector<pe_parser::section_header_t>			section_table_header_;
	std::vector<lief_import_t>							imports_;
};


#endif // !PE_FILE_H
