#pragma once

#ifndef MEMORY_DUMPER_H
#define MEMORY_DUMPER_H

#include "common.h"
#include "structures_and_enums.h"

#include "binary.h"
#include "generic_instrumentation.h"

class builder_t
/***
*	Class to parse and dump a PE file from memory to
*	disk. Some of things I had to include comparing
*	with other dumpers is the use of the function
*	PE_SafeCopy to get the data.
*/
{
public:
	builder_t(ADDRINT jump_target, binary_t* binary);
	builder_t(std::vector<uint8_t> file_base_in_vector, binary_t* binary);
	~builder_t();
	
	bool dump_pe_to_file(const std::string& file_name);
	bool dump_runpe_to_file(const std::string& file_name, std::vector<write_memory_t> file_data, ADDRINT base_address);

	//! @brief Construct a ``jmp [address] @ from``.
	//!
	//! It is used when patching import table
	std::vector<uint8_t> build_jmp(uint64_t from, uint64_t address);

	//! @brief Rebuild Import Table
	void build_import_table(void);
private:
	/**** Private dump functions ****/
	bool		dump_headers();
	bool		dump_sections();
	void		clean_list();

	binary_t*				binary_;
	FILE*					dumped_file;
	ADDRINT					address_code_to_dump;
	ADDRINT					base_address_to_dump;
	ADDRINT					base_address_name;
	IMG						img_to_dump;
	uint8_t*				dos_stub;
	bool					dump_correct;
	bool					mem_dumper_correct;
	std::vector<uint8_t>	data_from_vector;
};

#endif // !MEMORY_DUMPER_H
