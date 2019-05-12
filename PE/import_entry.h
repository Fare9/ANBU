#pragma once
#ifndef IMPORTENTRY_H
#define IMPORTENTRY_H

#include "common.h"
#include "structures_and_enums.h"

class import_entry_t
{
public:
	import_entry_t(void);
	import_entry_t(uint64_t data, const std::string& name = "");
	import_entry_t(const std::string& name);
	import_entry_t(const import_entry_t&);
	~import_entry_t(void);

	//! @brief ``True`` if ordinal is used
	bool is_ordinal(void) const;

	//! @brief ordinal value
	uint16_t ordinal(void) const;

	//! @see ImportEntry::data
	uint64_t hint_name_rva(void) const;

	//! @brief Index into the Export::entries
	uint16_t hint(void) const;

	//! @brief Value of the current entry in the Import Address Table.
	//! It should match the lookup table value
	uint64_t iat_value(void) const;

	//! @brief Import name if not ordinal
	const std::string& name(void) const;

	//! @brief Raw value
	uint64_t data(void) const;

	//! @brief **Original** address of the entry in the Import Address Table
	uint64_t iat_address(void) const;



	void name(const std::string& name);
	void data(uint64_t data);

	bool dump_import_entry(FILE *output_file);

private:
	uint64_t		data_;
	std::string		name_;
	uint16_t		hint_;
	uint64_t		iat_value_;
	uint64_t		rva_;
	PE_TYPE type_;
};

#endif // !IMPORTENTRY_H
