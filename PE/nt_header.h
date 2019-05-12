#pragma once

#ifndef NT_HEADER_H
#define NT_HEADER_H

#include "common.h"
#include "structures_and_enums.h"


namespace pe_parser
{
	class nt_header_t
	{
	public:

		nt_header_t(pe_header * header);
		~nt_header_t() = default;

		// getters
		pe_header				nt_header(void) const;
		const uint32_t			signature(void) const;
		MACHINE_TYPES			machine(void) const;
		uint16_t				numberof_sections(void) const;
		uint32_t				time_date_stamp(void) const;
		uint32_t				pointerto_symbol_table(void) const;
		uint32_t				numberof_symbols(void) const;
		uint16_t				sizeof_optional_header(void) const;
		HEADER_CHARACTERISTICS	characteristics(void) const;
		// setters
		void					machine(MACHINE_TYPES type);
		void					numberof_sections(uint16_t nbOfSections);
		void					time_date_stamp(uint32_t timestamp);
		void					pointerto_symbol_table(uint32_t pointerToSymbol);
		void					numberof_symbols(uint32_t nbOfSymbols);
		void					sizeof_optional_header(uint16_t sizeOfOptionalHdr);
		void					characteristics(HEADER_CHARACTERISTICS characteristics);
		void					signature(const uint32_t sig);

		bool					has_characteristic(HEADER_CHARACTERISTICS c) const;
		bool					is_pe_header_correct();
		bool					dump_nt_header(FILE *file_to_dump);
	private:
		uint32_t				signature_;
		MACHINE_TYPES			machine_;
		uint16_t				numberOfSections_;
		uint32_t				timeDateStamp_;
		uint32_t				pointerToSymbolTable_;
		uint32_t				numberOfSymbols_;
		uint16_t				sizeOfOptionalHeader_;
		HEADER_CHARACTERISTICS	characteristics_;

		bool pe_header_correct;
	};
}

#endif // !NT_HEADER_H
