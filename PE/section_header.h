#pragma once

#ifndef SECTION_HEADER_H
#define SECTION_HEADER_H

#include "common.h"
#include "structures_and_enums.h"

namespace pe_parser
{
	class section_header_t
	{
	public:
		
		section_header_t(const pe_section* header);
		section_header_t(const std::vector<uint8_t>& data, const pe_section* header);
		~section_header_t() = default;

		// getters
		pe_section	section_header(void) const;
		std::vector<uint8_t>  content(void) const;
		std::vector<uint8_t>& content_ref(void);
		const char* name(void) const;
		uint32_t	virtual_size(void) const;
		uint32_t	virtual_address(void) const;
		uint32_t	sizeof_raw_data(void) const;
		uint32_t	pointerto_raw_data(void) const;
		uint32_t	pointerto_relocation(void) const;
		uint32_t	pointerto_line_numbers(void) const;
		uint16_t	numberof_relocations(void) const;
		uint16_t	numberof_line_numbers(void) const;
		uint32_t	characteristics(void) const;
		// setters
		void content(const std::vector<uint8_t>& data);
		void name(const std::string& name);
		void virtual_address(uint32_t virtualAddress);
		void virtual_size(uint32_t virtualSize);
		void pointerto_raw_data(uint32_t pointerToRawData);
		void pointerto_relocation(uint32_t pointerToRelocation);
		void pointerto_line_numbers(uint32_t pointerToLineNumbers);
		void numberof_relocations(uint16_t numberOfRelocations);
		void numberof_line_numbers(uint16_t numberOfLineNumbers);
		void sizeof_raw_data(uint32_t sizeOfRawData);
		void characteristics(uint32_t characteristics);

		bool has_characteristic(SECTION_CHARACTERISTICS c) const;
		void add_characteristic(SECTION_CHARACTERISTICS characteristic);
		void remove_characteristic(SECTION_CHARACTERISTICS characteristic);

		bool dump_sections(FILE *output_file);

	private:
		std::string				name_;
		uint32_t				virtualSize_;
		uint32_t				virtual_address_;
		uint32_t				size_;
		uint32_t				offset_;
		uint32_t                pointerToRelocations_;
		uint32_t                pointerToLineNumbers_;
		uint16_t                numberOfRelocations_;
		uint16_t                numberOfLineNumbers_;
		uint32_t				characteristics_;

		std::vector<uint8_t>	content_;
	};
}

#endif // !SECTION_HEADER_H
