#pragma once

#ifndef DOS_HEADER_H
#define DOS_HEADER_H

#include "common.h"
#include "utils.h"
#include "structures_and_enums.h"

namespace pe_parser
{
	
	class dos_header_t
	{
	public:


		dos_header_t(const pe_dos_header* dos_header_address);
		~dos_header_t() = default;

		// getters
		pe_dos_header dos_header(void) const;
		uint16_t    magic(void) const;
		uint16_t    used_bytes_in_the_last_page(void) const;
		uint16_t    file_size_in_pages(void) const;
		uint16_t    numberof_relocation(void) const;
		uint16_t    header_size_in_paragraphs(void) const;
		uint16_t    minimum_extra_paragraphs(void) const;
		uint16_t    maximum_extra_paragraphs(void) const;
		uint16_t    initial_relative_ss(void) const;
		uint16_t    initial_sp(void) const;
		uint16_t    checksum(void) const;
		uint16_t    initial_ip(void) const;
		uint16_t    initial_relative_cs(void) const;
		uint16_t    addressof_relocation_table(void) const;
		uint16_t    overlay_number(void) const;
		uint16_t	reserved(size_t field) const;
		uint16_t    oem_id(void) const;
		uint16_t    oem_info(void) const;
		uint16_t	reserved2(size_t field) const;
		uint32_t	addressof_new_exeheader(void) const;
		// setters
		void magic(uint16_t magic);
		void used_bytes_in_the_last_page(uint16_t usedBytesInTheLastPage);
		void file_size_in_pages(uint16_t fileSizeInPages);
		void numberof_relocation(uint16_t numberOfRelocation);
		void header_size_in_paragraphs(uint16_t headerSizeInParagraphs);
		void minimum_extra_paragraphs(uint16_t minimumExtraParagraphs);
		void maximum_extra_paragraphs(uint16_t maximumExtraParagraphs);
		void initial_relative_ss(uint16_t initialRelativeSS);
		void initial_sp(uint16_t initialSP);
		void checksum(uint16_t checksum);
		void initial_ip(uint16_t initialIP);
		void initial_relative_cs(uint16_t initialRelativeCS);
		void addressof_relocation_table(uint16_t addressOfRelocationTable);
		void overlay_number(uint16_t overlayNumber);
		void reserved(const uint16_t* reserved);
		void oem_id(uint16_t oEMid);
		void oem_info(uint16_t oEMinfo);
		void reserved2(const uint16_t* reserved2);
		void addressof_new_exeheader(uint32_t addressOfNewExeHeader);


		bool check_dos_header();
		bool dump_dos_header(FILE *file_to_dump);
	private:
		uint16_t    magic_;
		uint16_t    usedBytesInTheLastPage_;
		uint16_t    fileSizeInPages_;
		uint16_t    numberOfRelocation_;
		uint16_t    headerSizeInParagraphs_;
		uint16_t    minimumExtraParagraphs_;
		uint16_t    maximumExtraParagraphs_;
		uint16_t    initialRelativeSS_;
		uint16_t    initialSP_;
		uint16_t    checksum_;
		uint16_t    initialIP_;
		uint16_t    initialRelativeCS_;
		uint16_t    addressOfRelocationTable_;
		uint16_t    overlayNumber_;
		uint16_t	reserved_[4];
		uint16_t    oEMid_;
		uint16_t    oEMinfo_;
		uint16_t	reserved2_[10];
		uint32_t	addressOfNewExeHeader_;

		bool dos_header_correct;
	};
}

#endif // !DOS_HEADER_H