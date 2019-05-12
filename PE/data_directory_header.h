#pragma once

#ifndef DATA_DIRECTORY_HEADER_H
#define DATA_DIRECTORY_HEADER_H

#include "common.h"
#include "structures_and_enums.h"

namespace pe_parser
{

	class data_directory_header_t
	{
	public:

		std::map<DATA_DIRECTORY, string> directory_names;

		data_directory_header_t(const pe_data_directory *header, DATA_DIRECTORY type);
		~data_directory_header_t() = default;

		// getters
		pe_data_directory	data_directory(void) const;
		uint32_t			RVA(void) const;
		uint32_t			size(void) const;
		DATA_DIRECTORY		type(void) const;
		// setters
		void				RVA(uint32_t rva);
		void				size(uint32_t size);
		void				type(DATA_DIRECTORY type);

		bool				dump_directories(FILE *output_file);

	private:
		uint32_t rva_;
		uint32_t size_;
		DATA_DIRECTORY type_;
	};
}

#endif // !DATA_DIRECTORY_HEADER_H
