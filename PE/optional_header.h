#pragma once

#ifndef OPTIONAL_HEADER_H
#define OPTIONAL_HEADER_H

#include "common.h"
#include "structures_and_enums.h"

namespace pe_parser
{
	class optional_header_t
	{
	public:

		optional_header_t(const pe32_optional_header *header);
		optional_header_t(const pe64_optional_header *header);
		~optional_header_t() = default;

		// getters
		pe32_optional_header optional_header_pe32();
		pe64_optional_header optional_header_pe64();
		PE_TYPE   magic(void) const;
		uint8_t   major_linker_version(void) const;
		uint8_t   minor_linker_version(void) const;
		uint32_t  sizeof_code(void) const;
		uint32_t  sizeof_initialized_data(void) const;
		uint32_t  sizeof_uninitialized_data(void) const;
		uint32_t  addressof_entrypoint(void) const;
		uint32_t  baseof_code(void) const;
		uint32_t  baseof_data(void) const;
		uint64_t  imagebase(void) const;
		uint32_t  section_alignment(void) const;
		uint32_t  file_alignment(void) const;
		uint16_t  major_operating_system_version(void) const;
		uint16_t  minor_operating_system_version(void) const;
		uint16_t  major_image_version(void) const;
		uint16_t  minor_image_version(void) const;
		uint16_t  major_subsystem_version(void) const;
		uint16_t  minor_subsystem_version(void) const;
		uint32_t  win32_version_value(void) const;
		uint32_t  sizeof_image(void) const;
		uint32_t  sizeof_headers(void) const;
		uint32_t  checksum(void) const;
		SUBSYSTEM subsystem(void) const;
		DLL_CHARACTERISTICS  dll_characteristics(void) const;
		uint64_t  sizeof_stack_reserve(void) const;
		uint64_t  sizeof_stack_commit(void) const;
		uint64_t  sizeof_heap_reserve(void) const;
		uint64_t  sizeof_heap_commit(void) const;
		uint32_t  loader_flags(void) const;
		uint32_t  numberof_rva_and_size(void) const;
		bool	  has(DLL_CHARACTERISTICS c) const;
		// setters
		void add(DLL_CHARACTERISTICS c);
		void remove(DLL_CHARACTERISTICS c);

		void magic(PE_TYPE magic);
		void major_linker_version(uint8_t majorLinkerVersion);
		void minor_linker_version(uint8_t minorLinkerVersion);
		void sizeof_code(uint32_t sizeOfCode);
		void sizeof_initialized_data(uint32_t sizeOfInitializedData);
		void sizeof_uninitialized_data(uint32_t sizeOfUninitializedData);
		void addressof_entrypoint(uint32_t addressOfEntryPoint);
		void baseof_code(uint32_t baseOfCode);
		void baseof_data(uint32_t baseOfData);
		void imagebase(uint64_t imageBase);
		void section_alignment(uint32_t sectionAlignment);
		void file_alignment(uint32_t fileAlignment);
		void major_operating_system_version(uint16_t majorOperatingSystemVersion);
		void minor_operating_system_version(uint16_t minorOperatingSystemVersion);
		void major_image_version(uint16_t majorImageVersion);
		void minor_image_version(uint16_t minorImageVersion);
		void major_subsystem_version(uint16_t majorSubsystemVersion);
		void minor_subsystem_version(uint16_t minorSubsystemVersion);
		void win32_version_value(uint32_t win32VersionValue);
		void sizeof_image(uint32_t sizeOfImage);
		void sizeof_headers(uint32_t sizeOfHeaders);
		void checksum(uint32_t checkSum);
		void subsystem(SUBSYSTEM subsystem);
		void dll_characteristics(DLL_CHARACTERISTICS DLLCharacteristics);
		void sizeof_stack_reserve(uint64_t sizeOfStackReserve);
		void sizeof_stack_commit(uint64_t sizeOfStackCommit);
		void sizeof_heap_reserve(uint64_t sizeOfHeapReserve);
		void sizeof_heap_commit(uint64_t sizeOfHeapCommit);
		void loader_flags(uint32_t loaderFlags);
		void numberof_rva_and_size(uint32_t numberOfRvaAndSize);

		bool is_64_bit_binary();
		bool dump_optional_image(FILE *output_file);
		size_t get_optional_header_size();
	private:

		PE_TYPE   magic_;
		uint8_t   majorLinkerVersion_;
		uint8_t   minorLinkerVersion_;
		uint32_t  sizeOfCode_;
		uint32_t  sizeOfInitializedData_;
		uint32_t  sizeOfUninitializedData_;
		uint32_t  addressOfEntryPoint_; // RVA
		uint32_t  baseOfCode_;          // RVA
		uint32_t  baseOfData_;          //Not present in PE32+
		uint64_t  imageBase_;
		uint32_t  sectionAlignment_;
		uint32_t  fileAlignment_;
		uint16_t  majorOperatingSystemVersion_;
		uint16_t  minorOperatingSystemVersion_;
		uint16_t  majorImageVersion_;
		uint16_t  minorImageVersion_;
		uint16_t  majorSubsystemVersion_;
		uint16_t  minorSubsystemVersion_;
		uint32_t  win32VersionValue_;
		uint32_t  sizeOfImage_;
		uint32_t  sizeOfHeaders_;
		uint32_t  checkSum_;
		SUBSYSTEM subsystem_;
		DLL_CHARACTERISTICS  DLLCharacteristics_;
		uint64_t  sizeOfStackReserve_;
		uint64_t  sizeOfStackCommit_;
		uint64_t  sizeOfHeapReserve_;
		uint64_t  sizeOfHeapCommit_;
		uint32_t  loaderFlags_;
		uint32_t numberOfRvaAndSize_;


		bool optional_header_correct;
		bool is_64_bit;
	};
}

#endif // !OPTIONAL_HEADER_H
