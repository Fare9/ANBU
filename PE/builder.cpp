
#include "builder.h"


/************* EXTERN VARIABLES *************/
extern FILE*		logfile;
extern std::string	unpacked_file_name;
extern std::string	import_section_name;

builder_t::builder_t(ADDRINT jump_target, binary_t* binary) : 
														binary_ { binary },
														dos_stub { nullptr },
														dump_correct { false }
/***
*	Constructor for unpacker when file has been dumped
*	from the same memory and then there's an indirect
*	jump to the unpacked code.
*/
{
	mem_dumper_correct = true;
	this->address_code_to_dump = jump_target;
	img_to_dump = IMG_FindByAddress(jump_target);

	if (img_to_dump == IMG_Invalid())
	{
		mem_dumper_correct = false;
		return;
	}

	base_address_to_dump = IMG_StartAddress(img_to_dump);

	if (base_address_to_dump == NULL)
	{
		mem_dumper_correct = false;
		return;
	}

	this->address_code_to_dump -= base_address_to_dump;

	ANBU::LOGGER_INFO(logfile, "Address of code to dump: 0x%x\n", (uintptr_t)jump_target);
	ANBU::LOGGER_INFO(logfile, "Base address of that image: 0x%x\n", (uintptr_t)base_address_to_dump);
}

builder_t::builder_t(std::vector<uint8_t> file_base_in_vector, binary_t* binary) : 
																			 binary_{ binary },
																			 dos_stub(nullptr),
																			 dump_correct(false),
																			 mem_dumper_correct(true)
/***
*	Constructor for the unpacker when unpacks a RunPE
*	we have the file in vectors of bytes, as it will 
*	be better that than not reading the code from the
*	other process.
*/
{
	this->data_from_vector = file_base_in_vector;
	this->address_code_to_dump = 0;
	base_address_to_dump = (ADDRINT) this->data_from_vector.begin();

	ANBU::LOGGER_INFO(logfile, "Base address of that image: 0x%x\n", (uintptr_t)base_address_to_dump);
}


builder_t::~builder_t()
{
	if (dumped_file != NULL)
		fclose(dumped_file);

	if (dos_stub != nullptr)
		free(dos_stub);

	if (data_from_vector.size() != 0)
		data_from_vector.empty();
}


bool builder_t::dump_pe_to_file(const std::string& file_name)
/***
*	Function to dump the file when it has been
*	unpacked in the same memory. 
*/
{
	if (!mem_dumper_correct)
		return false;

	dumped_file = fopen(file_name.c_str(), "wb");

	if (!dumped_file)
		return false;

	this->binary_->realign_pe();
	ANBU::LOGGER_INFO(logfile, "PE realigned\n");

	// set the new entry point, as the one from the header
	// will be packer's entry point.
	binary_->optional_header()->addressof_entrypoint(static_cast<uint32_t>(address_code_to_dump));

	// first write the headers to the file
	if (!dump_headers())
		return false;
	// finally write section by section
	if (!dump_sections())
		return false;

	// build the import table
	this->build_import_table();

	fseek(dumped_file,
		this->binary_->section_table_header().back().pointerto_raw_data(),
		SEEK_SET);

	size_t written_bytes = fwrite(
		this->binary_->section_table_header().back().content().begin(),
		this->binary_->section_table_header().back().sizeof_raw_data(), 
		1, 
		dumped_file);

	ANBU::LOGGER_INFO(logfile, "Written new import table into the raw pointer: 0x%x; virtual address: 0x%x\n",
		binary_->section_table_header().at(binary_->section_table_header().size() - 1).pointerto_raw_data(),
		binary_->section_table_header().at(binary_->section_table_header().size() - 1).virtual_address());

	if (!written_bytes)
		return false;

	// write again the headers
	ANBU::LOGGER_INFO(logfile, "Writing headers, now with the import section\n");
	if (!dump_headers())
		return false;

	return true;
}


bool builder_t::dump_runpe_to_file(const std::string& file_name, std::vector<write_memory_t> file_data, ADDRINT base_address)
/***
*	Dumper for the RunPE, it will use vector with 
*	the possible sections, also we give a base
*	address to create the name of the file.
*/
{
	ADDRINT image_base;
	size_t written_bytes;
	std::vector<pe_parser::section_header_t> sections;
	size_t index_section = -1;
	size_t size_to_copy;

	if (!mem_dumper_correct)
		return false;

	dumped_file = fopen(file_name.c_str(),"wb");

	if (!dumped_file)
		return false;

	// get the image base for later
	image_base = static_cast<ADDRINT>(this->binary_->optional_header()->imagebase());

	// write headers to file (as we have the header on structs).
	if (!dump_headers())
		return false;
	// get the structure of sections
	sections = this->binary_->section_table_header();
	
	for (size_t j = 0; j < sections.size(); j++)
	{
		index_section = -1;

		ANBU::LOGGER_INFO(logfile, "Trying to dump the section with RVA 0x%x and raw size 0x%x\n",
			sections.at(j).virtual_address(), sections.at(j).sizeof_raw_data());

		for (size_t i = 0; i < file_data.size(); i++)
		{
			// search inside of the vectors for the virtual address
			// of each section.
			if (sections.at(j).virtual_address() == (file_data.at(i).address - image_base))
			{
				index_section = i;
				break;
			}
		}
		// if the vector does not contain the section
		// it is an error, is not possible to dump.
		if (index_section == -1)
			return false;

		if (fseek(dumped_file, sections.at(j).pointerto_raw_data(), SEEK_SET))
			return false;

		size_to_copy = MIN(sections.at(j).sizeof_raw_data(), file_data.at(index_section).data.size());
		written_bytes = fwrite(file_data.at(index_section).data.begin(), size_to_copy, 1, dumped_file);

		if (!written_bytes)
			return false;
	}
	
	return true;
}


std::vector<uint8_t> builder_t::build_jmp(uint64_t from, uint64_t address)
{
	std::vector<uint8_t> instruction;

	// call $+5
	instruction.push_back(0xe8);
	instruction.push_back(0x00);
	instruction.push_back(0x00);
	instruction.push_back(0x00);
	instruction.push_back(0x00);

	// pop eax/pop rax
	instruction.push_back(0x58); // eax/rax holds the current PC

	// add rax/eax (signed)
	if (this->binary_->type() == PE_TYPE::pe64_k)
	{
		instruction.push_back(0x48); //x64
	}
	instruction.push_back(0x05);

	uint64_t diff = address - (from + 5);

	for (size_t i = 0; i < sizeof(uint32_t); ++i) 
	{
		instruction.push_back(static_cast<uint8_t>((diff >> (8 * i)) & 0xFF));
	}

	// jmp [rax/eax]
	instruction.push_back(0xff);
	instruction.push_back(0x20);

	return instruction;
}


void builder_t::build_import_table(void)
{

	this->clean_list();
	// Compute size of the the diffrent (sub)sections
	// inside the future import section
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// Size of pe_import + 1 for the null entry
	uint32_t import_table_size = static_cast<uint32_t>((this->binary_->imports().size() + 1) * sizeof(pe_import)); // +1 for the null entry

	// Size of import entries
	uint32_t entries_size = 0;

	// Size of the section which will holds imported function names
	uint32_t functions_name_size = 0;

	// Size of the section which will holds library name (e.g. kernel32.dll)
	uint32_t libraries_name_size = 0;

	// Compute size of each imports's sections
	for (size_t i = 0; i < this->binary_->imports().size(); i++)
	{
		for (size_t j = 0; j < this->binary_->imports().at(i).entries().size(); j++)
		{
			// size for the functions name plus hint and the last zero
			functions_name_size += 2 + this->binary_->imports().at(i).entries().at(j).name().size() + 1; // [Hint] [FunctionName\0]
		}
		// size for libraries name with the last zero
		libraries_name_size		+= this->binary_->imports().at(i).name().size() + 1; // [DllName\0]
		// size for entries (rva to names or ordinal + 1 with zeroes)
		entries_size			+= (this->binary_->imports().at(i).entries().size() + 1) * sizeof(uintptr_t);
	}

	// Offset of the diffrents sections inside *import section*
	// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// Offset to the import table (i.e list of pe_import)
	uint32_t import_table_offset = 0;

	// Offset to the lookup table: After import table
	uint32_t lookuptable_offset = import_table_offset + import_table_size;

	// Address table (IAT). Identical to the lookup table until the library is bound
	//uint32_t iat_offset = lookuptable_offset + entries_size / 2;


	// Offset to the section which will contains hints/names of the imported functions name
	uint32_t functions_name_offset = lookuptable_offset + entries_size;

	// Offset of the section which will holds libraries name
	uint32_t libraries_name_offset = functions_name_offset + functions_name_size;

	// Offset of the section where trampolines will be written
	//uint32_t trampolines_offset = libraries_name_offset + libraries_name_size;

	// Create empty content of the required size and align it
	ANBU::LOGGER("Libraries name offset 0x%x libraries name size 0x%x\n", libraries_name_offset, libraries_name_size);
	size_t new_section_size = libraries_name_offset + libraries_name_size;
	std::vector<uint8_t> content(new_section_size, 0);
	size_t raw_size_aligned = static_cast<size_t>(LIEF::align(content.size(), this->binary_->optional_header()->file_alignment()));
	size_t padding = raw_size_aligned - new_section_size;
	for (size_t i = 0; i < padding; i++)
		content.push_back(0);

	// Create a new section to handle imports
	pe_section new_section_struct = { 0 };
	strncpy(new_section_struct.Name, import_section_name.c_str(), 8);
	new_section_struct.Characteristics = static_cast<uint32_t>(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA_k) |
		static_cast<uint32_t>(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ_k) |
		static_cast<uint32_t>(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE_k);
	new_section_struct.SizeOfRawData = content.size();
	new_section_struct.VirtualSize = new_section_size;

	pe_parser::section_header_t new_import_section{ &new_section_struct };

	// As add_section will change DATA_DIRECTORY::IMPORT_TABLE we have to save it before
	pe_parser::section_header_t *import_section = this->binary_->add_section(&new_import_section);

	// Process libraries
	for (size_t i = 0; i < this->binary_->imports().size(); i++)
	{
		// Header
		pe_import header = { 0 };
		header.ImportLookupTableRVA = static_cast<uint32_t>(import_section->virtual_address() + lookuptable_offset);
		header.TimeDateStamp = static_cast<uint32_t>(this->binary_->imports().at(i).timedatestamp());
		header.ForwarderChain = static_cast<uint32_t>(this->binary_->imports().at(i).forwarder_chain());
		header.NameRVA = static_cast<uint32_t>(import_section->virtual_address() + libraries_name_offset);
		header.ImportAddressTableRVA = static_cast<uint32_t>(this->binary_->imports().at(i).import_address_table_rva());

		// copy the header in the "header section"
		std::copy(
			reinterpret_cast<uint8_t*>(&header),
			reinterpret_cast<uint8_t*>(&header) + sizeof(pe_import),
			content.begin() + import_table_offset
		);

		import_table_offset += sizeof(pe_import);

		// Copy the library name in the "string section"

		ANBU::LOGGER_INFO("Adding to import section library name '%s'\n", this->binary_->imports().at(i).name().c_str());

		strcpy(reinterpret_cast<char*>(content.begin() + libraries_name_offset), this->binary_->imports().at(i).name().c_str());

		libraries_name_offset += this->binary_->imports().at(i).name().size() + 1; // +1 for '\0'

		// Process imported functions
		for (size_t j = 0; j < this->binary_->imports().at(i).entries().size(); j++)
		{
			// Default: ordinal case
			uintptr_t lookup_table_value = static_cast<uintptr_t>(this->binary_->imports().at(i).entries().at(j).data());

			if (!this->binary_->imports().at(i).entries().at(j).is_ordinal()) // if it's name instead of ordinal
			{
				
				lookup_table_value = import_section->virtual_address() + functions_name_offset;

				// Insert entry in hint/name table
				// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


				// First: hint
				const uint16_t hint = this->binary_->imports().at(i).entries().at(j).hint();
				std::copy(
					reinterpret_cast<const uint8_t*>(&hint),
					reinterpret_cast<const uint8_t*>(&hint) + sizeof(uint16_t),
					content.begin() + functions_name_offset); // hintIdx

				functions_name_offset += sizeof(uint16_t);

				// Then: name
				fprintf(stderr, "[INFO] Adding to import section function name '%s'\n", this->binary_->imports().at(i).entries().at(j).name().c_str());

				strcpy(reinterpret_cast<char*>(content.begin() + functions_name_offset), this->binary_->imports().at(i).entries().at(j).name().c_str());
				functions_name_offset += this->binary_->imports().at(i).entries().at(j).name().size() + 1; // +1 for \0
			}

			// RVA to function name, or ordinal
			std::copy(
				reinterpret_cast<const uint8_t*>(&lookup_table_value),
				reinterpret_cast<const uint8_t*>(&lookup_table_value) + sizeof(uintptr_t),
				content.begin() + lookuptable_offset);

			/*
			std::copy(
				reinterpret_cast<const uint8_t*>(&iat_value),
				reinterpret_cast<const uint8_t*>(&iat_value) + sizeof(uintptr_t),
				content.begin() + iat_offset);
			*/
			lookuptable_offset	+= sizeof(uintptr_t);
		}

		// Insert null entry at the end
		std::fill(
			content.begin() + lookuptable_offset,
			content.begin() + lookuptable_offset + sizeof(uintptr_t),
			0
		);

		lookuptable_offset += sizeof(uintptr_t);
	}

	std::fill(
		content.begin() + import_table_offset,
		content.begin() + import_table_offset + sizeof(pe_import),
		0);

	import_table_offset += sizeof(pe_import);

	// Fill the section
	import_section->content(content);

	// Update IAT data directory
	this->binary_->data_directory(DATA_DIRECTORY::import_table_k)->RVA(import_section->virtual_address());
}


/************** PRIVATE DUMP FUNCTIONS **********************/
bool builder_t::dump_headers()
{
	size_t written_bytes, i;

	fseek(dumped_file, 0, SEEK_SET);

	// Write DOS Header
	pe_dos_header dos_header = this->binary_->dos_header()->dos_header();

	ANBU::LOGGER_INFO(logfile, "Writing to file dos header\n");

	written_bytes = fwrite(&dos_header, sizeof(pe_dos_header), 1, dumped_file);

	if (!written_bytes)
	{
		ANBU::LOGGER_ERROR(logfile, "Not possible to write dos header\n");
		return false;
	}

	// Write DOS stub
	dos_stub = this->binary_->dos_stub();

	if (dos_stub != nullptr)
	{
		size_t dos_stub_size = this->binary_->dos_header()->addressof_new_exeheader() - sizeof(pe_dos_header);

		ANBU::LOGGER_INFO(logfile, "Writing to file dos stub\n");

		written_bytes = fwrite(dos_stub, dos_stub_size, 1, dumped_file);
		
		if (dos_stub_size != 0) // check that size is different of zero
		{
			if (!written_bytes)
			{
				ANBU::LOGGER_ERROR(logfile, "Not possible to write dos stub\n");
				return false;
			}
		}
	}
	else
	{
		fseek(dumped_file, this->binary_->dos_header()->addressof_new_exeheader(), SEEK_SET);
	}

	// PE Header
	pe_header nt_header = this->binary_->nt_coff_header()->nt_header();

	ANBU::LOGGER_INFO(logfile, "Writing to file nt header\n");
	written_bytes = fwrite(&nt_header, sizeof(pe_header), 1, dumped_file);

	if (!written_bytes)
	{
		ANBU::LOGGER_ERROR(logfile, "Not possible to write nt header\n");
		return false;
	}


	// Optional Header
	ANBU::LOGGER_INFO(logfile, "Writing to file optional header\n");

	if (this->binary_->optional_header()->is_64_bit_binary())
	{
		pe64_optional_header optional_header_pe64 = this->binary_->optional_header()->optional_header_pe64();

		written_bytes = fwrite(
			&optional_header_pe64,
			sizeof(pe64_optional_header),
			1,
			dumped_file);
	}
	else
	{
		pe32_optional_header optional_header_pe32 = this->binary_->optional_header()->optional_header_pe32();

		written_bytes = fwrite(
			&optional_header_pe32,
			sizeof(pe32_optional_header),
			1,
			dumped_file);
	}

	if (!written_bytes)
	{
		ANBU::LOGGER_ERROR(logfile, "Not possible to write optional header\n");
		return false;
	}

	// Write Data directories
	ANBU::LOGGER_INFO(logfile, "Writing to file data directories\n");

	for (i = 0; i < this->binary_->optional_header()->numberof_rva_and_size(); i++)
	{
		pe_data_directory data_directory = this->binary_->data_directory().at(i).data_directory();

		written_bytes = fwrite(
			&data_directory,
			sizeof(pe_data_directory),
			1,
			dumped_file
		);

		if (!written_bytes)
		{
			ANBU::LOGGER_ERROR(logfile, "Not possible to write data directories\n");
			return false;
		}
	}

	// Write Section Headers
	ANBU::LOGGER_INFO(logfile, "Writing to file section header\n");

	for (i = 0; i < this->binary_->nt_coff_header()->numberof_sections(); i++)
	{
		pe_section section_header = this->binary_->section_table_header().at(i).section_header();

		written_bytes = fwrite(
			&section_header,
			sizeof(pe_section),
			1,
			dumped_file);

		if (!written_bytes)
		{
			ANBU::LOGGER_ERROR(logfile, "Not possible to write section header\n");
			return false;
		}
	}

	return true;
}


bool builder_t::dump_sections()
{
	const size_t block_size = 1024;
	size_t bytes_to_write, read_bytes, write_bytes, i;
	uint8_t* section_buffer;
	ADDRINT address_to_read;

	section_buffer = (uint8_t*)malloc(block_size);

	for (i = 0; i < this->binary_->nt_coff_header()->numberof_sections(); i++)
	{
		
		bytes_to_write = this->binary_->section_table_header().at(i).sizeof_raw_data();
		address_to_read = base_address_to_dump + this->binary_->section_table_header().at(i).virtual_address();

		ANBU::LOGGER_INFO(logfile, "Section virtual address: 0x%x, size of raw data: 0x%x, pointer to raw data: 0x%x\n",
			address_to_read,
			bytes_to_write,
			this->binary_->section_table_header().at(i).pointerto_raw_data());

		if (fseek(dumped_file, this->binary_->section_table_header().at(i).pointerto_raw_data(), SEEK_SET))
			return false;
		
		while (bytes_to_write != 0)
		{
			if (bytes_to_write < 1024)
			{
				read_bytes = PIN_SafeCopy(section_buffer, (const VOID*)address_to_read, bytes_to_write);
				if (read_bytes != bytes_to_write)
				{
					free(section_buffer);
					return false;
				}
			}
			else
			{
				read_bytes = PIN_SafeCopy(section_buffer, (const VOID*)address_to_read, 1024);
				if (read_bytes != 1024)
				{
					free(section_buffer);
					return false;
				}
			}

			write_bytes = fwrite(section_buffer, read_bytes, 1, dumped_file);

			if (!write_bytes)
			{
				free(section_buffer);
				return false;
			}

			bytes_to_write -= read_bytes;
			address_to_read += read_bytes;
		}
	}

	free(section_buffer);

	return true;
}


void builder_t::clean_list()
{
	std::vector<lief_import_t> imports = this->binary_->imports();
	/*
	*	First check if there's any dll without functions (because of stupid LoadLibrary
	*	or some PIN's mistake).
	*/
	for (std::vector<lief_import_t>::iterator it = imports.begin(); it != imports.end();)
	{
		if (it->entries().size() == 0)
		{
			it = imports.erase(it);
		}
		else
		{
			++it;
		}
	}

	/*
	*	I had to implement this because, all those functions imported
	*	by packer that match with some functions from the packed code
	*	receive the same destination address of copy, so what I do is
	*	to search those first_thunk that correspond to the same imports
	*	in case of match, I take the lowest.
	*/
	for (int i = 0; i < static_cast<int>(imports.size()); i++)
	{
		for (size_t j = 0; j < imports.size(); j++)
		{
			string name_i = imports.at(i).name();
			string name_j = imports.at(j).name();


			std::transform(name_i.begin(), name_i.end(), name_i.begin(), ::toupper);
			std::transform(name_j.begin(), name_j.end(), name_j.begin(), ::toupper);

			imports.at(i).name(name_i);
			imports.at(j).name(name_j);

			ANBU::LOGGER_INFO("Testing %s and %s with i = %d and j = %d\n", imports.at(i).name().c_str(), imports.at(j).name().c_str(), i, j);
			
			if ((i != j) && (imports.at(i).name() == imports.at(j).name()))
			{
				if ((imports.at(i).import_address_table_rva() < imports.at(j).import_address_table_rva()) &&
					(imports.at(j).import_address_table_rva() < (imports.at(i).import_address_table_rva() + (imports.at(i).entries().size() * sizeof(ADDRINT)) )))
				{
					ANBU::LOGGER_INFO("Deleting: %d\n", j);
					imports.erase(imports.begin() + j);
					i = -1;
					break;
				}
				else if ((imports.at(j).import_address_table_rva() < imports.at(i).import_address_table_rva()) &&
					(imports.at(i).import_address_table_rva() < (imports.at(j).import_address_table_rva() + (imports.at(j).entries().size() * sizeof(ADDRINT)))))
				{
					ANBU::LOGGER_INFO("Deleting: %d\n", i);
					imports.erase(imports.begin() + i);
					i = -1;
					break;
				}
			}
			
		}
	}

	this->binary_->imports(imports);
}