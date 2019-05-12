
#include "data_directory_header.h"

/************* EXTERN VARIABLES *************/
extern FILE *logfile; // log file handler

namespace pe_parser
{

	data_directory_header_t::data_directory_header_t(const pe_data_directory *header, DATA_DIRECTORY type) : 
		rva_ { header->RelativeVirtualAddress },
		size_ { header->Size },
		type_ { type }
	{
		/* I couldn't initialize the map with as many values, so I do it in the constructor */
		directory_names[DATA_DIRECTORY::export_table_k]				= "Export Table";
		directory_names[DATA_DIRECTORY::import_table_k]				= "Import Table";
		directory_names[DATA_DIRECTORY::resource_table_k]			= "Resource Table";
		directory_names[DATA_DIRECTORY::exception_table_k]			= "Exception Table";
		directory_names[DATA_DIRECTORY::certificate_table_k]		= "Certificate Table";
		directory_names[DATA_DIRECTORY::base_relocation_table_k]	= "Base Relocation Table";
		directory_names[DATA_DIRECTORY::debug_k]					= "Debug";
		directory_names[DATA_DIRECTORY::architecture_k]				= "Architecture";
		directory_names[DATA_DIRECTORY::global_ptr_k]				= "Global Ptr";
		directory_names[DATA_DIRECTORY::tls_table_k]				= "TLS Table";
		directory_names[DATA_DIRECTORY::load_config_table_k]		= "Load Config Table";
		directory_names[DATA_DIRECTORY::bound_import_k]				= "Bound Import";
		directory_names[DATA_DIRECTORY::iat_k]						= "IAT";
		directory_names[DATA_DIRECTORY::delay_import_descriptor_k]	= "Delay Import Descriptor";
		directory_names[DATA_DIRECTORY::clr_runtime_header_k]		= "CLR Runtime Header";
		directory_names[DATA_DIRECTORY::reserved_k]					= "Reserved";
	}


	pe_data_directory data_directory_header_t::data_directory(void) const
	{
		/*
		*	This part corresponds to LIEF project:	
			Builder& Builder::operator<<(const DataDirectory& data_directory) {

			  pe_data_directory header;

			  header.RelativeVirtualAddress = data_directory.RVA();
			  header.Size                   = data_directory.size();

			  this->ios_.write(reinterpret_cast<uint8_t*>(&header), sizeof(pe_data_directory));
			  return *this;
			}
		*/
		pe_data_directory data_directory;

		data_directory.RelativeVirtualAddress	= this->rva_;
		data_directory.Size						= this->size_;

		return data_directory;
	}


	uint32_t data_directory_header_t::RVA(void) const
	{
		return this->rva_;
	}


	uint32_t data_directory_header_t::size(void) const
	{
		return this->size_;
	}


	DATA_DIRECTORY data_directory_header_t::type(void) const
	{
		return this->type_;
	}


	void data_directory_header_t::RVA(uint32_t rva)
	{
		this->rva_ = rva;
	}


	void data_directory_header_t::size(uint32_t size)
	{
		this->size_ = size;
	}


	void data_directory_header_t::type(DATA_DIRECTORY type)
	{
		this->type_ = type;
	}


	bool data_directory_header_t::dump_directories(FILE *output_file)
	{
		fprintf(output_file, "\t+Name: %s\n",				directory_names[this->type()].c_str());
		fprintf(output_file, "\t+Virtual Address: 0x%x\n",	this->RVA());
		fprintf(output_file, "\t+Size: 0x%x\n",				this->size());

		return true;
	}
}