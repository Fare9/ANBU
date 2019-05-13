#include "binary.h"

#include "builder.h"

/************* EXTERN VARIABLES *************/
extern FILE* logfile;

binary_t::binary_t(std::vector<uint8_t>* buffer) :
	available_sections_space_{ 0 },
	has_imports_{ 0 }
{
	this->binary_is_okay		= true;
	this->binary_base_address	= reinterpret_cast<ADDRINT>(buffer->begin());

#ifdef _Win64
	this->type_ = PE_TYPE::pe64_k;
#else
	this->type_ = PE_TYPE::pe32_k;
#endif // _Win64
}

binary_t::binary_t(ADDRINT binary_address) : 
	available_sections_space_ {0},
	has_imports_{ 0 }
{
	this->binary_is_okay		= true;
	this->binary_img			= IMG_FindByAddress(binary_address);

	if (this->binary_img == IMG_Invalid())
	{
		this->binary_is_okay = false;
		return;
	}

	this->binary_base_address	= IMG_StartAddress(this->binary_img);

	if (this->binary_base_address == NULL)
	{
		this->binary_is_okay = false;
		return;
	}

#ifdef _Win64
	this->type_ = PE_TYPE::pe64_k;
#else
	this->type_ = PE_TYPE::pe32_k;
#endif // _Win64


	fprintf(stderr,  "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
	fprintf(logfile, "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
}


binary_t::binary_t(IMG binary_img) :
	available_sections_space_{ 0 },
	has_imports_{ 0 }
{
	this->binary_is_okay		= true;
	this->binary_img			= binary_img;

	if (this->binary_img == IMG_Invalid())
	{
		this->binary_is_okay = false;
		return;
	}

	this->binary_base_address = IMG_StartAddress(this->binary_img);

	if (this->binary_base_address == NULL)
	{
		this->binary_is_okay = false;
		return;
	}

#ifdef _Win64
	this->type_ = PE_TYPE::pe64_k;
#else
	this->type_ = PE_TYPE::pe32_k;
#endif // _Win64

	fprintf(stderr, "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
	fprintf(logfile, "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
}


binary_t::~binary_t()
{
	if (this->initial_entropies != nullptr)
	{
		free(this->initial_entropies);
	}

	if (this->dos_header_ != nullptr)
	{
		delete this->dos_header_;
	}

	if (this->dos_stub_ != nullptr)
	{
		free(this->dos_stub_);
	}

	if (this->nt_coff_header_ != nullptr)
	{
		delete this->nt_coff_header_;
	}

	if (this->optional_header_ != nullptr)
	{
		delete this->optional_header_;
	}

	if (this->data_directory_header_.size())
	{
		this->data_directory_header_.clear();
	}

	if (this->section_table_header_.size())
	{
		this->section_table_header_.clear();
	}
}

PE_TYPE binary_t::type(void) const
{
	return this->type_;
}


bool binary_t::analyze_binary(void)
{
	if (parse())
		if (calculate_initial_entropy())
			return true;
	return false;
}


uint64_t binary_t::va_to_offset(uint64_t VA)
{
	uint64_t rva = VA - this->optional_header_->imagebase();
	return this->rva_to_offset(rva);
}


uint64_t binary_t::rva_to_offset(uint64_t RVA)
{
	int32_t section = -1;

	for (size_t sec = 0; sec < this->section_table_header_.size(); sec++)
	{
		if (RVA >= section_table_header_[sec].virtual_address() && RVA < (section_table_header_[sec].virtual_address() + section_table_header_[sec].virtual_size()))
		{
			section = static_cast<int32_t>(sec);
			break;
		}
	}

	if (section == -1)
		return static_cast<uint32_t>(RVA);

	// rva - virtual_address + pointer_to_raw_data
	uint32_t section_alignment = this->optional_header_->section_alignment();
	uint32_t file_alignment    = this->optional_header_->file_alignment();
	if (section_alignment < 0x1000)
		section_alignment = file_alignment;

	uint64_t section_va		= section_table_header_[section].virtual_address();
	uint64_t section_offset = section_table_header_[section].pointerto_raw_data();
	return ((RVA - section_va) + section_offset);
}


pe_parser::section_header_t* binary_t::section_from_offset(uint64_t offset)
{
	int32_t section = -1;

	for (size_t sec = 0; sec < this->section_table_header_.size(); sec++)
	{
		if (offset >= section_table_header_[sec].pointerto_raw_data() && offset < (section_table_header_[sec].pointerto_raw_data() + section_table_header_[sec].sizeof_raw_data()))
		{
			section = static_cast<int32_t>(sec);
			break;
		}
	}

	if (section == -1)
		return nullptr;
	
	return &section_table_header_[section];
}


pe_parser::section_header_t* binary_t::section_from_rva(uint64_t virtual_address)
{
	int32_t section = -1;

	for (size_t sec = 0; sec < this->section_table_header_.size(); sec++)
	{
		if (virtual_address >= section_table_header_[sec].virtual_address() && virtual_address < (section_table_header_[sec].virtual_address() + section_table_header_[sec].virtual_size()))
		{
			section = static_cast<int32_t>(sec);
			break;
		}
	}

	if (section == -1)
		return nullptr;

	return &section_table_header_[section];
}
/******* GETTERS **********/
pe_parser::dos_header_t* binary_t::dos_header(void)
{
	return this->dos_header_;
}


uint8_t* binary_t::dos_stub(void)
{
	return this->dos_stub_;
}


pe_parser::nt_header_t* binary_t::nt_coff_header(void)
{
	return this->nt_coff_header_;
}


pe_parser::optional_header_t* binary_t::optional_header(void)
{
	return this->optional_header_;
}


std::vector<pe_parser::data_directory_header_t> binary_t::data_directory(void)
{
	return this->data_directory_header_;
}


void binary_t::data_directory(std::vector<pe_parser::data_directory_header_t> data_directory_header)
{
	this->data_directory_header_ = data_directory_header;
}


pe_parser::data_directory_header_t* binary_t::data_directory(DATA_DIRECTORY index)
{
	if (static_cast<size_t>(index) < this->data_directory_header_.size())
		return &this->data_directory_header_[static_cast<size_t>(index)];
}


bool binary_t::has(DATA_DIRECTORY index)
{
	if (static_cast<size_t>(index) < this->data_directory_header_.size())
		return (this->data_directory_header_[static_cast<size_t>(index)].RVA() != 0) && (this->data_directory_header_[static_cast<size_t>(index)].size() != 0);
	else
		return false;
}


bool binary_t::has_imports(void) const
{
	return this->has_imports_;
}


uint32_t binary_t::sizeof_headers(void) const
{
	uint32_t size = 0;
	size += dos_header_->addressof_new_exeheader();
	size += sizeof(pe_header);
	size += this->optional_header_->get_optional_header_size();
	
	size += sizeof(pe_data_directory) * (this->data_directory_header_.size() + 1);
	size += sizeof(pe_section) * (this->section_table_header_.size() + 1);

	size = static_cast<uint32_t>(LIEF::align(size, this->optional_header_->file_alignment()));
	return size;
}


uint64_t binary_t::virtual_size(void) const
{
	uint64_t size = 0;
	size += this->dos_header_->addressof_new_exeheader();
	size += sizeof(pe_header);
	size += this->optional_header_->get_optional_header_size();
	
	size = MAX(size, (this->section_table_header_.back().virtual_address() + this->section_table_header_.back().virtual_size()));

	size = LIEF::align(size, this->optional_header_->section_alignment());

	fprintf(stderr, "[INFO] New virtual size of binary 0x%llx", size);

	return size;
}


std::vector<pe_parser::section_header_t> binary_t::section_table_header(void)
{
	return this->section_table_header_;
}

void binary_t::section_table_header(std::vector<pe_parser::section_header_t> sections)
{
	this->section_table_header_ = sections;
}

pe_parser::section_header_t* binary_t::get_section(std::string& name)
{
	for (size_t i = 0; i < section_table_header_.size(); i++)
	{
		if (strcmp(name.c_str(), section_table_header_[i].name()) == 0)
			return &section_table_header_[i];
	}
	
	return nullptr;
}


pe_parser::section_header_t* binary_t::import_section(void)
{
	pe_parser::data_directory_header_t* import_directory = this->data_directory(DATA_DIRECTORY::import_table_k);
	if (import_directory->RVA() == 0 || import_directory->size() == 0)
		return nullptr;
	
	for (size_t i = 0; i < section_table_header_.size(); i++)
	{
		if (import_directory->RVA() >= section_table_header_[i].virtual_address() &&
			import_directory->RVA() < (section_table_header_[i].virtual_address() + section_table_header_[i].virtual_size()))
			return &section_table_header_[i];
	}

	return nullptr;
}


void binary_t::remove_section(std::string& name)
{
	for (size_t i = 0; i < section_table_header_.size(); i++)
	{
		if (strcmp(section_table_header_[i].name(), name.c_str()) == 0)
		{
			this->remove(&section_table_header_[i]);
			return;
		}
	}
	
	fprintf(stderr, "[ERROR] Section %s not found\n", name.c_str());
	fprintf(logfile, "[ERROR] Section %s not found\n", name.c_str());
	return;
}


void binary_t::remove(pe_parser::section_header_t* section)
{
	int32_t section_index = -1;

	for (size_t i = 0; i < section_table_header_.size(); i++)
	{
		if (section->virtual_address() == section_table_header_[i].virtual_address())
		{
			section_index = static_cast<int32_t>(i);
			break;
		}
	}

	if (section_index == -1)
	{
		fprintf(stderr, "[ERROR] Section %s not found\n", section->name());
		fprintf(logfile, "[ERROR] Section %s not found\n", section->name());
		return;
	}

	pe_parser::section_header_t* to_remove = section;

	if (section_index < static_cast<int32_t>( (this->section_table_header_.size() - 1) ) && section_index > 0) // if it's not the last or the first one
	{
		pe_parser::section_header_t* previous = &(this->section_table_header_[section_index - 1]);
		const size_t raw_size_gap = (to_remove->pointerto_raw_data() + to_remove->sizeof_raw_data()) - (previous->pointerto_raw_data() + previous->sizeof_raw_data());
		previous->sizeof_raw_data(static_cast<uint32_t>(previous->sizeof_raw_data() + raw_size_gap));

		const size_t vsize_size_gap = (to_remove->virtual_address() + to_remove->virtual_size()) - (previous->virtual_address() + previous->virtual_size());
		previous->virtual_size(previous->virtual_size() + vsize_size_gap);
	}

	this->section_table_header_.erase(this->section_table_header_.begin() + section_index);

	this->nt_coff_header()->numberof_sections(this->nt_coff_header()->numberof_sections() - 1);
	this->optional_header_->sizeof_headers(this->sizeof_headers());
}


void binary_t::make_space_for_new_section(void)
{
	const uint32_t shift = static_cast<uint32_t>(LIEF::align(sizeof(pe_section), this->optional_header()->file_alignment()));

	fprintf(stderr, "[INFO] Making space for a new section header\n");
	fprintf(stderr, "[INFO] Shifting all sections by 0x%x", shift);

	for (size_t i = 0; i < this->section_table_header_.size(); i++)
	{
		this->section_table_header_[i].pointerto_raw_data(this->section_table_header_[i].pointerto_raw_data() + shift);
	}

	this->available_sections_space_++;
}


pe_parser::section_header_t* binary_t::add_section(pe_parser::section_header_t* section)
{
	/*
	*	This function corresponds to LIEF project:
		Section& Binary::add_section(const Section& section, PE_SECTION_TYPES type) {

		  if (this->available_sections_space_ < 0) {
			this->make_space_for_new_section();
			return this->add_section(section, type);
		  }

		  // Check if a section of type **type** already exist
		  auto&& it_section = std::find_if(
			  std::begin(this->sections_),
			  std::end(this->sections_),
			  [&type] (const Section* s) {
				return s != nullptr and s->is_type(type);
			  });

		  if (it_section != std::end(this->sections_)) {
			Section* s = *it_section;
			s->remove_type(type);
		  }

		  Section* new_section                = new Section{section};
		  std::vector<uint8_t> content        = new_section->content();
		  const uint32_t section_size         = static_cast<uint32_t>(content.size());
		  const uint32_t section_size_aligned = static_cast<uint32_t>(align(section_size, this->optional_header().file_alignment()));
		  const uint32_t virtual_size         = section_size;

		  content.insert(std::end(content), section_size_aligned - section_size, 0);
		  new_section->content(content);

		  // Compute new section offset
		  uint64_t new_section_offset = align(std::accumulate(
			  std::begin(this->sections_),
			  std::end(this->sections_), this->sizeof_headers(),
			  [] (uint64_t offset, const Section* s) {
				return std::max<uint64_t>(s->pointerto_raw_data() + s->sizeof_raw_data(), offset);
			  }), this->optional_header().file_alignment());

		  VLOG(VDEBUG) << "New section offset: 0x" << std::hex << new_section_offset;


		  // Compute new section Virtual address
		  const uint64_t new_section_va = align(std::accumulate(
			  std::begin(this->sections_),
			  std::end(this->sections_), this->optional_header().section_alignment(),
			  [] (uint64_t va, const Section* s) {
				return std::max<uint64_t>(s->virtual_address() + s->virtual_size(), va);
			  }), this->optional_header().section_alignment());

		  VLOG(VDEBUG) << "New section va: 0x" << std::hex << new_section_va;

		  new_section->add_type(type);

		  if (new_section->pointerto_raw_data() == 0) {
			new_section->pointerto_raw_data(new_section_offset);
		  }

		  if (new_section->sizeof_raw_data() == 0) {
			new_section->sizeof_raw_data(section_size_aligned);
		  }

		  if (new_section->virtual_address() == 0) {
			new_section->virtual_address(new_section_va);
		  }

		  if (new_section->virtual_size() == 0) {
			new_section->virtual_size(virtual_size);
		  }

		  if (new_section->is_type(PE_SECTION_TYPES::TEXT)) {
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
			this->optional_header().baseof_code(static_cast<uint32_t>(new_section->virtual_address()));
			this->optional_header().sizeof_code(new_section->sizeof_raw_data());
		  }

		  if (new_section->is_type(PE_SECTION_TYPES::DATA)) {
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA);
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

			if (this->type() == PE_TYPE::PE32) {
			  this->optional_header().baseof_data(static_cast<uint32_t>(new_section->virtual_address()));
			}
			this->optional_header().sizeof_initialized_data(new_section->sizeof_raw_data());
		  }


		  if (type == PE_SECTION_TYPES::IMPORT) {

			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
			new_section->add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

			this->data_directory(DATA_DIRECTORY::IMPORT_TABLE).RVA(new_section->virtual_address());
			this->data_directory(DATA_DIRECTORY::IMPORT_TABLE).size(new_section->sizeof_raw_data());
			this->data_directory(DATA_DIRECTORY::IMPORT_TABLE).section_ = new_section;
			this->data_directory(DATA_DIRECTORY::IAT).RVA(0);
			this->data_directory(DATA_DIRECTORY::IAT).size(0);
		  }

		  if (type == PE_SECTION_TYPES::RELOCATION) {
			this->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).RVA(new_section->virtual_address());
			this->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).size(new_section->virtual_size());
			this->data_directory(DATA_DIRECTORY::BASE_RELOCATION_TABLE).section_ = new_section;
		  }

		  if (type == PE_SECTION_TYPES::RESOURCE) {
			this->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).RVA(new_section->virtual_address());
			this->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).size(new_section->size());
			this->data_directory(DATA_DIRECTORY::RESOURCE_TABLE).section_ = new_section;
		  }

		  if (type == PE_SECTION_TYPES::TLS) {
			this->data_directory(DATA_DIRECTORY::TLS_TABLE).RVA(new_section->virtual_address());
			this->data_directory(DATA_DIRECTORY::TLS_TABLE).size(new_section->size());
			this->data_directory(DATA_DIRECTORY::TLS_TABLE).section_ = new_section;
		  }


		  if (this->sections_.size() >= std::numeric_limits<uint16_t>::max()) {
			throw pe_error("Binary reachs its maximum number of sections");
		  }

		  this->available_sections_space_--;
		  this->sections_.push_back(new_section);

		  // Update headers
		  this->header().numberof_sections(static_cast<uint16_t>(this->sections_.size()));

		  this->optional_header().sizeof_image(this->virtual_size());
		  this->optional_header().sizeof_headers(this->sizeof_headers());
		  return *(this->sections_.back());
		}
	*/

	if (this->available_sections_space_ < 0)
	{
		this->make_space_for_new_section();
		return this->add_section(section);
	}

	pe_parser::section_header_t* new_section	= section;
	std::vector<uint8_t> content				= new_section->content();
	const uint32_t section_size					= static_cast<uint32_t>(content.size());
	const uint32_t section_size_aligned			= static_cast<uint32_t>(LIEF::align(section_size, this->optional_header_->file_alignment()));
	const uint32_t virtual_size					= section_size;

	for (size_t i = 0; i < (section_size_aligned - section_size); i++)
		content.push_back(0);

	new_section->content(content);

	// compute new section offset
	uint64_t new_section_offset = LIEF::align(
		(this->section_table_header_[this->section_table_header_.size() - 1].pointerto_raw_data() +
		 this->section_table_header_[this->section_table_header_.size() - 1].sizeof_raw_data()),
		 this->optional_header_->file_alignment()
	);

	fprintf(stderr, "[INFO] New section offset: 0x%x\n", static_cast<unsigned int>(new_section_offset));

	// Compute new section virtual address
	const uint64_t new_section_va = LIEF::align(
		(this->section_table_header_[this->section_table_header_.size() - 1].virtual_address() +
		 this->section_table_header_[this->section_table_header_.size() - 1].virtual_size()),
		 this->optional_header_->section_alignment()
	);

	fprintf(stderr, "[INFO] New section va: 0x%x\n", static_cast<unsigned int>(new_section_va));

	if (new_section->pointerto_raw_data() == 0)
		new_section->pointerto_raw_data(static_cast<uint32_t>(new_section_offset));

	if (new_section->sizeof_raw_data() == 0)
		new_section->sizeof_raw_data(section_size_aligned);

	if (new_section->virtual_address() == 0)
		new_section->virtual_address(static_cast<uint32_t>(new_section_va));

	if (new_section->virtual_size() == 0)
		new_section->virtual_size(virtual_size);

	if (this->section_table_header_.size() >= MaxNumberOfSections16)
	{
		fprintf(stderr, "[ERROR] Binary reachs its maximum number of sectiosn");
		return nullptr;
	}

	this->available_sections_space_--;
	this->section_table_header_.push_back(*new_section);

	// Update headers
	this->nt_coff_header_->numberof_sections(static_cast<uint16_t>(this->section_table_header_.size()));
	this->optional_header_->sizeof_image(static_cast<uint32_t>(this->virtual_size()));
	this->optional_header_->sizeof_headers(this->sizeof_headers());
	return &(this->section_table_header_.back());
}


bool binary_t::has_section_changed_entropy(ADDRINT address_of_section)
{
	size_t i;
	float entropy;
	float threshold;

	pe_parser::section_header_t* section = this->section_from_rva(address_of_section - this->binary_base_address);

	entropy = calculate_entropy_section(*section);

	for (i = 0; i < this->section_table_header_.size(); i++)
	{
		if (section_table_header_[i].virtual_address() == section->virtual_address())
		{
			threshold = this->initial_entropies[i] * (this->entropy_threshold / (float)100.0);
			if (
				(entropy > this->initial_entropies[i] + threshold) || 
				(entropy < this->initial_entropies[i] - threshold)
				)
			{
				return true;
			}
			else
				return false;
		}
	}

	return true;
}


bool binary_t::on_pe_file(ADDRINT address)
{
	if (!this->binary_is_okay)
		return false;

	address -= binary_base_address;

	if (address <= optional_header_->sizeof_image())
		return true;

	return false;
}


float binary_t::calculate_entropy_section(pe_parser::section_header_t section)
{
	float		count						= 0.0;
	float		entropy						= 0.0;
	uint32_t	each_byte_repetition[256]	= { 0 };
	uint8_t*	buffer_for_section			= nullptr;
	uint8_t		aux;
	size_t		i;
	buffer_for_section = (uint8_t*)calloc(section.virtual_size(), sizeof(uint8_t));

	for (i = 0; i < section.virtual_size(); i++)
	{
		if (PIN_SafeCopy(
			(VOID*)(&aux),
			(const VOID*)(this->binary_base_address + (ADDRINT)section.virtual_address() + (ADDRINT)i),
			sizeof(uint8_t)
		) != sizeof(uint8_t))
			std::__stl_throw_runtime_error("[ERROR] Reading byte from memory");

		each_byte_repetition[aux]++;
	}

	for (i = 0; i <= 0xff; i++)
	{
		if (each_byte_repetition[i] != 0)
		{
			count = (float)each_byte_repetition[i] / (float)section.virtual_size();
			entropy += -count * log2f(count);
		}
	}

	free(buffer_for_section);

	return entropy;
}


bool binary_t::calculate_initial_entropy(void)
{
	size_t i;
	
	this->initial_entropies = (float*)calloc(this->section_table_header_.size(), sizeof(float));

	for (i = 0; i < this->section_table_header_.size(); i++)
	{
		initial_entropies[i] = calculate_entropy_section(section_table_header_[i]);

		fprintf(stderr, "[INFO] Entropy for section in RVA 0x%x - %f\n", section_table_header_[i].virtual_address(), initial_entropies[i]);
		fprintf(logfile, "[INFO] Entropy for section in RVA 0x%x - %f\n", section_table_header_[i].virtual_address(), initial_entropies[i]);
	}
	
	return true;
}


bool binary_t::parse(void)
{
	if (!this->parse_headers())
		return false;

	if (!this->parse_dos_stub())
		return false;

	fprintf(stderr, "[INFO] Decomposing Sections\n");

	if (!this->parse_sections())
		return false;

	fprintf(stderr, "[INFO] Decomposing Data directories\n");
	if (!this->parse_data_directories())
		return false;

	return true;
}


bool binary_t::parse_headers(void)
{
	if (!this->binary_is_okay)
		return false;

	headers_are_correct = false;

	size_t copied_data, data_to_copy;

	// DOS Header
	const ADDRINT pe_dos_header_offset = this->binary_base_address;
	pe_dos_header dos_header_struct;

	data_to_copy = sizeof(pe_dos_header);
	
	copied_data = PIN_SafeCopy((VOID*)&dos_header_struct, (const VOID*)pe_dos_header_offset, data_to_copy);

	if (copied_data != data_to_copy)
	{
		fprintf(stderr, "[ERROR] dos header corrupted\n");
		fprintf(logfile, "[ERROR] dos header corrupted\n");
		return false;
	}

	if (dos_header_struct.Magic != mz_signature)
	{
		fprintf(stderr, "[ERROR] dos header not correct\n");
		fprintf(logfile, "[ERROR] dos header not correct\n");
		return false;
	}


	dos_header_ = new pe_parser::dos_header_t(&dos_header_struct);

	dos_header_->dump_dos_header(logfile);
	
	// PE32 Header
	const ADDRINT pe32_header_off = this->binary_base_address + dos_header_->addressof_new_exeheader();
	pe_header pe_header;

	data_to_copy = sizeof(pe_header);

	copied_data = PIN_SafeCopy((VOID*)&pe_header, (const VOID*)pe32_header_off, data_to_copy);

	if (copied_data != data_to_copy)
	{
		fprintf(stderr, "[ERROR] pe header corrupted\n");
		fprintf(logfile, "[ERROR] pe header corrupted\n");
		return false;
	}
	
	if (pe_header.signature != correct_pe_signature_k)
	{
		fprintf(stderr, "[ERROR] pe header not correct\n");
		fprintf(logfile, "[ERROR] pe header not correct\n");
		return false;
	}

	nt_coff_header_ = new pe_parser::nt_header_t(&pe_header);

	nt_coff_header_->dump_nt_header(logfile);

	// Optional Header
	const ADDRINT optional_header_off = this->binary_base_address + dos_header_->addressof_new_exeheader() + sizeof(pe_header);
	PE_TYPE pe_type;
	pe32_optional_header pe32_optional_header;
	pe64_optional_header pe64_optional_header;

	data_to_copy = sizeof(PE_TYPE);

	copied_data = PIN_SafeCopy((VOID*)&pe_type, (const VOID*)optional_header_off, data_to_copy);

	if (copied_data != data_to_copy)
	{
		fprintf(stderr, "[ERROR] optional header corrupted\n");
		fprintf(logfile, "[ERROR] optional header corupted\n");
		return false;
	}

	if (pe_type == PE_TYPE::pe32_k)
	{
		data_to_copy = sizeof(pe32_optional_header);
		copied_data  = PIN_SafeCopy((VOID*)&pe32_optional_header, (const VOID*)optional_header_off, data_to_copy);
	}
	else if (pe_type == PE_TYPE::pe64_k)
	{
		data_to_copy = sizeof(pe64_optional_header);
		copied_data = PIN_SafeCopy((VOID*)&pe64_optional_header, (const VOID*)optional_header_off, data_to_copy);
	}
	
	if (copied_data != data_to_copy)
	{
		fprintf(stderr, "[ERROR] optional header corrupted\n");
		fprintf(logfile, "[ERROR] optional header corupted\n");
		return false;
	}

	if (pe_type == PE_TYPE::pe32_k)
	{
		this->optional_header_ = new pe_parser::optional_header_t(&pe32_optional_header);
	}
	else if (pe_type == PE_TYPE::pe64_k)
	{
		this->optional_header_ = new pe_parser::optional_header_t(&pe64_optional_header);
	}

	headers_are_correct = true;

	return true;
}


bool binary_t::parse_dos_stub(void)
{
	const ADDRINT ptr_to_dos_stub = this->binary_base_address + sizeof(pe_parser::dos_header_t);
	const uint64_t sizeof_dos_stub = dos_header_->addressof_new_exeheader() - sizeof(pe_dos_header);

	size_t copied_data;

	fprintf(stderr, "[INFO] Size of dos stub: %llu\n", sizeof_dos_stub);

	if (dos_header_->addressof_new_exeheader() < sizeof(pe_parser::dos_header_t))
		return true;


	dos_stub_ = (uint8_t*)calloc(static_cast<size_t>(sizeof_dos_stub), sizeof(uint8_t));

	if (dos_stub_ == nullptr)
	{
		fprintf(stderr, "[ERROR] DOS Stub corrupted\n");
		fprintf(logfile, "[ERROR] DOS Stub corrupted\n");
		return false;
	}
	else
	{
		copied_data = PIN_SafeCopy((VOID*)dos_stub_, (const VOID*)ptr_to_dos_stub, static_cast<size_t>(sizeof_dos_stub));

		if (copied_data != sizeof_dos_stub)
		{
			fprintf(stderr, "[ERROR] dos stub not correct\n");
			fprintf(logfile, "[ERROR] dos stub not correct\n");

			return false;
		}
	}
	return true;
}


bool binary_t::parse_data_directories(void)
{
	const ADDRINT directories_offset =
		this->binary_base_address +
		this->dos_header_->addressof_new_exeheader() +
		sizeof(pe_header) +
		this->optional_header_->get_optional_header_size();

	const uint32_t nbof_datadir = static_cast<uint32_t>(this->optional_header_->numberof_rva_and_size());

	size_t copied_data;

	pe_data_directory data_directory_struct;
	pe_parser::data_directory_header_t *data_directory;

	fprintf(logfile, "============== DATA DIRECTORY HEADERS ==============");

	for (size_t i = 0; i < nbof_datadir; i++)
	{
		copied_data = PIN_SafeCopy((VOID*)&data_directory_struct, (const VOID*)(directories_offset + (i * sizeof(pe_data_directory))), sizeof(pe_data_directory));

		if (copied_data != sizeof(pe_data_directory))
		{
			fprintf(stderr,  "[ERROR] Data Directory corrupted\n");
			fprintf(logfile, "[ERROR] Data Directory corrupted\n");
			return false;
		}

		data_directory = new pe_parser::data_directory_header_t(&data_directory_struct, static_cast<DATA_DIRECTORY>(i));

		fprintf(stderr, "[INFO] Processing Directory: %s\n", data_directory->directory_names[static_cast<DATA_DIRECTORY>(i)].c_str());
		fprintf(stderr, "[INFO] RVA: %x\n", data_directory->RVA());
		fprintf(stderr, "[INFO] Size: %x\n", data_directory->size());

		data_directory->dump_directories(logfile);

		data_directory_header_.push_back(*data_directory);
	}

	return true;
}


bool binary_t::parse_sections(void)
{
	fprintf(stdout, "[INFO] Parsing Sections\n");

	const ADDRINT section_offset =
		this->binary_base_address +
		this->dos_header_->addressof_new_exeheader() +
		sizeof(pe_header) +
		this->optional_header_->get_optional_header_size() +
		sizeof(pe_data_directory) * this->optional_header_->numberof_rva_and_size();

	const uint32_t numberof_sections = this->nt_coff_header_->numberof_sections();

	size_t copied_data;

	pe_section pe_section_;
	pe_parser::section_header_t *section_header_;

	fprintf(logfile, "============== SECTION HEADERS ==============");

	for (size_t i = 0; i < numberof_sections; i++)
	{
		copied_data = PIN_SafeCopy((VOID*)&pe_section_, (const VOID*)(section_offset + (i * sizeof(pe_section))), sizeof(pe_section));

		if (copied_data != sizeof(pe_section))
		{
			fprintf(stderr, "[ERROR] Secion table corrupted\n");
			fprintf(logfile, "[ERROR] Secion table corrupted\n");
			return false;
		}

		section_header_ = new pe_parser::section_header_t(&pe_section_);

		section_header_->dump_sections(logfile);

		this->section_table_header_.push_back(*section_header_);
	}

	return true;
}


uint64_t binary_t::realign_pe()
/*
*	Function extracted from: https://github.com/x64dbg/TitanEngine/blob/7976be4edd84e923f24b8e68fc710262a6f3f4b0/TitanEngine/TitanEngine.Realigner.cpp#L44
*	I have to modify a little bit this function to use
*	LIEF binary_t class, and read memory from PIN API
*/
{
	uint32_t new_virtual_section_size = 0; // DWORD NewVirtualSectionSize = 0;
	uint32_t new_section_raw_pointer = 0; // DWORD NewSectionRawPointer = 0;
	uint32_t old_section_data_raw_ptr = 0; // DWORD OldSectionDataRawPtr = 0;
	uint32_t old_section_data_ptr = 0; // DWORD OldSectionDataPtr = 0;
	uint32_t section_data_ptr = 0; // DWORD SectionDataPtr = 0;
	uint32_t current_section = 0; // DWORD CurrentSection = 0;
	uint32_t file_alignment = 0; // DWORD FileAlignment = 0;
	uint8_t  section_byte = 0; // we will need this byte to read from memory

	std::vector<pe_parser::section_header_t> sections;

	sections = this->section_table_header();

	file_alignment = this->optional_header()->file_alignment();

	if (file_alignment == 0x1000)
		file_alignment = 0x200;		// set the minimum file alignment

	this->optional_header()->file_alignment(file_alignment);

	/*
	*	if(FileMapVA != NULL)
	*	{
	*	This part is not necessary because file is already
	*	loaded on memory.
	*	Also it is not necessary to create code for pe32
	*	and pe32+ because optional_header from LIEF binary_
	*	works for both architectures.
	*/

	for (size_t i = 0; i < sections.size(); i++)
	{
		auto *sec = &sections[i];
		section_data_ptr = sec->virtual_address() + sec->sizeof_raw_data();

		if (sec->sizeof_raw_data() > 0)	// use 0 instead of NULL
		{
			section_data_ptr--;
			PIN_SafeCopy((VOID*)&section_byte, (const VOID*)(binary_base_address + section_data_ptr), 1);
			/*
			*	while(*(PUCHAR)(FileMapVA + SectionDataPtr) == 0x00 && SectionDataPtr > PESections->PointerToRawData)
			*
			*	PIN doesn't work with file on disk, so instead of PointerToRawData, we use the virtual address
			*/
			while (section_byte == 0 && section_data_ptr > sec->virtual_address())
			{
				section_data_ptr--;
				PIN_SafeCopy((VOID*)&section_byte, (const VOID*)(binary_base_address + section_data_ptr), 1);
			}
		}

		section_data_ptr = section_data_ptr - sec->virtual_address();
		old_section_data_ptr = section_data_ptr;
		section_data_ptr = (section_data_ptr / file_alignment) * file_alignment;
		if (section_data_ptr < old_section_data_ptr)
			section_data_ptr = section_data_ptr + file_alignment;

		if (current_section == 0)
		{
			sec->pointerto_raw_data(
				MIN(
					this->optional_header()->sizeof_headers(),
					sec->pointerto_raw_data()
				)
			);
			this->optional_header()->sizeof_headers(sec->pointerto_raw_data());
			this->optional_header()->section_alignment(sec->virtual_address());
			sec->sizeof_raw_data(section_data_ptr);
		}
		else
		{
			old_section_data_ptr = sec->pointerto_raw_data();
			sec->sizeof_raw_data(section_data_ptr);
			new_section_raw_pointer = sections[i - 1].pointerto_raw_data() + sections[i - 1].sizeof_raw_data();

			new_section_raw_pointer = static_cast<uint32_t>(LIEF::align(new_section_raw_pointer, file_alignment));

			sec->pointerto_raw_data(new_section_raw_pointer);
			/*
			*	Not necessary in this case:
			*
				PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
				PESections->PointerToRawData = NewSectionRawPointer;
				RtlMoveMemory((LPVOID)((ULONG_PTR)FileMapVA + NewSectionRawPointer), (LPVOID)((ULONG_PTR)FileMapVA + OldSectionDataRawPtr), SectionDataPtr);
			*
			*/
		}

		/*
		*	Sometimes at the end virtual addresses +
		*	virtual sizes can be less than virtual address
		*	of next section, fix that just setting a new
		*	virtual address
		*/
		if (i != (sections.size() - 1))
		{
			uint64_t section_size = sec->virtual_size() + sec->virtual_address();

			if (section_size < sections[i + 1].virtual_address())
			{
				uint64_t new_section_virtual_address = sections[i + 1].virtual_address() - sec->virtual_address();

				sec->virtual_size(static_cast<uint32_t>(new_section_virtual_address));
			}
		}

		current_section++;
	}

	// once sections has been modified
	// set those sections on LIEF binary_
	this->section_table_header(sections);

	return sections[sections.size() - 1].pointerto_raw_data() +
		sections[sections.size() - 1].sizeof_raw_data(); // return the total size of the file in raw
}

/*
uint64_t binary_t::realign_pe()

{
	uint32_t new_virtual_section_size = 0; // DWORD NewVirtualSectionSize = 0;
	uint32_t new_section_raw_pointer = 0; // DWORD NewSectionRawPointer = 0;
	uint32_t old_section_data_raw_ptr = 0; // DWORD OldSectionDataRawPtr = 0;
	uint32_t old_section_data_ptr = 0; // DWORD OldSectionDataPtr = 0;
	uint32_t section_data_ptr = 0; // DWORD SectionDataPtr = 0;
	uint32_t current_section = 0; // DWORD CurrentSection = 0;
	uint32_t file_alignment = 0; // DWORD FileAlignment = 0;
	uint8_t  section_byte = 0; // we will need this byte to read from memory

	std::vector<pe_parser::section_header_t> sections;

	sections = this->section_table_header();

	file_alignment = this->optional_header()->file_alignment();

	if (file_alignment == 0x1000)
		file_alignment = 0x200;		// set the minimum file alignment

	this->optional_header()->file_alignment(file_alignment);

	for (size_t i = 0; i < sections.size(); i++)
	{
		auto *sec = &sections[i];
		section_data_ptr = sec->virtual_address() + sec->sizeof_raw_data();

		if (sec->sizeof_raw_data() > 0)	// use 0 instead of NULL
		{
			section_data_ptr--;
			PIN_SafeCopy((VOID*)&section_byte, (const VOID*)(binary_base_address + section_data_ptr), 1);

			while (section_byte == 0 && section_data_ptr > sec->virtual_address())
			{
				section_data_ptr--;
				PIN_SafeCopy((VOID*)&section_byte, (const VOID*)(binary_base_address + section_data_ptr), 1);
			}
		}

		section_data_ptr = section_data_ptr - sec->virtual_address();
		section_data_ptr = (section_data_ptr / file_alignment) * file_alignment;
		if (section_data_ptr < old_section_data_ptr)
			section_data_ptr = section_data_ptr + file_alignment;
		if (current_section == 0)
		{
			sec->pointerto_raw_data(
				MIN(
					this->optional_header()->sizeof_headers(),
					sec->pointerto_raw_data()
				)
			);
			this->optional_header()->sizeof_headers(sec->pointerto_raw_data());
			this->optional_header()->section_alignment(sec->virtual_address());
			sec->sizeof_raw_data(section_data_ptr);
		}
		else
		{
			old_section_data_ptr = sec->pointerto_raw_data();
			sec->sizeof_raw_data(section_data_ptr);
			new_section_raw_pointer = sections[i - 1].pointerto_raw_data() + sections[i - 1].sizeof_raw_data();
			
			new_section_raw_pointer = static_cast<uint32_t>(LIEF::align(new_section_raw_pointer, file_alignment));

			sec->pointerto_raw_data(new_section_raw_pointer);
		}


		if (i != (sections.size() - 1))
		{
			uint64_t section_size = sec->virtual_size() + sec->virtual_address();

			if (section_size < sections[i + 1].virtual_address())
			{
				uint64_t new_section_virtual_address = sections[i + 1].virtual_address() - sec->virtual_address();

				sec->virtual_size(static_cast<uint32_t>(new_section_virtual_address));
			}
		}

		current_section++;
	}

	// once sections has been modified
	// set those sections on LIEF binary_
	this->section_table_header(sections);

	return sections[sections.size() - 1].pointerto_raw_data() +
		sections[sections.size() - 1].sizeof_raw_data(); // return the total size of the file in raw
}
*/

bool binary_t::entropy_higher_than_HE(uint32_t entropy)
{
	return true;
}


bool binary_t::entropy_lower_than_LE(uint32_t entropy)
{
	return true;
}


// Imports
// ========

std::vector<lief_import_t> binary_t::imports(void)
{
	return this->imports_;
}


void binary_t::imports(std::vector<lief_import_t> imports)
{
	this->imports_ = imports;
}


import_entry_t* binary_t::add_import_function(const std::string& library, const std::string& function)
{
	for (size_t i = 0; i < this->imports_.size(); i++)
	{
		if (this->imports_.at(i).name() == library)
		{
			this->imports_.at(i).add_entry({ function });
			return this->imports_.at(i).get_entry(function);
		}
	}

	return nullptr;
}


lief_import_t* binary_t::add_library(const std::string& name)
{
	lief_import_t* new_import = new lief_import_t(name);
	this->imports_.push_back(*new_import);

	if (this->imports_.size() > 0)
		this->has_imports_ = true;

	return &this->imports_.back();
}


void binary_t::remove_library(const std::string& name)
{
	fprintf(stderr, "[ERROR] Not implemented yet\n");
	return;
}


void binary_t::remove_all_libraries(void)
{
	this->imports_.clear();
}


uint32_t binary_t::predict_function_rva(const std::string& library, const std::string& function)
{
	int64_t index_import = -1;
	
	for (size_t i = 0; i < this->imports_.size(); i++)
	{
		if (this->imports_.at(i).name() == library)
		{
			index_import = static_cast<uint64_t>(i);
			break;
		}
	}

	if (index_import == -1)
	{
		fprintf(stderr, "[ERROR] Unable to find library '%s'\n", library.c_str());
		return 0;
	}

	std::vector<import_entry_t> entries = this->imports_.at(static_cast<size_t>(index_import)).entries();

	size_t nb_functions = 0;

	for (size_t i = 0; i < entries.size(); i++)
	{
		if (entries.at(i).name() == function)
			nb_functions++;
	}

	if (nb_functions == 0)
	{
		fprintf(stderr, "[ERROR] Unable to find function '%s' in '%s' library\n", function.c_str(), library.c_str());
		return 0;
	}

	if (nb_functions > 1)
	{
		fprintf(stderr, "[ERROR] '%s' function is defined more than once in '%s' library\n", function.c_str(), library.c_str());
		return 0;
	}

	uint32_t import_table_size = static_cast<uint32_t>((this->imports_.size() + 1) * sizeof(pe_import)); // +1 for the null entry

	uint32_t address = import_table_size;

	uint32_t lookup_table_size = 0;
	for (size_t i = 0; i < this->imports_.size(); i++)
	{
		if (this->type_ == PE_TYPE::pe32_k)
			lookup_table_size += (this->imports_.at(i).entries().size() + 1) * sizeof(uint32_t);
		else
			lookup_table_size += (this->imports_.at(i).entries().size() + 1) * sizeof(uint64_t);
	}

	address += lookup_table_size;

	for (size_t i = 0; entries.at(i).name() != function && i < entries.size(); ++i)
	{
		if (this->type_ == PE_TYPE::pe32_k)
			address += sizeof(uint32_t);
		else
			address += sizeof(uint64_t);
	}

		// We assume the idata section will be the last section
	const uint64_t next_virtual_address = LIEF::align(
		(this->section_table_header_.at(this->section_table_header_.size() - 1).virtual_address() +
			this->section_table_header_.at(this->section_table_header_.size() - 1).virtual_size()),
		this->optional_header_->section_alignment());

	return static_cast<uint32_t>(next_virtual_address + address);
}


bool binary_t::has_import(const std::string& import_name) const
{
	for (size_t i = 0; i < this->imports_.size(); i++)
	{
		if (this->imports_.at(i).name() == import_name)
			return true;
	}

	return false;
}


const lief_import_t* binary_t::get_import(const std::string& import_name) const
{
	if (!this->has_import(import_name))
		return nullptr;

	for (size_t i = 0; i < this->imports_.size(); i++)
	{
		if (this->imports_.at(i).name() == import_name)
			return &this->imports_.at(i);
	}
	// not necessary but doesn't matter
	return nullptr;
}


lief_import_t* binary_t::get_import(const std::string& import_name)
{
	return const_cast<lief_import_t*>(static_cast<const binary_t*>(this)->get_import(import_name));
}


bool binary_t::write(const std::string& filename, ADDRINT target)
{
	builder_t* builder = new builder_t( target, this );

	bool returned = builder->dump_pe_to_file(filename);

	delete builder;

	return returned;
}


bool binary_t::write(const std::string& filename, std::vector<uint8_t> file_base_in_vector, std::vector<write_memory_t> file_data)
{
	builder_t* builder = new builder_t( file_base_in_vector, this );

	bool returned = builder->dump_runpe_to_file(filename, file_data, static_cast<ADDRINT>(this->optional_header_->imagebase()));

	delete builder;

	return returned;
}