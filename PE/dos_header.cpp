#include "dos_header.h"

namespace pe_parser
{
	dos_header_t::dos_header_t(const pe_dos_header* dos_header_address) : 
		magic_{ dos_header_address->Magic },
		usedBytesInTheLastPage_{ dos_header_address->UsedBytesInTheLastPage },
		fileSizeInPages_{ dos_header_address->FileSizeInPages },
		numberOfRelocation_{ dos_header_address->NumberOfRelocationItems },
		headerSizeInParagraphs_{ dos_header_address->HeaderSizeInParagraphs },
		minimumExtraParagraphs_{ dos_header_address->MinimumExtraParagraphs },
		maximumExtraParagraphs_{ dos_header_address->MaximumExtraParagraphs },
		initialRelativeSS_{ dos_header_address->InitialRelativeSS },
		initialSP_{ dos_header_address->InitialSP },
		checksum_{ dos_header_address->Checksum },
		initialIP_{ dos_header_address->InitialIP },
		initialRelativeCS_{ dos_header_address->InitialRelativeCS },
		addressOfRelocationTable_{ dos_header_address->AddressOfRelocationTable },
		overlayNumber_{ dos_header_address->OverlayNumber },
		oEMid_{ dos_header_address->OEMid },
		oEMinfo_{ dos_header_address->OEMinfo },
		addressOfNewExeHeader_{ dos_header_address->AddressOfNewExeHeader }
	{
		size_t copied_size, size_to_copy = sizeof(dos_header_address->Reserved);
		dos_header_correct = true;

		copied_size = PIN_SafeCopy((VOID*)&this->reserved_, (const VOID*)dos_header_address->Reserved, size_to_copy);

		if (copied_size != size_to_copy)
		{
			dos_header_correct = false;
			return;
		}

		size_to_copy = sizeof(dos_header_address->Reserved2);

		copied_size = PIN_SafeCopy((VOID*)&this->reserved2_, (const VOID*)dos_header_address->Reserved2, size_to_copy);

		if (copied_size != size_to_copy)
		{
			dos_header_correct = false;
			return;
		}

		if (magic_ != mz_signature)
			dos_header_correct = false;
	}

	bool dos_header_t::check_dos_header()
	{
		return dos_header_correct;
	}

	/******** GETTERS *********/
	pe_dos_header dos_header_t::dos_header(void) const
	{
		/*
		*	This part corresponds to LIEF builder:
			Builder& Builder::operator<<(const DosHeader& dos_header) {

			  pe_dos_header dosHeader;
			  dosHeader.Magic                     = static_cast<uint16_t>(dos_header.magic());
			  dosHeader.UsedBytesInTheLastPage    = static_cast<uint16_t>(dos_header.used_bytes_in_the_last_page());
			  dosHeader.FileSizeInPages           = static_cast<uint16_t>(dos_header.file_size_in_pages());
			  dosHeader.NumberOfRelocationItems   = static_cast<uint16_t>(dos_header.numberof_relocation());
			  dosHeader.HeaderSizeInParagraphs    = static_cast<uint16_t>(dos_header.header_size_in_paragraphs());
			  dosHeader.MinimumExtraParagraphs    = static_cast<uint16_t>(dos_header.minimum_extra_paragraphs());
			  dosHeader.MaximumExtraParagraphs    = static_cast<uint16_t>(dos_header.maximum_extra_paragraphs());
			  dosHeader.InitialRelativeSS         = static_cast<uint16_t>(dos_header.initial_relative_ss());
			  dosHeader.InitialSP                 = static_cast<uint16_t>(dos_header.initial_sp());
			  dosHeader.Checksum                  = static_cast<uint16_t>(dos_header.checksum());
			  dosHeader.InitialIP                 = static_cast<uint16_t>(dos_header.initial_ip());
			  dosHeader.InitialRelativeCS         = static_cast<uint16_t>(dos_header.initial_relative_cs());
			  dosHeader.AddressOfRelocationTable  = static_cast<uint16_t>(dos_header.addressof_relocation_table());
			  dosHeader.OverlayNumber             = static_cast<uint16_t>(dos_header.overlay_number());
			  dosHeader.OEMid                     = static_cast<uint16_t>(dos_header.oem_id());
			  dosHeader.OEMinfo                   = static_cast<uint16_t>(dos_header.oem_info());
			  dosHeader.AddressOfNewExeHeader     = static_cast<uint16_t>(dos_header.addressof_new_exeheader());

			  const DosHeader::reserved_t& reserved   = dos_header.reserved();
			  const DosHeader::reserved2_t& reserved2 = dos_header.reserved2();

			  std::copy(std::begin(reserved),  std::end(reserved),  std::begin(dosHeader.Reserved));
			  std::copy(std::begin(reserved2), std::end(reserved2), std::begin(dosHeader.Reserved2));

			  this->ios_.seekp(0);
			  this->ios_.write(reinterpret_cast<const uint8_t*>(&dosHeader), sizeof(pe_dos_header));
			  if (this->dos_stub().size() > 0 and this->build_dos_stub_) {

				if (sizeof(pe_dos_header) + this->dos_stub().size() > dos_header.addressof_new_exeheader()) {
				  LOG(WARNING) << "Inconsistent 'addressof_new_exeheader' (0x" << std::hex << dos_header.addressof_new_exeheader();
				}
				this->ios_.write(this->dos_stub());
			  }

			  return *this;
			}
		*/
		pe_dos_header dos_header;

		dos_header.Magic						= this->magic_;
		dos_header.UsedBytesInTheLastPage		= this->usedBytesInTheLastPage_;
		dos_header.FileSizeInPages				= this->fileSizeInPages_;
		dos_header.NumberOfRelocationItems		= this->numberOfRelocation_;
		dos_header.HeaderSizeInParagraphs		= this->headerSizeInParagraphs_;
		dos_header.MinimumExtraParagraphs		= this->minimumExtraParagraphs_;
		dos_header.MaximumExtraParagraphs		= this->maximumExtraParagraphs_;
		dos_header.InitialRelativeSS			= this->initialRelativeSS_;
		dos_header.InitialSP					= this->initialSP_;
		dos_header.Checksum						= this->checksum_;
		dos_header.InitialIP					= this->initialIP_;
		dos_header.InitialRelativeCS			= this->initialRelativeCS_;
		dos_header.AddressOfRelocationTable		= this->addressOfRelocationTable_;
		dos_header.OverlayNumber				= this->overlayNumber_;

		memcpy(dos_header.Reserved, this->reserved_, 4);

		dos_header.OEMid						= this->oEMid_;
		dos_header.OEMinfo						= this->oEMinfo_;

		memcpy(dos_header.Reserved2, this->reserved2_, 10);

		dos_header.AddressOfNewExeHeader		= this->addressOfNewExeHeader_;

		return dos_header;
	}


	uint16_t dos_header_t::magic(void) const 
	{
		return this->magic_;
	}


	uint16_t dos_header_t::used_bytes_in_the_last_page(void) const 
	{
		return this->usedBytesInTheLastPage_;
	}


	uint16_t dos_header_t::file_size_in_pages(void) const 
	{
		return this->fileSizeInPages_;
	}


	uint16_t dos_header_t::numberof_relocation(void) const 
	{
		return this->numberOfRelocation_;
	}


	uint16_t dos_header_t::header_size_in_paragraphs(void) const 
	{
		return this->headerSizeInParagraphs_;
	}


	uint16_t dos_header_t::minimum_extra_paragraphs(void) const 
	{
		return this->minimumExtraParagraphs_;
	}


	uint16_t dos_header_t::maximum_extra_paragraphs(void) const 
	{
		return this->maximumExtraParagraphs_;
	}


	uint16_t dos_header_t::initial_relative_ss(void) const 
	{
		return this->initialRelativeSS_;
	}


	uint16_t dos_header_t::initial_sp(void) const 
	{
		return this->initialSP_;
	}


	uint16_t dos_header_t::checksum(void) const 
	{
		return this->checksum_;
	}


	uint16_t dos_header_t::initial_ip(void) const 
	{
		return this->initialIP_;
	}


	uint16_t dos_header_t::initial_relative_cs(void) const 
	{
		return this->initialRelativeCS_;
	}


	uint16_t dos_header_t::addressof_relocation_table(void) const 
	{
		return this->addressOfRelocationTable_;
	}


	uint16_t dos_header_t::overlay_number(void) const 
	{
		return this->overlayNumber_;
	}


	uint16_t dos_header_t::reserved(size_t field) const 
	{
		if (field >= 4)
			return 0;
		return this->reserved_[field];
	}


	uint16_t dos_header_t::oem_id(void) const 
	{
		return this->oEMid_;
	}


	uint16_t dos_header_t::oem_info(void) const 
	{
		return this->oEMinfo_;
	}


	uint16_t dos_header_t::reserved2(size_t field) const 
	{
		if (field >= 10)
			return 0;

		return this->reserved2_[field];
	}


	uint32_t dos_header_t::addressof_new_exeheader(void) const 
	{
		return this->addressOfNewExeHeader_;
	}

	/********** Setters *************/
	void dos_header_t::magic(uint16_t magic) {
		this->magic_ = magic;
	}


	void dos_header_t::used_bytes_in_the_last_page(uint16_t usedBytesInTheLastPage) {
		this->usedBytesInTheLastPage_ = usedBytesInTheLastPage;
	}


	void dos_header_t::file_size_in_pages(uint16_t fileSizeInPages) {
		this->fileSizeInPages_ = fileSizeInPages;
	}


	void dos_header_t::numberof_relocation(uint16_t numberOfRelocation) {
		this->numberOfRelocation_ = numberOfRelocation;
	}


	void dos_header_t::header_size_in_paragraphs(uint16_t headerSizeInParagraphs) {
		this->headerSizeInParagraphs_ = headerSizeInParagraphs;
	}


	void dos_header_t::minimum_extra_paragraphs(uint16_t minimumExtraParagraphs) {
		this->minimumExtraParagraphs_ = minimumExtraParagraphs;
	}


	void dos_header_t::maximum_extra_paragraphs(uint16_t maximumExtraParagraphs) {
		this->maximumExtraParagraphs_ = maximumExtraParagraphs;
	}


	void dos_header_t::initial_relative_ss(uint16_t initialRelativeSS) {
		this->initialRelativeSS_ = initialRelativeSS;
	}


	void dos_header_t::initial_sp(uint16_t initialSP) {
		this->initialSP_ = initialSP;
	}


	void dos_header_t::checksum(uint16_t checksum) {
		this->checksum_ = checksum;
	}


	void dos_header_t::initial_ip(uint16_t initialIP) {
		this->initialIP_ = initialIP;
	}


	void dos_header_t::initial_relative_cs(uint16_t initialRelativeCS) {
		this->initialRelativeCS_ = initialRelativeCS;
	}


	void dos_header_t::addressof_relocation_table(uint16_t addressOfRelocationTable) {
		this->addressOfRelocationTable_ = addressOfRelocationTable;
	}


	void dos_header_t::overlay_number(uint16_t overlayNumber) {
		this->overlayNumber_ = overlayNumber;
	}


	void dos_header_t::reserved(const uint16_t* reserved) {
		size_t i;
		
		for (i = 0; i < 4; i++)
			this->reserved_[i] = reserved[i];
	}


	void dos_header_t::oem_id(uint16_t oEMid) {
		this->oEMid_ = oEMid;
	}


	void dos_header_t::oem_info(uint16_t oEMinfo) {
		this->oEMinfo_ = oEMinfo;
	}


	void dos_header_t::reserved2(const uint16_t* reserved2) {
		size_t i;
		
		for (i = 0; i < 10; i++)
			this->reserved2_[i] = reserved2[i];
	}


	void dos_header_t::addressof_new_exeheader(uint32_t addressOfNewExeHeader) {
		this->addressOfNewExeHeader_ = addressOfNewExeHeader;
	}


	bool dos_header_t::dump_dos_header(FILE *file_to_dump)
	{
		if (!dos_header_correct)
			return false;
		fprintf(file_to_dump, "================== DUMP DOS HEADER ===================\n");
		fprintf(file_to_dump, "\t+Magic: 0x%x\n", magic_);
		fprintf(file_to_dump, "\t+Used Bytes In The LastPage: 0x%x\n", usedBytesInTheLastPage_);
		fprintf(file_to_dump, "\t+File Size In Pages: 0x%x\n", fileSizeInPages_);
		fprintf(file_to_dump, "\t+Number Of Relocation: 0x%x\n", numberOfRelocation_);
		fprintf(file_to_dump, "\t+Header Size In Paragraphs: 0x%x\n", headerSizeInParagraphs_);
		fprintf(file_to_dump, "\t+Minimum Extra Paragraphs: 0x%x\n", minimumExtraParagraphs_);
		fprintf(file_to_dump, "\t+Maximum Extra Paragraphs: 0x%x\n", maximumExtraParagraphs_);
		fprintf(file_to_dump, "\t+Initial Relative SS: 0x%x\n", initialRelativeSS_);
		fprintf(file_to_dump, "\t+Initial SP: 0x%x\n", initialSP_);
		fprintf(file_to_dump, "\t+Checksum: 0x%x\n", checksum_);
		fprintf(file_to_dump, "\t+Initial IP: 0x%x\n", initialIP_);
		fprintf(file_to_dump, "\t+Initial Relative CS: 0x%x\n", initialRelativeCS_);
		fprintf(file_to_dump, "\t+Address Of Relocation Table: 0x%x\n", addressOfRelocationTable_);
		fprintf(file_to_dump, "\t+Overlay Number: 0x%x\n", overlayNumber_);
		fprintf(file_to_dump, "\t+OEM id: 0x%x\n", oEMid_);
		fprintf(file_to_dump, "\t+OEM info: 0x%x\n", oEMinfo_);
		fprintf(file_to_dump, "\t+Address Of New Exe Header: 0x%x\n", addressOfNewExeHeader_);

		return true;
	}
}