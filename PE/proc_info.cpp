#include "proc_info.h"

// singleton
proc_info_t* proc_info_t::instance = nullptr;


proc_info_t* proc_info_t::get_instance()
{
	if (instance == nullptr)
		instance = new proc_info_t();

	return instance;
}


proc_info_t::proc_info_t() :
	prev_ip_{ 0 }
{}


proc_info_t::~proc_info_t() = default;


// Setters
void proc_info_t::first_instruction(ADDRINT address)
{
	first_instruction_ = address;
}


void proc_info_t::prev_ip(ADDRINT ip)
{
	prev_ip_ = ip;
}


void proc_info_t::main_img_address(ADDRINT start_address, ADDRINT end_addr)
{
	main_img.start_address = start_address;
	main_img.end_address = end_addr;
}


void proc_info_t::proc_name(std::string name)
{
	this->full_proc_name_ = name;
	
	int pos_exe_name = name.find_last_of("\\");
	string exe_name = name.substr(pos_exe_name + 1);
	exe_name = ANBU::replace_string(exe_name, " ", "");
	this->proc_name_ = exe_name.substr(0, exe_name.length() - 4);
}


// Getters
ADDRINT	proc_info_t::first_instruction()
{
	return first_instruction_;
}


ADDRINT proc_info_t::prev_ip()
{
	return prev_ip_;
}


std::string proc_info_t::proc_name()
{
	return proc_name_;
}


std::vector<ADDRINT> proc_info_t::get_jmp_black_list()
{
	return addr_jmp_blacklist;
}


std::map<std::string, heap_zone_t> proc_info_t::get_heap_map()
{
	return heap_map;
}


std::map<std::string, std::string> proc_info_t::get_dumped_hz()
{
	return heap_map_dumped;
}


// insert the mmory range in the current list of memory ranges detected on the heap
void proc_info_t::insert_heap_zone(std::string hz_md5, heap_zone_t heap_zone)
{
	heap_map.insert(std::pair<std::string, heap_zone_t>(hz_md5, heap_zone));
}


void proc_info_t::insert_dumped_heap_zone(std::string hz_data_md5, std::string hz_bin_path)
{
	heap_map_dumped.insert(std::pair<std::string, std::string>(hz_data_md5, hz_bin_path));
}


// remove a specific memory range from the heap list
void proc_info_t::delete_heap_zone(std::string md5_to_remove)
{
	heap_map.erase(md5_to_remove);
}



// return the index of the memory range that includes the specified address
// if it is not found it returns -1
bool proc_info_t::search_heap_map(ADDRINT ip)
{
	int i = 0;
	heap_zone_t hz;

	if (ip == 0x01600118)
	{
		ANBU::LOGGER_INFO("Now checking if the address is inside the heapmap\n");
	}

	for (std::map<std::string, heap_zone_t>::iterator it = heap_map.begin(); it != heap_map.end(); ++it)
	{
		hz = it->second;

		if (ip == 0x01600118)
		{
			ANBU::LOGGER_INFO("-----------Checking hz.begin= %08x - hz.end = %08x\n", hz.begin, hz.end);
		}

		if (ip >= hz.begin && ip <= hz.end)
		{
			if (ip == 0x01600118)
			{
				ANBU::LOGGER_INFO("Well, true for %08x %08x\n", hz.begin, hz.end);
			}

			return true;
		}
	}

	if (ip == 0x01600118)
	{
		ANBU::LOGGER_INFO("Well, true for %08x %08x\n", hz.begin, hz.end);
	}

	return false;
}


// Jumps
void proc_info_t::insert_in_jmp_black_list(ADDRINT ip)
{
	if(std::find(
		addr_jmp_blacklist.begin(),
		addr_jmp_blacklist.end(),
		ip
	) == addr_jmp_blacklist.end())
		addr_jmp_blacklist.push_back(ip);
}


bool proc_info_t::is_inside_jmp_black_list(ADDRINT ip)
{
	return std::find(
		addr_jmp_blacklist.begin(),
		addr_jmp_blacklist.end(),
		ip
	) != addr_jmp_blacklist.end();
}


void proc_info_t::print_heap_list()
{
	size_t cont = 1;

	for (std::map<std::string, heap_zone_t>::iterator it = heap_map.begin(); it != heap_map.end(); ++it)
	{
		heap_zone_t hz = it->second;
		ANBU::LOGGER_INFO("Heapzone number  %u  start %08x end %08x\n", cont, hz.begin, hz.end);
		cont++;
	}
}


//+++++++++++++++++++++++++++++++++++++++++++++++++++++++ Memory layout information +++++++++++++++++++++++++++++++++++++++++++++++++++++++

//--------------------------------------------------Library--------------------------------------------------------------
bool proc_info_t::is_lib_item_duplicate(uint32_t address, std::vector<library_item_t> libraries)
{
	for (std::vector<library_item_t>::iterator lib = libraries.begin(); lib != libraries.end(); ++lib)
	{
		if (address == lib->start_address)
			return true;
	}

	return false;
}


// Add library in a list sorted by address
void proc_info_t::add_library(const string name, ADDRINT start_addr, ADDRINT end_addr)
{
	library_item_t lib_item;
	lib_item.start_address	= start_addr;
	lib_item.end_address	= end_addr;
	lib_item.name			= name;

	if (is_known_library(name, start_addr, end_addr))
	{
		// check if the library is present yet in the list of known libraries
		if (!is_lib_item_duplicate(start_addr, known_libraries))
		{
			ANBU::LOGGER_INFO("Adding to known libraries: %s, Base address 0x%x -> 0x%x\n", name.c_str(), start_addr, end_addr);
			known_libraries.push_back(lib_item);
		}
		return;
	}
	else
	{
		// check if the library is present yet in the list of unknown libraries
		if (!is_lib_item_duplicate(start_addr, unknown_libraries))
		{
			ANBU::LOGGER_INFO("Adding to unknown libraries: %s, Base address 0x%x -> 0x%x\n", name.c_str(), start_addr, end_addr);
			unknown_libraries.push_back(lib_item);
		}
		return;
	}
}


// Convert a library item object to string
std::string proc_info_t::lib_to_string(library_item_t lib)
{
	std::stringstream ss;
	ss << "Library: " << lib.name;
	ss << "\t\tstart: " << std::hex << lib.start_address;
	ss << "\t\tend: " << std::hex << lib.end_address;
	const std::string s = ss.str();
	return s;
}


// Check the current name against a set ofwhitelisted library names
// the idea is not to track dlls as kernel32, but track custom dlls 
// which may contain malicious payloads
bool proc_info_t::is_known_library(const string name, ADDRINT start_addr, ADDRINT end_addr)
{
	std::string dll_path = name;

	transform(dll_path.begin(), dll_path.end(), dll_path.begin(), ::tolower);

	bool is_system_dll = (dll_path.find("c:\\windows\\system32") == 0) || 
						 (dll_path.find("c:\\windows\\syswow64") == 0);

	if (is_system_dll)
	{
		return true;
	}
	else
	{
		ANBU::LOGGER_INFO("Found Unknown library %s from %08x  to   %08x: start tracking its instruction\n", name.c_str(), start_addr, end_addr);
		return false;
	}
}


// Check if the address belong to a Library
bool proc_info_t::is_library_instruction(ADDRINT addr)
{
	// check inside of known libraries
	for (std::vector<library_item_t>::iterator lib = known_libraries.begin(); lib != known_libraries.end(); ++lib)
	{
		if (lib->start_address <= addr && addr <= lib->end_address)
		{
			return true;
		}
	}

	// check inside unknown libraries
	for (std::vector<library_item_t>::iterator lib = unknown_libraries.begin(); lib != unknown_libraries.end(); ++lib)
	{
		if (lib->start_address <= addr && addr <= lib->end_address)
		{
			return true;
		}
	}

	return false;
}


bool proc_info_t::is_known_library_instruction(ADDRINT addr)
{
	for (std::vector<library_item_t>::iterator lib = known_libraries.begin(); lib != known_libraries.end(); ++lib)
	{
		if (lib->start_address <= addr && addr <= lib->end_address)
		{
			return true;
		}
	}
	return false;
}


void proc_info_t::add_proc_addresses()
{
	set_current_mapped_files();
	add_peb_address();
	add_context_data_address();
	add_code_page_data_address();
	add_shared_memory_address();
	add_process_heap_and_check_address(NULL);
	add_pshim_data_address();
	add_api_set_map_address();
	add_kuser_shared_data_address();
}


//------------------------------------------------------------PEB------------------------------------------------------------
void proc_info_t::add_peb_address()
{
	typedef int (WINAPI * ZwQueryInformationProcess)(WINDOWS::HANDLE,
		WINDOWS::DWORD,
		WINDOWS::PROCESS_BASIC_INFORMATION*,
		WINDOWS::DWORD,
		WINDOWS::DWORD*);

	ZwQueryInformationProcess MyZwQueryInformationProcess;
	WINDOWS::PROCESS_BASIC_INFORMATION tmppeb;
	WINDOWS::DWORD tmp;
	WINDOWS::HMODULE hMod = WINDOWS::GetModuleHandleA("ntdll.dll");
	MyZwQueryInformationProcess = reinterpret_cast<ZwQueryInformationProcess>(WINDOWS::GetProcAddress(hMod, "ZwQueryInformationProcess"));
	MyZwQueryInformationProcess(WINDOWS::GetCurrentProcess(), 0, &tmppeb, sizeof(WINDOWS::PROCESS_BASIC_INFORMATION), &tmp);
	peb = reinterpret_cast<PEB*>(tmppeb.PebBaseAddress);
	ANBU::LOGGER_INFO("PEB added from %08x -> %08x\n", peb, peb + sizeof(PEB));
}


bool proc_info_t::is_peb_address(ADDRINT addr)
{
	return (reinterpret_cast<ADDRINT>(peb) <= addr && addr <= reinterpret_cast<ADDRINT>(peb) + sizeof(PEB));
}


void proc_info_t::print_peb_information()
{
	ANBU::LOGGER_INFO("PEB address: 0x%p\n", peb);
	ANBU::LOGGER_INFO("PEB IsBeingDebugged: %s\n", ((peb->BeingDebugged == 1) ? "true" : "false"));
}


void proc_info_t::process_not_being_debugged()
{
	peb->BeingDebugged = 0;
}
//------------------------------------------------------------TEB------------------------------------------------------------
void proc_info_t::add_thread_teb_address()
{
	WINDOWS::_TEB *teb_addr = WINDOWS::NtCurrentTeb();
	memory_range_t cur_teb;
	cur_teb.start_address = reinterpret_cast<ADDRINT>(teb_addr);
	cur_teb.end_address   = reinterpret_cast<ADDRINT>(teb_addr + TEB_SIZE);
	tebs.push_back(cur_teb);
}


bool proc_info_t::is_teb_address(ADDRINT addr)
{
	for (std::vector<memory_range_t>::iterator it = tebs.begin(); it != tebs.end(); ++it)
	{
		if (it->start_address <= addr && addr <= it->end_address)
		{
			return true;
		}
	}

	return false;
}


//------------------------------------------------------------ Stack ------------------------------------------------------------
// Check if an address is on the stack
bool proc_info_t::is_stack_address(ADDRINT addr)
{
	for (std::vector<memory_range_t>::iterator it = stacks.begin(); it != stacks.end(); ++it)
	{
		if (it->start_address <= addr && addr <= it->end_address)
		{
			return true;
		}
	}

	return false;
}


// Initializing the base stack address by getting a value in the stack and searching the highest allocated address in the same memory region
void proc_info_t::add_thread_stack_address(ADDRINT addr)
{
	memory_range_t stack;
	WINDOWS::MEMORY_BASIC_INFORMATION mbi;
	int num_bytes = WINDOWS::VirtualQuery(reinterpret_cast<WINDOWS::LPCVOID>(addr), &mbi, sizeof(mbi));

	if (num_bytes == 0)
	{
		ANBU::LOGGER_ERROR("VirtualQuery failed\n");
		return;
	}

	if (mbi.State == MEM_COMMIT || mbi.Type == MEM_PRIVATE)
	{
		stack.end_address = reinterpret_cast<ADDRINT>(mbi.BaseAddress) + static_cast<ADDRINT>(mbi.RegionSize);
	}
	else
	{
		stack.end_address = addr;
	}

	// check integer underflow ADDRINT
	if (stack.end_address <= MAX_STACK_SIZE)
	{
		stack.start_address = 0;
	}
	else
	{
		stack.start_address = stack.end_address - MAX_STACK_SIZE;
	}

	ANBU::LOGGER_INFO("Init Stacks by adding from %x to %x\n", stack.start_address, stack.end_address);
	stacks.push_back(stack);
}


/**
Fill the MemoryRange passed as parameter with the startAddress and EndAddress of the memory location in which the address is contained
ADDRINT address:  address of which we want to retrieve the memory region
MemoryRange& range: MemoryRange which will be filled
return TRUE if the address belongs to a memory mapped area otherwise return FALSE
**/
bool proc_info_t::get_memory_range(ADDRINT address, memory_range_t& range)
{
	WINDOWS::MEMORY_BASIC_INFORMATION mbi;
	int num_bytes = WINDOWS::VirtualQuery(reinterpret_cast<WINDOWS::LPCVOID>(address), &mbi, sizeof(mbi));

	if (num_bytes == 0)
	{
		ANBU::LOGGER_ERROR("VirtualQuery failed\n");
		return false;
	}

	ADDRINT start = reinterpret_cast<ADDRINT>(mbi.BaseAddress);
	ADDRINT end = reinterpret_cast<ADDRINT>(mbi.BaseAddress) + static_cast<ADDRINT>(mbi.RegionSize);
	// get the stack base address by searching the highest address in the allocated memory containing the stack Address
	if ((mbi.State == MEM_COMMIT || mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE || mbi.Type == MEM_PRIVATE) &&
		start <= address && address <= end)
	{
		range.start_address = start;
		range.end_address = end;
		return true;
	}
	else
	{
		ANBU::LOGGER_ERROR("Address %08x  not inside mapped memory from %08x -> %08x or Type/State not correct\n", address, start, end);
		ANBU::LOGGER_INFO("state %08x   %08x\n", mbi.State, mbi.Type);
		return false;
	}
}


//----------------------------- Know memory regions to whitelist(Functions for FakeMemoryReader) -------------

//------------------------------------------------------------ Memory Mapped Files------------------------------------------------------------

//Add to the mapped files list the region marked as mapped when the application starts
void proc_info_t::set_current_mapped_files()
{
	WINDOWS::MEMORY_BASIC_INFORMATION mbi;
	WINDOWS::SIZE_T num_bytes;
	WINDOWS::DWORD my_address = 0;
	// delete old elements
	mapped_files.clear();

	do
	{
		num_bytes = WINDOWS::VirtualQuery(reinterpret_cast<WINDOWS::LPCVOID>(my_address), &mbi, sizeof(mbi));

		if (num_bytes == 0)
		{
			ANBU::LOGGER_ERROR("VirtualQuery failed\n");
			return;
		}

		if (mbi.Type == MEM_MAPPED)
		{
			memory_range_t range;
			range.start_address = reinterpret_cast<ADDRINT>(mbi.BaseAddress);
			range.end_address = reinterpret_cast<ADDRINT>(mbi.BaseAddress) + static_cast<ADDRINT>(mbi.RegionSize);
			mapped_files.push_back(range);
		}

		my_address += mbi.RegionSize;
	} while (num_bytes);
}


bool proc_info_t::is_mapped_file_address(ADDRINT addr)
{
	for (std::vector<memory_range_t>::iterator it = mapped_files.begin(); it != mapped_files.end(); ++it)
	{
		if (it->start_address <= addr && addr <= it->end_address)
		{
			return true;
		}
	}
	return false;
}

void proc_info_t::print_mapped_file_address()
{
	for (std::vector<memory_range_t>::iterator it = mapped_files.begin(); it != mapped_files.end(); ++it)
	{
		ANBU::LOGGER_INFO("Mapped file %08x -> %08x\n", it->start_address, it->end_address);
	}
}


//Add dynamically created mapped files to the mapped files list
void proc_info_t::add_mapped_files_address(ADDRINT start_addr)
{
	memory_range_t mapped_file;

	if (get_memory_range(start_addr, mapped_file))
	{
		ANBU::LOGGER_INFO("Adding mappedFile base address  %08x -> %08x\n", mapped_file.start_address, mapped_file.end_address);
		mapped_files.push_back(mapped_file);
	}
}


//------------------------------------------------------------ Other Memory Location ------------------------------------------------------------
bool proc_info_t::is_generic_memory_address(ADDRINT address)
{
	for (std::vector<memory_range_t>::iterator item = generic_memory_ranges.begin(); item != generic_memory_ranges.end(); ++item)
	{
		if (item->start_address <= address && address <= item->end_address)
		{
			return true;
		}
	}
	return false;
}


// Adding the ContextData to the generic Memory Ranges
void proc_info_t::add_context_data_address()
{
	memory_range_t activation_context_data;
	memory_range_t system_default_activation_context_data;
	memory_range_t p_context_data;

	if (get_memory_range(reinterpret_cast<ADDRINT>(peb->ActivationContextData), activation_context_data))
	{
		ANBU::LOGGER_INFO("Init activationContextData base address  %08x -> %08x\n", activation_context_data.start_address, activation_context_data.end_address);
		generic_memory_ranges.push_back(activation_context_data);
	}

	if (get_memory_range(reinterpret_cast<ADDRINT>(peb->SystemDefaultActivationContextData), system_default_activation_context_data))
	{
		ANBU::LOGGER_INFO("Init systemDefaultActivationContextData base address  %08x -> %08x\n", system_default_activation_context_data.start_address, system_default_activation_context_data.end_address);
		generic_memory_ranges.push_back(system_default_activation_context_data);
	}

	if (get_memory_range(reinterpret_cast<ADDRINT>(peb->pContextData), p_context_data))
	{
		ANBU::LOGGER_INFO("Init pContextData base address  %08x -> %08x\n", p_context_data.start_address, p_context_data.end_address);
		generic_memory_ranges.push_back(p_context_data);
	}
}


// Adding the Shared Memory Address to the generic memory ranges
void proc_info_t::add_shared_memory_address()
{
	memory_range_t read_only_shared_memory_base;

	if (get_memory_range(reinterpret_cast<ADDRINT>(peb->ReadOnlySharedMemoryBase), read_only_shared_memory_base))
	{
		ANBU::LOGGER_INFO("Init readOnlySharedMemoryBase base address  %08x -> %08x\n", read_only_shared_memory_base.start_address, read_only_shared_memory_base.end_address);
		generic_memory_ranges.push_back(read_only_shared_memory_base);
	}
}


//Adding the codepagedataaddress to the generic memory ranges
void proc_info_t::add_code_page_data_address()
{
	memory_range_t ansi_code_page_data;

	if (get_memory_range(reinterpret_cast<ADDRINT>(peb->AnsiCodePageData), ansi_code_page_data))
	{
		ANBU::LOGGER_INFO("Init ansiCodePageData base address  %08x -> %08x\n", ansi_code_page_data.start_address, ansi_code_page_data.end_address);
		generic_memory_ranges.push_back(ansi_code_page_data);
	}
}


//Adding the pShimDataAddress to the generic memory ranges
void proc_info_t::add_pshim_data_address()
{
	memory_range_t pshim_data;
	if (get_memory_range(reinterpret_cast<ADDRINT>(peb->pShimData), pshim_data))
	{
		ANBU::LOGGER_INFO("Init PShim data address  %08x -> %08x\n", pshim_data.start_address, pshim_data.end_address);
		generic_memory_ranges.push_back(pshim_data);
	}
}


//Adding Api Set Map to the generic memory ranges
void proc_info_t::add_api_set_map_address()
{
	memory_range_t api_set_map;
	if (get_memory_range(reinterpret_cast<ADDRINT>(peb->ApiSetMap), api_set_map))
	{
		ANBU::LOGGER_INFO("Init ApiSetMap base address  %08x -> %08x\n", api_set_map.start_address, api_set_map.end_address);
		generic_memory_ranges.push_back(api_set_map);
	}
}


//Add to the generic memory ranges the KUserShareData structure
void proc_info_t::add_kuser_shared_data_address()
{
	memory_range_t KUser_shared_data;
	KUser_shared_data.start_address = KUSER_SHARED_DATA_ADDRESS;
	KUser_shared_data.end_address = KUSER_SHARED_DATA_ADDRESS + KUSER_SHARED_DATA_SIZE;
	generic_memory_ranges.push_back(KUser_shared_data);
}


//Adding the ProcessHeaps to the generic Memory Ranges
bool proc_info_t::add_process_heap_and_check_address(ADDRINT eip)
{
	bool is_eip_discovered_here = false;
	WINDOWS::SIZE_T bytes_to_allocate;
	WINDOWS::PHANDLE a_heaps;
	// getting the number of process heaps
	WINDOWS::DWORD number_of_heaps = WINDOWS::GetProcessHeaps(0, NULL);

	if (!number_of_heaps)
	{
		ANBU::LOGGER_ERROR("Error in retrieving number of Process Heaps\n");
		return is_eip_discovered_here;
	}

	// Allocating space for the processheaps addresses
	WINDOWS::SIZETMult(number_of_heaps, sizeof(*a_heaps), &bytes_to_allocate);
	a_heaps = reinterpret_cast<WINDOWS::PHANDLE>(WINDOWS::HeapAlloc(WINDOWS::GetProcessHeap(), 0, bytes_to_allocate));

	if (a_heaps == NULL)
	{
		ANBU::LOGGER_ERROR("HeapAlloc failed to allocate space\n");
		return is_eip_discovered_here;
	}

	WINDOWS::GetProcessHeaps(number_of_heaps, a_heaps);
	//Adding the memory range containing the process heaps to the generic memory ranges
	for (size_t i = 0; i < number_of_heaps; i++)
	{
		memory_range_t process_heap;
		if (get_memory_range(reinterpret_cast<ADDRINT>(a_heaps[i]), process_heap))
		{
			generic_memory_ranges.push_back(process_heap);
			
			if (eip >= process_heap.start_address && eip <= process_heap.end_address)
			{
				is_eip_discovered_here = true;
			}
		}
	}

	return is_eip_discovered_here;
}


//-------------------------- Anti process fingerprint --------------
bool proc_info_t::is_interesting_process(unsigned int pid)
{
	return std::find(
		interesting_processes_pid.begin(),
		interesting_processes_pid.end(),
		pid
	) != interesting_processes_pid.end();
}

// print the whitelisted memory in a fancy way
void proc_info_t::print_white_listed_addr()
{
	// Iterate through the already whitelisted memory addresses
	for (std::vector<memory_range_t>::iterator item = generic_memory_ranges.begin(); item != generic_memory_ranges.end(); ++item)
	{
		ANBU::LOGGER("[MEMORY RANGE]Whitelisted  %08x  ->  %08x\n", item->start_address, item->end_address);
	}

	for (std::map<std::string, heap_zone_t>::iterator it = heap_map.begin(); it != heap_map.end(); ++it)
	{
		heap_zone_t hz = it->second;
		ANBU::LOGGER("[HEAPZONES]Whitelisted  %08x  ->  %08x\n", hz.begin, hz.end);
	}

	for (std::vector<library_item_t>::iterator item = unknown_libraries.begin(); item != unknown_libraries.end(); ++item)
	{
		ANBU::LOGGER("[UNKNOWN LIBRARY ITEM]Whitelisted  %08x  ->  %08x\n", item->start_address, item->end_address);
	}

	for (std::vector<library_item_t>::iterator item = known_libraries.begin(); item != known_libraries.end(); ++item)
	{
		ANBU::LOGGER("[KNOWN LIBRARY ITEM]Whitelisted  %08x  ->  %08x\n", item->start_address, item->end_address);
	}

	for (std::vector<memory_range_t>::iterator item = this->mapped_files.begin(); item != mapped_files.end(); ++item)
	{
		ANBU::LOGGER("[MAPPED FILES]Whitelisted  %08x  ->  %08x\n", item->start_address, item->end_address);
	}
}