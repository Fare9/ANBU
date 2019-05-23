#pragma once
#ifndef PROC_INFO_H
#define PROC_INFO_H

#include "common.h"
#include "utils.h"


#define MAX_STACK_SIZE				0x100000
#define TEB_SIZE					0xFE0
#define KUSER_SHARED_DATA_ADDRESS	0x7FFE0000
#define KUSER_SHARED_DATA_SIZE		0x3E0


typedef struct PEB {
	WINDOWS::BYTE padding1[2];
	WINDOWS::BYTE BeingDebugged;
	WINDOWS::BYTE padding2[53];
	WINDOWS::PVOID ApiSetMap;
	WINDOWS::BYTE padding3[16];
	WINDOWS::PVOID ReadOnlySharedMemoryBase;
	WINDOWS::BYTE padding4[8];
	WINDOWS::PVOID AnsiCodePageData;
	WINDOWS::BYTE padding5[52];
	WINDOWS::PVOID ProcessHeaps;
	WINDOWS::PVOID GdiSharedHandleTable;
	WINDOWS::BYTE padding6[336];
	WINDOWS::PVOID pShimData;
	WINDOWS::BYTE padding7[12];
	WINDOWS::PVOID ActivationContextData;
	WINDOWS::BYTE padding8[4];
	WINDOWS::PVOID SystemDefaultActivationContextData;
	WINDOWS::BYTE padding9[52];
	WINDOWS::PVOID pContextData;
	WINDOWS::BYTE padding10[4];
}PEB;


struct memory_range_t
{
	ADDRINT start_address;
	ADDRINT end_address;
};


// Struct that will track library loaded at program startup
struct library_item_t
{
	ADDRINT		start_address;
	ADDRINT		end_address;
	std::string name;
};


struct heap_zone_t
{
	ADDRINT		begin;
	ADDRINT		end;
	uint32_t	size;
	uint32_t	version;
};


class proc_info_t
{
public:

	proc_info_t();
	~proc_info_t();

	// singleton
	static proc_info_t*							get_instance();

	// Setters
	void									add_proc_addresses();
	void									first_instruction(ADDRINT first_instruction);
	void									prev_ip(ADDRINT prev_ip);
	void									main_img_address(ADDRINT start_address, ADDRINT end_addr);
	void									proc_name(std::string name);

	// Getters
	ADDRINT									first_instruction();
	ADDRINT									prev_ip();
	std::string								proc_name();
	std::vector<ADDRINT>					get_jmp_black_list();
	ADDRINT									get_pin_vm_start();
	ADDRINT									get_pin_vm_end();
	std::map<std::string, heap_zone_t>		get_heap_map();
	std::map<std::string, std::string>		get_dumped_hz();

	// debug
	void									print_start_context();
	void									print_curr_context();
	void									print_heap_list();

	// helper
	void									insert_heap_zone(std::string hz_data_md5, heap_zone_t heap_zone);
	void									insert_dumped_heap_zone(std::string hz_data_md5, std::string hz_bin_path);
	void									delete_heap_zone(std::string md5_to_remove);
	bool									search_heap_map(ADDRINT ip);
	heap_zone_t*							get_heap_zone_by_index(size_t index);
	std::vector<heap_zone_t>				get_while_list_heap();
	void									insert_in_jmp_black_list(ADDRINT ip);
	bool									is_inside_jmp_black_list(ADDRINT ip);
	
	//Whitelisted memory (functions for FakeMemoryReader)
	//PEB
	void									print_peb_information();
	bool									is_peb_address(ADDRINT addr);
	void									process_not_being_debugged();
	//TEB
	bool									is_teb_address(ADDRINT addr);
	void									add_thread_teb_address();
	//Stack
	bool									is_stack_address(ADDRINT addr);
	void									add_thread_stack_address(ADDRINT addr);
	//Library
	bool									is_library_instruction(ADDRINT addr);
	bool									is_known_library_instruction(ADDRINT addr);
	void									add_library(const string name, ADDRINT start_addr, ADDRINT end_addr);
	bool									is_lib_item_duplicate(uint32_t address, std::vector<library_item_t> libraries);

	bool									get_memory_range(ADDRINT address, memory_range_t& range);
	bool									add_process_heap_and_check_address(ADDRINT address);

	//Memory mapped files
	bool									is_mapped_file_address(ADDRINT addr);
	void									add_mapped_files_address(ADDRINT start_addr);
	void									set_current_mapped_files();
	void									print_mapped_file_address();

	//Generic Address
	bool									is_generic_memory_address(ADDRINT address);
	void									print_white_listed_addr();

	//Process Fingerprint
	bool									is_interesting_process(unsigned int pin);
private:
	static proc_info_t*						instance;
	ADDRINT									first_instruction_;
	ADDRINT									prev_ip_;
	std::vector<std::string>				interesting_processes_name;
	std::vector<uint32_t>					interesting_processes_pid;
	std::vector<memory_range_t>				stacks;	// Set of Stack
	memory_range_t							main_img;
	std::vector<memory_range_t>				tebs;
	std::vector<memory_range_t>				generic_memory_ranges;
	std::vector<memory_range_t>				mapped_files;
	PEB*									peb;
	std::map<std::string, heap_zone_t>		heap_map;
	std::vector<heap_zone_t>				white_list_heap;
	std::map<std::string, std::string>		heap_map_dumped;
	std::vector<ADDRINT>					addr_jmp_blacklist;
	std::vector<library_item_t>				known_libraries;
	std::vector<library_item_t>				unknown_libraries;

	std::string								full_proc_name_;
	std::string								proc_name_;
	// Enumerate whitelisted memory helpers
	// return the memory_range_t in which the address is mapped
	bool									is_known_library(const std::string name, ADDRINT start_addr, ADDRINT end_addr);
	void									add_peb_address();
	void									add_context_data_address();
	void									add_shared_memory_address();
	void									add_code_page_data_address();
	void									add_pshim_data_address();
	void									add_api_set_map_address();
	void									add_kuser_shared_data_address();
	// Library Helpers
	std::string								lib_to_string(library_item_t lib);
};

#endif // !PROC_INFO_H
