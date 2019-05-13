
#include "memory_movement_detection.h"

/************* EXTERN VARIABLES *************/
extern FILE*									logfile;			// log file handler
extern ADDRINT									main_base_address;	// main base address of binary, to start
																// reading PE file	
extern std::vector<dll_import_struct_t*>		dll_imports;
extern bool										check_first_thunk;
extern binary_t*								pe_file;
extern std::string								unpacked_file_name;
/******************* Data for the unpacker *******************/
ADDRINT											saved_addr;			// temporary variable needed for storing state between
																	// two analysis routines
bool											any_import_resolved = false;

bool											header_modified = false;

w_xor_x_heuristic_t								w_xor_x_heuristic;

pushad_popad_heuristic_t						pushad_popad_heuristic;
/******************* Variables for dump *******************/
lief_import_t*									library;
import_entry_t*									function;


/******************* Functions for the unpacker *******************/

void fini()
/*
*   Function that will be executed at the end
*   of the execution or when PIN detachs from
*   the process.
*/
{
	fprintf(stderr, "------ unpacking complete ------\n");
	fprintf(logfile, "------ unpacking complete ------\n");

	// save final log and close file
	fprintf(stderr, "------ end log ------\n");
	fprintf(logfile, "------ end log ------\n");
	fclose(logfile);
}

void instrument_mem_cflow(INS ins, void *v)
/*
*   Function to instrument each instruction
*   we will use this function to record the
*   written memory, and the jumps to those
*   memory.
*/
{
	if (INS_IsMemoryWrite(ins)      
		&& INS_hasKnownMemorySize(ins))
	{
		// this first three callbacks will be used for tracking memory writes

		INS_InsertPredicatedCall(
			ins,
			IPOINT_BEFORE,              
			(AFUNPTR)queue_memwrite,	
			IARG_MEMORYWRITE_EA,        
			IARG_END                    
		);


		// For REP instructions

		// if no more REPs, execute next instruction
		if (INS_HasFallThrough(ins))
		{
			INS_InsertPredicatedCall(
				ins,
				IPOINT_AFTER,           
				(AFUNPTR)log_memwrite,  
				IARG_MEMORYWRITE_SIZE,  
				IARG_END                
			);
		}

		// check if it is REP or another kind of branch or call instruction to copy
		if (INS_IsBranchOrCall(ins))
		{
			INS_InsertPredicatedCall(
				ins,
				IPOINT_TAKEN_BRANCH,        
				(AFUNPTR)log_memwrite,      
				IARG_MEMORYWRITE_SIZE,      
				IARG_END                    
			);
		}
	}

	// check if jumped to unpacked code
	if ((INS_IsDirectBranch(ins) || INS_IsIndirectBranchOrCall(ins))
		&& INS_OperandCount(ins) > 0)
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE,                      
			(AFUNPTR)check_indirect_ctransfer,  
			IARG_INST_PTR,                      
			IARG_BRANCH_TARGET_ADDR,
			IARG_BRANCH_TAKEN,
			IARG_END                            
		);
	}

	pushad_popad_heuristic.check_pushad_popad(ins);
}

void queue_memwrite(ADDRINT addr)
/*
*   Function which will save for a moment the address
*   of the instruction which will copy memory.
*   This is necessary as only before of the instruction
*   execution is possible to record the address
*/
{
	saved_addr = addr;
}

void log_memwrite(UINT32 size)
/*
*   Function to log in shared_mem the address and the size of
*   copied data from a copy instruction
*/
{
	ADDRINT addr = saved_addr;
	unsigned char aux;

	for (ADDRINT i = addr; i < addr + size; i++)
	{
		w_xor_x_heuristic.set_shadow_memory_as_writable(i);
		PIN_SafeCopy((VOID*)&aux, (const void*)i, 1);
		w_xor_x_heuristic.set_shadow_memory_value(i, aux);
	}
	
	if (!header_modified &&
		(addr >= main_base_address &&
			addr < main_base_address + sizeof(pe_dos_header))
		)
	{
		header_modified = true;
	}

	// check if is writing an API to memory
	// only will be executed after a GetProcAddress
	if (check_first_thunk && size == sizeof(ADDRINT) && pe_file->on_pe_file(addr))
	{
		ADDRINT api_write;
		PIN_SafeCopy((VOID*)&api_write, (const VOID*)addr, sizeof(ADDRINT));

		for (size_t i = 0; i < dll_imports.size(); i++)
		{
			for (size_t j = 0; j < dll_imports.at(i)->functions.size(); j++)
			{
				if (dll_imports.at(i)->functions.at(j).function_address == api_write) // check which API is writing
				{
					any_import_resolved = true;

					PIN_LockClient();
					dll_imports.at(i)->functions.at(j).function_destination = addr;
					PIN_UnlockClient();

					fprintf(stderr, "[INFO] API %s (0x%x) written to: 0x%x\n",
						dll_imports.at(i)->functions.at(j).function_name.c_str(),
						dll_imports.at(i)->functions.at(j).function_address,
						dll_imports.at(i)->functions.at(j).function_destination);

					fprintf(logfile, "[INFO] API %s (0x%x) written to: 0x%x\n",
						dll_imports.at(i)->functions.at(j).function_name.c_str(),
						dll_imports.at(i)->functions.at(j).function_address,
						dll_imports.at(i)->functions.at(j).function_destination);
				}
			}
		}
		
		check_first_thunk = false;
	}
}

void check_indirect_ctransfer(ADDRINT ip, ADDRINT target, BOOL taken)
/*
*   Function to detect the jump to the OEP and dump the unpacked code.
*   we will use the shadow_mem to detect if a memory was used as a target
*   of a copy, we will taint that memory as possible OEP.
*/
{
	if (!taken)
		return;

	w_xor_x_heuristic.set_shadow_memory_as_executable(target);

	/*
	*	Pushad & popad heuristic detection
	*/
	if (pushad_popad_heuristic.pushad_popad_detected() && !pushad_popad_heuristic.pushad_popad_finished())
		return;
	else if (pushad_popad_heuristic.pushad_popad_detected() && 
		     pushad_popad_heuristic.pushad_popad_finished() &&
			 w_xor_x_heuristic.is_shadow_memory_writable(target))
	{
		PIN_LockClient();
		if (dump_to_file(target))
		{
			PIN_UnlockClient();

			fini();

			PIN_ExitProcess(0);
		}
		PIN_UnlockClient();
	}

	/*
	*	w+x heuristic detection
	*/
	if (w_xor_x_heuristic.is_shadow_memory_writable(target) && !w_xor_x_heuristic.in_cluster(target))
	{
		fprintf(stderr, "[INFO] Jumped to the address: 0x%x, written before\n", target);
		fprintf(logfile, "[INFO] Jumped to the address: 0x%x, written before\n", target);

		w_xor_x_heuristic.set_cluster(target, true);
		
		if (pe_file->has_section_changed_entropy(target) && any_import_resolved)
		{
			PIN_LockClient();
			if (dump_to_file(target))
			{
				PIN_UnlockClient();

				fini();

				PIN_ExitProcess(0);
			}
			PIN_UnlockClient();
		}
	}
}

bool dump_to_file(ADDRINT target)
 {
	if (header_modified)
		pe_file->parse();

	auto sections = pe_file->section_table_header();
	 
	for (size_t i = 0; i < sections.size(); i++)
	{
		sections[i].pointerto_raw_data(sections[i].virtual_address());
		sections[i].sizeof_raw_data(sections[i].virtual_size());
	}

	pe_file->section_table_header(sections);

	/*
	*	go through the APIs
	*/
	for (size_t i = 0; i < dll_imports.size(); i++)
	{
		// check if the dll to insert is inside of the unpacked zone
		// if not, go fuck off
		if (dll_imports.at(i)->dll_nameA.size() != 0)
		 {
			 fprintf(stderr, "[INFO] Adding to the import DLL: %s\n", dll_imports.at(i)->dll_nameA.c_str());
			 fprintf(logfile, "[INFO] Adding to the import DLL: %s\n", dll_imports.at(i)->dll_nameA.c_str());
			 library = pe_file->add_library(dll_imports.at(i)->dll_nameA.c_str());
		 }
		else
		 {
			 fwprintf(stderr, L"[INFO] Adding to the import DLL: %S\n", dll_imports.at(i)->dll_nameW.c_str());
			 fwprintf(logfile, L"[INFO] Adding to the import DLL: %s\n", dll_imports.at(i)->dll_nameW.c_str());
			 char* dll_nameA = (char*)calloc(1, wcslen(dll_imports.at(i)->dll_nameW.c_str()) + 1);
			 wcstombs(dll_nameA, dll_imports.at(i)->dll_nameW.c_str(), wcslen(dll_imports.at(i)->dll_nameW.c_str()) + 1);
			 library = pe_file->add_library(dll_nameA);
		 }
		ADDRINT first_thunk = 0;

		for (size_t j = 0; j < dll_imports.at(i)->functions.size(); j++)
		{
			if (!pe_file->on_pe_file(dll_imports.at(i)->functions.at(j).function_destination))
				continue;

			if (dll_imports.at(i)->functions.at(j).is_ordinal)
			{
				if (dll_imports.at(i)->functions.at(j).function_ordinal > 0xFFFF)
					continue;

				fprintf(stderr, "[INFO] Adding to the import Function: 0%x\n", dll_imports.at(i)->functions.at(j).function_ordinal);
				fprintf(logfile, "[INFO] Adding to the import Function: 0%x\n", dll_imports.at(i)->functions.at(j).function_ordinal);

				const uint64_t ORDINAL_MASK = pe_file->type() == PE_TYPE::pe32_k ? 0x80000000 : 0x8000000000000000;
				function = &library->add_entry(import_entry_t( ORDINAL_MASK | dll_imports.at(i)->functions.at(j).function_ordinal,"" ));
			}
			else
			{
				if (dll_imports.at(i)->functions.at(j).function_name.size() == 0 || dll_imports.at(i)->functions.at(j).function_name.size() > 256)
					continue;

				fprintf(stderr, "[INFO] Adding to the import Function: %s\n", dll_imports.at(i)->functions.at(j).function_name.c_str());
				fprintf(logfile, "[INFO] Adding to the import Function: %s\n", dll_imports.at(i)->functions.at(j).function_name.c_str());

				function = &library->add_entry(dll_imports.at(i)->functions.at(j).function_name);
			}
			 
			if (first_thunk == 0)
				first_thunk = dll_imports.at(i)->functions.at(j).function_destination;
			else if (dll_imports.at(i)->functions.at(j).function_destination < first_thunk)
				first_thunk = dll_imports.at(i)->functions.at(j).function_destination;
		}
		if (first_thunk == 0x0)
			continue;

		first_thunk -= IMG_StartAddress(IMG_FindByAddress(first_thunk));
		library->import_address_table_rva(first_thunk);
	}


	fprintf(stderr, "[INFO] Dumping to file\n");
	fprintf(logfile, "[INFO] Dumping to file\n");
	 
	char file_name[MAX_PATH];
	if (unpacked_file_name.size() != 0)
		snprintf(file_name, sizeof(file_name) - 1, "%s", unpacked_file_name.c_str());
	else
		snprintf(file_name, sizeof(file_name) - 1, "file.base-0x%x.entry-0x%x.bin", (uintptr_t)main_base_address, (uintptr_t)(target - main_base_address));

	if (!pe_file->write(file_name, target))
	{
		fprintf(stderr, "[ERROR] Error dumping the file\n");
		fprintf(logfile, "[ERROR] Error dumping the file\n");

		return false;
	}
	
	return true;
 }