
#include "run_pe_detector.h"

/************* EXTERN VARIABLES *************/
extern FILE*								logfile;			// log file handler
extern std::string							unpacked_file_name;
/********************** VARIABLES ****************************/

// Array for syscalls names one by one
std::map<unsigned long, const char *>		g_syscall_names;
// Addresses of syscalls
ADDRINT										SYS_NtCreateUserProcess, 
											SYS_NtWriteVirtualMemory, 
											SYS_NtResumeThread;
ADDRINT										SYS_NtDuplicateObject, 
											SYS_NtOpenThread, 
											SYS_NtDelayExecution;
ADDRINT										SYS_NtOpenProcess, 
											SYS_NtCreateProcess, 
											SYS_NtCreateProcessEx;
ADDRINT										SYS_NtAllocateVirtualMemory,
											SYS_NtUnmapViewOfSection;

ADDRINT										entry_point;

map<HANDLE, std::vector<write_memory_t>>	process_data;
write_memory_t*								write_mem = nullptr;

int											g_process_handle_count = 0;
int											g_thread_handle_count = 0;
HANDLE										g_process_handle[256] = { 0 };
HANDLE										g_thread_handle[256] = { 0 };

// code from rreat library
void enum_syscalls()
{
	// as this is the beginning of execution under a 
	// sandbox environment take ntdll is correct
	HMODULE image = WINDOWS::GetModuleHandle("ntdll.dll");
	WINDOWS::PIMAGE_DOS_HEADER dos_header = (WINDOWS::PIMAGE_DOS_HEADER) image;
	WINDOWS::PIMAGE_NT_HEADERS nt_header = (WINDOWS::PIMAGE_NT_HEADERS) ((WINDOWS::LONG)dos_header + dos_header->e_lfanew);
	WINDOWS::PIMAGE_DATA_DIRECTORY data_directory = (WINDOWS::PIMAGE_DATA_DIRECTORY)(&nt_header->OptionalHeader.DataDirectory);
	WINDOWS::PIMAGE_EXPORT_DIRECTORY export_directory = (WINDOWS::PIMAGE_EXPORT_DIRECTORY)((WINDOWS::LONG)dos_header + data_directory->VirtualAddress);


	WINDOWS::PDWORD address_of_names			=	(WINDOWS::PDWORD)((WINDOWS::LONG)dos_header + export_directory->AddressOfNames);
	WINDOWS::PDWORD address_of_functions		=	(WINDOWS::PDWORD)((WINDOWS::LONG)dos_header + export_directory->AddressOfFunctions);
	WINDOWS::PWORD address_of_name_ordinals		=	(WINDOWS::PWORD)((WINDOWS::LONG)dos_header + export_directory->AddressOfNameOrdinals);
	size_t  number_of_names						=	MIN(export_directory->NumberOfFunctions, export_directory->NumberOfNames);

	ANBU::LOGGER(logfile, "<------------------- Getting syscalls ------------------->\n");
	for (size_t i = 0; i < number_of_names; i++)
	{
		const char		*name = (const char *)((WINDOWS::LONG)dos_header + address_of_names[i]);
		WINDOWS::PBYTE	 addr  = (WINDOWS::PBYTE)((WINDOWS::LONG)dos_header + address_of_functions[address_of_name_ordinals[i]]);

		if (!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2))
		{
			/*
			*	Check for the next instructions:
			*		mov eax, syscall_number ; mov ecx, some_value
			*		mov eax, syscall_number ; xor ecx, ecx
			*		mov eax, syscall_number ; mov edx, 0x7ffe0300
			*/
			if (*addr == 0xb8 &&
				(addr[5] == 0xb9 ||
					addr[5] == 0x33 ||
					addr[5] == 0xba))
			{
				// get syscall number from code
				unsigned long syscall_number = *(WINDOWS::PDWORD)(addr + 1);
				ANBU::LOGGER_INFO(logfile, "Saved syscall 0x%x(%s)\n", syscall_number, name);
				g_syscall_names[syscall_number] = name;
			}
		}
	}
	ANBU::LOGGER(logfile, "<-------------------------------------->\n");
}

unsigned long syscall_name_to_number(const char *name)
{
	for (size_t i = 0; i < g_syscall_names.size(); i++)
	{
		if (g_syscall_names[i] != NULL &&
			// avoid Nt or Zw
			!strcmp(g_syscall_names[i] + 2, name + 2))
			return i;
	}
	ANBU::LOGGER_ERROR("The syscall %s was not found\n", name);
	return 0;
}

void init_common_syscalls()
{
	/****** Function used to create process suspended ******/
	SYS_NtCreateUserProcess		= syscall_name_to_number("NtCreateUserProcess");
	SYS_NtCreateProcess			= syscall_name_to_number("NtCreateProcess");
	SYS_NtCreateProcessEx		= syscall_name_to_number("NtCreateProcessEx");
	/****** Function to write new content on new process ******/
	SYS_NtWriteVirtualMemory	= syscall_name_to_number("NtWriteVirtualMemory");
	/****** Function to restart execution of suspended process ******/
	SYS_NtResumeThread			= syscall_name_to_number("NtResumeThread");
	/****** Function to open processes or threads *******/
	SYS_NtOpenProcess			= syscall_name_to_number("NtOpenProcess");
	SYS_NtOpenThread			= syscall_name_to_number("NtOpenThread");
	/****** Function to allocate memory in remote or local process ******/
	SYS_NtAllocateVirtualMemory = syscall_name_to_number("NtAllocateVirtualMemory");
	/****** Other functions *******/
	SYS_NtUnmapViewOfSection	= syscall_name_to_number("NtUnmapViewOfSection");
	SYS_NtDuplicateObject		= syscall_name_to_number("NtDuplicateObject");
	SYS_NtDelayExecution		= syscall_name_to_number("NtDelayExecution");
}

void syscall_get_arguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...)
{
	va_list args;
	va_start(args, count);
	
	for (int i = 0; i < count; i++)
	{
		int index = va_arg(args, int);
		ADDRINT *ptr = va_arg(args, ADDRINT *);
		*ptr = PIN_GetSyscallArgument(ctx, std, index);
	}

	va_end(args);
}

void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
	OBJECT_ATTRIBUTES*									object_attributes;
	RTL_USER_PROCESS_PARAMETERS*						process_parameters;
	unsigned long										syscall_number;
	map<HANDLE, std::vector<write_memory_t>>::iterator	it;
	binary_t*											binary_;
	size_t												index_base_address;

	// get the syscall number
	syscall_number = PIN_GetSyscallNumber(ctx, std);
	index_base_address = -1;

	// if the syscall is not in our list, you can leave
	if (g_syscall_names.find(syscall_number) != g_syscall_names.end())	
	{
		const char *name = g_syscall_names[syscall_number];

		syscall_t *sc = &((syscall_t *)v)[thread_id];
		sc->syscall_number = syscall_number;

		if (syscall_number == SYS_NtCreateUserProcess)
		{
			ANBU::LOGGER_INFO(logfile, "Syscall called 0x%x(%s) thread 0x%x \n", syscall_number, name, thread_id);

			ULONG create_thread_flags;

			syscall_get_arguments(ctx, std, 4, 0, &sc->arg0, 1, &sc->arg1, 8, &process_parameters, 7, &create_thread_flags);
			
			ANBU::LOGGER_INFO(logfile, "Image_name: %S\ncommand_line: %S\n",
				process_parameters->ImagePathName.Buffer,
				process_parameters->CommandLine.Buffer);
			ANBU::LOGGER_INFO(logfile, "Process_flags: 0x%x\nthread_flags: 0x%x\n",
				PIN_GetSyscallArgument(ctx, std, 6),
				PIN_GetSyscallArgument(ctx, std, 7));
		}
		else if (syscall_number == SYS_NtCreateProcess ||
			syscall_number == SYS_NtCreateProcessEx)
		{
			ANBU::LOGGER_INFO(logfile, "Syscall called 0x%x(%s) thread 0x%x \n", syscall_number, name, thread_id);
			syscall_get_arguments(ctx, std, 2, 0, &sc->arg0, 2, &object_attributes);
			
			if (object_attributes != NULL &&
				object_attributes->ObjectName != NULL)
			{
				ANBU::LOGGER_INFO(logfile, L"Process execute image_name: %S\n", object_attributes->ObjectName->Buffer);
			}
		}
		else if (syscall_number == SYS_NtWriteVirtualMemory)
		{
			ANBU::LOGGER_INFO(logfile, "Syscall called 0x%x(%s) thread 0x%x \n", syscall_number, name, thread_id);

			HANDLE process_handle;
			char *base_address, *buffer;

			syscall_get_arguments(ctx, std, 5, 0, &process_handle, 1, &base_address, 2, &buffer, 3, &sc->arg3, 4, &sc->arg4);

			ANBU::LOGGER_INFO(logfile, "Process Handle: 0x%x\nBase Address to write: 0x%x\nBuffer with data to write: 0x%x\nSize: 0x%x\n", (unsigned int)process_handle, (unsigned int)base_address, (unsigned int)buffer, (unsigned int)sc->arg3);
			
			write_mem = new write_memory_t();

			write_mem->address = (ADDRINT)base_address;
			write_mem->size = (size_t)sc->arg3;

			write_mem->data.resize((size_t)sc->arg3);

			if (PIN_SafeCopy(write_mem->data.begin(), (const VOID*)buffer, (size_t)sc->arg3) != (size_t)sc->arg3)
			{
				ANBU::LOGGER_ERROR(logfile, "Not possible to read from 0x%x\n", (unsigned int)buffer);

				PIN_ExitProcess(-1);
				exit(-1);
			}
			process_data[process_handle].push_back(*write_mem);
		}
		else if (syscall_number == SYS_NtResumeThread)
		{
			ANBU::LOGGER_INFO(logfile, "Syscall called 0x%x(%s) thread 0x%x \n", syscall_number, name, thread_id);

			WINDOWS::TerminateThread(g_thread_handle[0], 0);
			WINDOWS::TerminateProcess(g_process_handle[0], 0);

			ANBU::LOGGER_INFO(logfile, "Finished runPE process... Dumping\n");

			for (it = process_data.begin(); it != process_data.end(); it++)
			{
				ANBU::LOGGER_INFO(logfile, "Dumping file for process handle: 0x%x\n", (unsigned int)it->first);
				
				for (size_t index_vector = 0; index_vector < it->second.size(); index_vector++)
				{
					// discover which one could be the index of the base address
					PIN_LockClient();
					binary_ = new binary_t(&it->second.at(index_vector).data);					

					if (binary_->analyze_binary())
					{
						index_base_address = index_vector;
						break;
					}

					delete binary_;
				}
				
				if (index_base_address == -1)
				{
					PIN_UnlockClient();
					ANBU::LOGGER_ERROR(logfile, "Not found base memory in process with handle: 0x%x\n", (unsigned int)it->first);

					delete binary_;
					continue;
				}

				char file_name[MAX_PATH];
				if (unpacked_file_name.size() != 0)
					snprintf(file_name, sizeof(file_name) - 1, "%s", unpacked_file_name.c_str());
				else
					snprintf(file_name, sizeof(file_name) - 1, "file.base-0x%x.entry.bin", (uintptr_t)binary_->optional_header()->imagebase());

				if(!binary_->write(file_name, it->second.at(index_base_address).data, it->second))
				{
					ANBU::LOGGER_ERROR(logfile, "Not possible to dump process with handle: 0x%x\n", (unsigned int)it->first);
				}
				else
				{
					ANBU::LOGGER_INFO(logfile, "Success dumping process with handle %x and base 0x%x", (unsigned int)it->first, (unsigned int)it->second.at(index_base_address).address);
				}

				PIN_UnlockClient();
				delete binary_;
			}
			
			exit(0);
		}
		else if (syscall_number == SYS_NtDuplicateObject)
		{
			ANBU::LOGGER_ERROR("DuplicateHandle() not implemented yet!\n");
		}
		else if (syscall_number == SYS_NtOpenThread)
		{
			ANBU::LOGGER_ERROR("OpenThread() not implemented yet!\n");
		}
		else if (syscall_number == SYS_NtOpenProcess)
		{
			ANBU::LOGGER_ERROR("OpenProcess() not implemented yet!\n");
		}
		else if (syscall_number == SYS_NtDelayExecution)
		{
			ANBU::LOGGER_INFO(logfile, "Syscall called 0x%x(%s) thread 0x%x \n", syscall_number, name, thread_id);
			WINDOWS::LARGE_INTEGER *delay_interval;
			syscall_get_arguments(ctx, std, 1, 1, &delay_interval);
			if (delay_interval->QuadPart != 0)
			{
				ANBU::LOGGER_INFO(logfile, "Skipped Sleep(%d)\n", (int)-delay_interval->QuadPart / 10000);
			}
			delay_interval->QuadPart = 0; // modify!!!
		}
		else if (syscall_number == SYS_NtUnmapViewOfSection)
		{
			ANBU::LOGGER_INFO(logfile, "Syscall called 0x%x(%s) thread 0x%x \n", syscall_number, name, thread_id);

			syscall_get_arguments(ctx, std, 2, 0, &sc->arg0, 1, &sc->arg1);
			
			ANBU::LOGGER_INFO(logfile, "Unmaped section 0x%x in process handle %x\n", (unsigned int)sc->arg0, (unsigned int)sc->arg1);
		}
		else if (syscall_number == SYS_NtAllocateVirtualMemory)
		{
			ANBU::LOGGER_INFO(logfile, "Syscall called 0x%x(%s) thread 0x%x \n", syscall_number, name, thread_id);

			ADDRINT address_to_allocate;
			WINDOWS::SIZE_T  size_to_allocate;
			syscall_get_arguments(ctx, std, 3, 0, &sc->arg0, 1, &sc->arg1, 3, &sc->arg2);

			PIN_SafeCopy((VOID*)&address_to_allocate, (const VOID*)sc->arg1, sizeof(ADDRINT));
			PIN_SafeCopy((VOID*)&size_to_allocate, (const VOID*)sc->arg2, sizeof(WINDOWS::SIZE_T));

			ANBU::LOGGER_INFO(logfile, "Allocated memory address 0x%x, with size 0x%x, in process handle %x\n", (unsigned int)address_to_allocate,
				(unsigned int)size_to_allocate,
				(unsigned int)sc->arg0);
		}
	}
}

void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
	syscall_t *sc = &((syscall_t*)v)[thread_id];

	if (sc->syscall_number == SYS_NtCreateUserProcess)
	{
		g_process_handle[g_process_handle_count++] = *(HANDLE*)sc->arg0;
		g_thread_handle[g_thread_handle_count++] = *(HANDLE*)sc->arg1;
	}
	else if (sc->syscall_number == SYS_NtCreateProcess ||
		sc->syscall_number == SYS_NtCreateProcessEx)
	{
		g_process_handle[g_process_handle_count++] = *(HANDLE*)sc->arg0;
	}
}


bool compare_by_address(const write_memory_t& a, const write_memory_t& b)
{
	return a.address < b.address;
}