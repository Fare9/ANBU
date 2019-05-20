
#include "generic_instrumentation.h"

#ifdef MAKEINTRESOURCEA
#undef MAKEINTRESOURCEA
#endif // MAKEINTRESOURCEA


#define MAKEINTRESOURCEA(i) ((WINDOWS::LPSTR)((WINDOWS::ULONG_PTR)((WINDOWS::WORD)(i))))

/************* EXTERN VARIABLES *************/
extern FILE*						logfile; // log file handler
extern binary_t*					pe_file;

/************* VARIABLES USED FOR MONITORING BINARY *************/
ADDRINT								main_base_address;
dll_import_struct_t*				aux = nullptr;
std::vector<dll_import_struct_t*>	dll_imports;
bool								check_first_thunk = false;

const char*							saved_dll_nameA = nullptr;
const wchar_t*						saved_dll_nameW = nullptr;


void get_addresses_from_images(IMG img, VOID *v)
{
	RTN loadlibraryA;
	RTN loadlibraryW;
	RTN getmodulehandleA;
	RTN getmodulehandleW;
	RTN getprocaddress;

	ANBU::LOGGER_INFO(logfile, "IMG Loaded: %s\n", IMG_Name(img).c_str());

	if (IMG_IsMainExecutable(img)) 
	/*
	*	Check if the loaded executable is the main one
	*	in that case record the base address.
	*/
	{
		main_base_address = IMG_StartAddress(img);
		pe_file = new binary_t(main_base_address);
		pe_file->analyze_binary();
		ANBU::LOGGER_INFO(logfile, "Binary Base Address: 0x%x\n", main_base_address);
		return;
	}

	loadlibraryA = RTN_FindByName(img, "LoadLibraryA");

	if (RTN_Valid(loadlibraryA))
	{
		RTN_Open(loadlibraryA);

		ANBU::LOGGER_INFO("Inserting callbacks for: %s\n", RTN_Name(loadlibraryA).c_str());

		RTN_InsertCall(loadlibraryA,
			IPOINT_BEFORE,
			(AFUNPTR)hook_loadlibrarya_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END
		);

		RTN_InsertCall(loadlibraryA,
			IPOINT_AFTER,
			(AFUNPTR)hook_loadlibrary_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(loadlibraryA);
	}

	loadlibraryW = RTN_FindByName(img, "LoadLibraryW");

	if (RTN_Valid(loadlibraryW))
	{
		RTN_Open(loadlibraryW);

		ANBU::LOGGER_INFO("Inserting callbacks for: %s\n", RTN_Name(loadlibraryW).c_str());

		RTN_InsertCall(loadlibraryW,
			IPOINT_BEFORE,
			(AFUNPTR)hook_loadlibraryw_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END
		);

		RTN_InsertCall(loadlibraryW,
			IPOINT_AFTER,
			(AFUNPTR)hook_loadlibrary_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(loadlibraryW);
	}

	getmodulehandleA = RTN_FindByName(img, "GetModuleHandleA");

	if (RTN_Valid(getmodulehandleA))
	{
		RTN_Open(getmodulehandleA);

		ANBU::LOGGER_INFO("Inserting callbacks for: %s\n", RTN_Name(getmodulehandleA).c_str());

		RTN_InsertCall(getmodulehandleA,
			IPOINT_BEFORE,
			(AFUNPTR)hook_getmodulehandlea_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END
		);

		RTN_InsertCall(getmodulehandleA,
			IPOINT_AFTER,
			(AFUNPTR)hook_loadlibrary_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(getmodulehandleA);
	}

	getmodulehandleW = RTN_FindByName(img, "GetModuleHandleW");

	if (RTN_Valid(getmodulehandleW))
	{
		RTN_Open(getmodulehandleW);

		ANBU::LOGGER_INFO("Inserting callbacks for: %s\n", RTN_Name(getmodulehandleW).c_str());

		RTN_InsertCall(getmodulehandleW,
			IPOINT_BEFORE,
			(AFUNPTR)hook_getmodulehandlew_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END
		);

		RTN_InsertCall(getmodulehandleW,
			IPOINT_AFTER,
			(AFUNPTR)hook_loadlibrary_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(getmodulehandleW);
	}

	getprocaddress = RTN_FindByName(img, "GetProcAddress");

	if (RTN_Valid(getprocaddress))
	{
		RTN_Open(getprocaddress);

		ANBU::LOGGER_INFO("Inserting callbacks for: %s\n", RTN_Name(getprocaddress).c_str());

		RTN_InsertCall(getprocaddress,
			IPOINT_BEFORE,
			(AFUNPTR)hook_getprocaddress_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END
		);

		RTN_InsertCall(getprocaddress,
			IPOINT_AFTER,
			(AFUNPTR)hook_getprocaddress_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(getprocaddress);
	}

	return;
}

void hook_loadlibrarya_before(const char* dll_name)
{
	check_first_thunk = false;			// close the check of the first thunk copy

	saved_dll_nameA = dll_name;
}

void hook_getmodulehandlea_before(const char* dll_name)
{
	check_first_thunk = false;			// close the check of the first thunk copy

	saved_dll_nameA = dll_name;
}

void hook_loadlibraryw_before(const wchar_t* dll_name)
{
	check_first_thunk = false; // close the check of the first thunk copy

	saved_dll_nameW = dll_name;
}

void hook_getmodulehandlew_before(const wchar_t* dll_name)
{
	check_first_thunk = false; // close the check of the first thunk copy

	saved_dll_nameW = dll_name;
}

void hook_loadlibrary_after(ADDRINT dll_address)
{
	if (dll_address != NULL)
	{
		if (saved_dll_nameA != nullptr)
		{
			if (aux == nullptr					// if aux is equals to nullptr
				|| strcmp(aux->dll_nameA.c_str(), saved_dll_nameA) != 0)
			{
				aux = new dll_import_struct_t();
				aux->dll_nameA = saved_dll_nameA;
				dll_imports.push_back(aux);

				ANBU::LOGGER_INFO(logfile, "LoadLibraryA dll name: %s\n", saved_dll_nameA);

				aux->dll_address = dll_address;

				ANBU::LOGGER_INFO(logfile, "LoadLibrary returned: 0x%x\n", dll_address);
			}
		}
		else if (saved_dll_nameW != nullptr)
		{
			if (aux == nullptr
				|| wcscmp(aux->dll_nameW.c_str(), saved_dll_nameW) != 0)
			{
				aux = new dll_import_struct_t();
				aux->dll_nameW = saved_dll_nameW;
				dll_imports.push_back(aux);

				ANBU::LOGGER_INFO(logfile, L"LoadLibraryW dll name: %S\n", saved_dll_nameW);

				aux->dll_address = dll_address;

				ANBU::LOGGER_INFO(logfile, "LoadLibrary returned: 0x%x\n", dll_address);
			}
		}
		saved_dll_nameA = nullptr;
		saved_dll_nameW = nullptr;
	}
}

void hook_getprocaddress_before(ADDRINT dll_address, const char* function_name)
{
	check_first_thunk = false;

	// Create a new function
	if (aux)
	{	
		function_struct_t func;
		const char *filename;

		if ((uintptr_t)function_name <= 0xFFFF) // it is ordinal
		{
			func.function_ordinal = (uint16_t)((uintptr_t)function_name & 0xFFFF);
			func.is_ordinal = true;
		}
		else
		{
			func.function_name = function_name;
			func.is_ordinal = false;
		}

		PIN_LockClient();

		if (func.is_ordinal)
		{
			if ((aux->dll_nameA.size() != 0 && (WINDOWS::GetProcAddress(WINDOWS::GetModuleHandleA(aux->dll_nameA.c_str()), MAKEINTRESOURCE(function_name)) == NULL) ||
				(aux->dll_nameW.size() != 0 && (WINDOWS::GetProcAddress(WINDOWS::GetModuleHandleW(aux->dll_nameW.c_str()), MAKEINTRESOURCE(function_name)) == NULL))))
			{
				filename = strrchr(IMG_Name(IMG_FindByAddress(dll_address)).c_str(), '\\');

				if (filename == NULL)
					filename = IMG_Name(IMG_FindByAddress(dll_address)).c_str();
				else
					filename++;

				aux->dll_nameA = filename;
				aux->dll_nameW.erase();
			}
		}
		else
		{
			if ((aux->dll_nameA.size() != 0 && (WINDOWS::GetProcAddress(WINDOWS::GetModuleHandleA(aux->dll_nameA.c_str()), function_name) == NULL) ||
				(aux->dll_nameW.size() != 0 && (WINDOWS::GetProcAddress(WINDOWS::GetModuleHandleW(aux->dll_nameW.c_str()), function_name) == NULL))))
			{
				filename = strrchr(IMG_Name(IMG_FindByAddress(dll_address)).c_str(), '\\');

				if (filename == NULL)
					filename = IMG_Name(IMG_FindByAddress(dll_address)).c_str();
				else
					filename++;

				aux->dll_nameA = filename;
				aux->dll_nameW.erase();
			}
		}

		aux->functions.push_back(func);
		if (func.is_ordinal)
		{
			ANBU::LOGGER_INFO(logfile, "Dll 0x%x(%s), function 0x%x\n", dll_address, IMG_Name(IMG_FindByAddress(dll_address)).c_str(), func.function_ordinal);
		}
		else
		{
			ANBU::LOGGER_INFO(logfile, "Dll 0x%x(%s), function %s\n", dll_address, IMG_Name(IMG_FindByAddress(dll_address)).c_str(), function_name);	
		}
		PIN_UnlockClient();

	}
}

void hook_getprocaddress_after(ADDRINT function_address)
{
	if (aux)
	{
		check_first_thunk = true;

		ANBU::LOGGER_INFO(logfile, "GetProcAddress returned: 0x%x\n", function_address);

		// add the function address to the last function
		aux->functions.at(
			aux->functions.size() - 1
		).function_address = function_address;
	}
}