/*
*   Compile: make PIN_ROOT="<path_to_pin>"
*/
#include "unpacker.h"
#include "utils.h"


FILE*				logfile; // log file handler
binary_t*			pe_file;
uint64_t			tick_counts_per_millisecond = 0; // more or less ticks per millisecond
std::string			unpacked_file_name;
std::string			import_section_name;
 /*
 *   KNOB class to create arguments with PIN
 *   on this case, we will create an argument
 *   string for the user if wants to save
 *   logs in a file.
 */
KNOB<string>		KnobLogFile(
			KNOB_MODE_WRITEONCE,
			"pintool",
			"l", // command accepted (-l)
			"unpacker.log", // value of the command, log file name
			"log file"
);
/*
*	argument to activate the Debug mode
*/
KNOB<string>		KnobDebugFile(
			KNOB_MODE_WRITEONCE,
			"pintool",
			"d", // command accepted (-d)
			"false",
			"start debug mode"
);
/*
*	argument for giving a name to the
*	output unpacked file
*/
KNOB<string>		KnobUnpackedFileName(
			KNOB_MODE_WRITEONCE,
			"pintool",
			"n", // command accepted (-n)
			"",
			"unpacked file name"
);
/*
*	argument for giving a name to the
*	import section
*/
KNOB<string>		KnobImportSectionName(
	KNOB_MODE_WRITEONCE,
	"pintool",
	"i", // command accepted (-i)
	".F9", // default value
	"import section name"
);


/*
*	PIN Exception handler function
*/
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
	EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
	EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);

	ANBU::LOGGER_ERROR(logfile, "Exception class: 0x%x\n", (unsigned int)cl);
	ANBU::LOGGER_ERROR(logfile, "Exception string: %s\n", PIN_ExceptionToString(pExceptInfo).c_str());

	return EHR_CONTINUE_SEARCH;
}

int main(int argc, char *argv[])
{
	WINDOWS::DWORD tick_count1, tick_count2;

	/*
	*	As we will use symbols...
	*/
	PIN_InitSymbols();
	/*
	*   Function to initialize the Pintool
	*   always called before almost any other PIN
	*   function (only PIN_InitSymbols can be before)
	*/
	if (PIN_Init(argc, argv))
	{
		usage();
		return 1;
	}

	if (strcmp(KnobDebugFile.Value().c_str(), "true") == 0)
	{
		DEBUG_MODE debug;
		debug._type		= DEBUG_CONNECTION_TYPE_TCP_SERVER;
		debug._options	= DEBUG_MODE_OPTION_STOP_AT_ENTRY;
		PIN_SetDebugMode(&debug);
	}

	// open log file to append
	ANBU::LOGGER_INFO("File name: %s\n", KnobLogFile.Value().c_str());
	logfile = fopen(KnobLogFile.Value().c_str(), "w");
	if (!logfile)
	{
		ANBU::LOGGER_ERROR("Failed to open '%s'\n", KnobLogFile.Value().c_str());
		return 1;
	}

	// name for unpacked file
	unpacked_file_name = KnobUnpackedFileName.Value();

	// import section name
	import_section_name = KnobImportSectionName.Value();

	if (import_section_name.size() > 8)
	{
		ANBU::LOGGER_ERROR("Name cannot be greater than 8 characters");
		return -1;
	}

	PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

	ANBU::LOGGER(logfile,"+--<<< ANBU by F9 >>>>--+\n");
	ANBU::LOGGER(logfile, "------ unpacking binary ------\n");
	
	enum_syscalls();

	init_common_syscalls();

	syscall_t sc[256] = { 0 };
	/*
	*	Add instrumentation function for Syscalls entry and exit
	*/
	PIN_AddSyscallEntryFunction(&syscall_entry, &sc);
	PIN_AddSyscallExitFunction(&syscall_exit, &sc);


	/*
	*   Add instrumentation function at Instruction tracer level
	*   in opposite to TRACE instrumentation, this goes to an
	*   instruction granularity.
	*/
	INS_AddInstrumentFunction(instrument_mem_cflow, NULL);

	/*
	*	Add instrumentation for IMG loading.
	*/
	IMG_AddInstrumentFunction(get_addresses_from_images, NULL);

	/*
	*	Add instrumentation for anti-anti-stuff.
	*/
	tick_count1 = WINDOWS::GetTickCount();
	WINDOWS::Sleep(1);
	tick_count2 = WINDOWS::GetTickCount();
	tick_counts_per_millisecond = tick_count2 - tick_count1;
	IMG_AddInstrumentFunction(hook_functions, NULL);
	INS_AddInstrumentFunction(hook_instructions, NULL);

	/*
	*   RUN the program and never return
	*/
	PIN_StartProgram();

	return 1;
}


void usage()
{
	ANBU::LOGGER_ERROR("Parameters error, please check next help line(s)\n");
	ANBU::LOGGER("pin -t <pintool_path> [-l <logname>] -- application\n");
	ANBU::LOGGER("Commands: \n");
	ANBU::LOGGER("\t+ -t <pintool_path> (MANDATORY): necessary flag for PIN to specify a pintool\n");
	ANBU::LOGGER("\t+ -l <logname> (OPTIONAL): specify name for a log file\n");
	ANBU::LOGGER("\t+ -d true (OPTIONAL): start debug mode\n");
	ANBU::LOGGER("\t+ -n <unpacked file name> (OPTIONAL): name for unpacked file\n");
	ANBU::LOGGER("\n");
}