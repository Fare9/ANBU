#include "anti-methods.h"

/************* EXTERN VARIABLES *************/
extern FILE*						logfile; // log file handler
extern uint64_t						tick_counts_per_millisecond;

/************* VARIABLES FOR ANTI-* STUFF ***/
static uint32_t						rdtsc = 0;
static WINDOWS::SYSTEMTIME			local_time = { 0 };
static WINDOWS::SYSTEMTIME			system_time = { 0 };

/******************************
*	INSTRUMENTATION CODE
*******************************/

void hook_functions(IMG img, VOID *v)
{
	RTN isdebuggerpresent;
	RTN sleep;
	RTN gettickcount;
	RTN gettickcount64;
	RTN process32first;
	RTN process32next;

	isdebuggerpresent = RTN_FindByName(img, "IsDebuggerPresent");
	if (RTN_Valid(isdebuggerpresent))
	{
		fprintf(stderr, "[INFO] Replacing IsDebuggerPresent for anti IsDebuggerPresent\n");
		fprintf(logfile, "[INFO] Replacing IsDebuggerPresent for anti IsDebuggerPresent\n");
		RTN_Replace(isdebuggerpresent, AFUNPTR(MyIsDebuggerPresent));
	}

	sleep = RTN_FindByName(img, "Sleep");
	if (RTN_Valid(sleep))
	{
		fprintf(stderr, "[INFO] Replacing Sleep for anti Sleep\n");
		fprintf(logfile, "[INFO] Replacing Sleep for anti Sleep\n");
		RTN_Replace(sleep, AFUNPTR(MySleep));
	}

	gettickcount = RTN_FindByName(img, "GetTickCount");
	if (RTN_Valid(gettickcount))
	{
		fprintf(stderr, "[INFO] Replacing GetTickCount for anti GetTickCount\n");
		fprintf(logfile, "[INFO] Replacing GetTickCount for anti GetTickCount\n");
		RTN_Replace(gettickcount, AFUNPTR(MyGetTickCount));
	}

	gettickcount64 = RTN_FindByName(img, "GetTickCount64");
	if (RTN_Valid(gettickcount64))
	{
		fprintf(stderr, "[INFO] Replacing GetTickCount64 for anti GetTickCount64\n");
		fprintf(logfile, "[INFO] Replacing GetTickCount64 for anti GetTickCount64\n");
		RTN_Replace(gettickcount64, AFUNPTR(MyGetTickCount64));
	}

	process32first = RTN_FindByName(img, "Process32First");
	if (RTN_Valid(process32first))
	{
		fprintf(stderr, "[INFO] Replacing Process32First for anti Process32First\n");
		fprintf(logfile, "[INFO] Replacing Process32First for anti Process32First\n");
		RTN_Replace(process32first, AFUNPTR(MyProcess32First));
	}

	process32next = RTN_FindByName(img, "Process32Next");
	if (RTN_Valid(process32next))
	{
		fprintf(stderr, "[INFO] Replacing Process32Next for anti Process32Next\n");
		fprintf(logfile, "[INFO] Replacing Process32Next for anti Process32Next\n");
		RTN_Replace(process32next, AFUNPTR(MyProcess32Next));
	}
}

void hook_instructions(INS ins, void *v)
{
	if (INS_IsRDTSC(ins))
	{
		INS_InsertPredicatedCall(
			ins,
			IPOINT_AFTER,
			AFUNPTR(MyRDTSC),
			IARG_REG_REFERENCE, REG_GAX,
			IARG_REG_REFERENCE, REG_GDX,
			IARG_END
		);
	}
}

/******************************
*	HOOKS
*******************************/

WINDOWS::BOOL WINAPI MyIsDebuggerPresent()
{
	return FALSE;
}

WINDOWS::DWORD WINAPI MyGetTickCount()
{
	if (!rdtsc)
	{
		rdtsc = WINDOWS::GetTickCount();
	}
	else
	{
		rdtsc++;
	}

	return rdtsc;
}

WINDOWS::ULONGLONG WINAPI MyGetTickCount64()
{
	return (WINDOWS::ULONGLONG)MyGetTickCount();
}

void MySleep(WINDOWS::DWORD dwMilliseconds)
{
	if (!rdtsc)
	{
		rdtsc = MyGetTickCount();
	}

	rdtsc += (uint32_t)tick_counts_per_millisecond * dwMilliseconds;

	fprintf(stderr, "[INFO] Sleep Avoided\n");
	fprintf(logfile, "[INFO] Sleep Avoided\n");
	return;
}

/*
*	Fixed function thanks to: https://reverseengineering.stackexchange.com/questions/17830/intel-pin-tracerpin-adding-modification-of-registers
*/
void MyRDTSC(ADDRINT *gax, ADDRINT *gdx)
{
	ADDRINT new_value = MyGetTickCount();

	*gax = new_value;
	*gdx = (ADDRINT)0;

	return;
}

WINDOWS::BOOL MyProcess32First(WINDOWS::HANDLE hSnapshot, WINDOWS::LPPROCESSENTRY32 lppe)
{
	WINDOWS::BOOL function_return = WINDOWS::Process32First(hSnapshot, lppe);

	if (strcmp(lppe->szExeFile, "pin.exe") == 0)
	{
		function_return = WINDOWS::Process32Next(hSnapshot, lppe);
	}

	return function_return;
}

WINDOWS::BOOL MyProcess32Next(WINDOWS::HANDLE hSnapshot, WINDOWS::LPPROCESSENTRY32 lppe)
{
	WINDOWS::BOOL function_return = WINDOWS::Process32Next(hSnapshot, lppe);

	if (strcmp(lppe->szExeFile, "pin.exe") == 0)
	{
		function_return = WINDOWS::Process32Next(hSnapshot, lppe);
	}

	return function_return;
}