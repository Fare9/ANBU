/***
*	RunPE detector By Jurriaan Bremer
*/
#pragma once


#ifndef RUN_PE_DETECTOR_H
#define RUN_PE_DETECTOR_H

#include "common.h"
#include "builder.h"
#include "data_directory_header.h"

#define USHORT	WINDOWS::USHORT
#define ULONG	WINDOWS::ULONG
typedef wchar_t *PWCH;
typedef char	*PCHAR;
#define HANDLE	WINDOWS::HANDLE
#define PHANDLE WINDOWS::PHANDLE
#define HMODULE WINDOWS::HMODULE
typedef void	*PVOID;
#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _syscall_t
{
	ADDRINT syscall_number;
	union
	{
		ADDRINT args[16];
		struct
		{
			ADDRINT arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7;
		};
	};
} syscall_t;

void enum_syscalls();
unsigned long syscall_name_to_number(const char *name);
void init_common_syscalls();
void syscall_get_arguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...);
void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v);
bool compare_by_address(const write_memory_t& a, const write_memory_t& b);
#endif // !RUN_PE_DETECTOR_H
