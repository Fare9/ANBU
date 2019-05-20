#include "utils.h"

namespace ANBU
{

	void LOGGER(FILE *file_to_dump, const char *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		if (file_to_dump)
		{
			vfprintf(file_to_dump, format, argptr);
		}

		vfprintf(stderr, format, argptr);
		vfprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER(const char *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		vfprintf(stderr, format, argptr);
		vfprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_INFO(FILE *file_to_dump, const char *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		if (file_to_dump)
		{
			fprintf(file_to_dump, "[INFO] ");
			vfprintf(file_to_dump, format, argptr);
		}
		fprintf(stderr, "[INFO] ");
		vfprintf(stderr, format, argptr);
		fprintf(stdout, "[INFO] ");
		vfprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_INFO(const char *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		fprintf(stderr, "[INFO] ");
		vfprintf(stderr, format, argptr);
		fprintf(stdout, "[INFO] ");
		vfprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_ERROR(FILE *file_to_dump, const char *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		if (file_to_dump)
		{
			fprintf(file_to_dump, "[ERROR] ");
			vfprintf(file_to_dump, format, argptr);
		}

		fprintf(stderr, "[ERROR] ");
		vfprintf(stderr, format, argptr);
		fprintf(stdout, "[ERROR] ");
		vfprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_ERROR(const char *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		fprintf(stderr, "[ERROR] ");
		vfprintf(stderr, format, argptr);
		fprintf(stdout, "[ERROR] ");
		vfprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER(FILE *file_to_dump, const wchar_t *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		if (file_to_dump)
		{
			vfwprintf(file_to_dump, format, argptr);
		}

		vfwprintf(stderr, format, argptr);
		vfwprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER(const wchar_t *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		vfwprintf(stderr, format, argptr);
		vfwprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_INFO(FILE *file_to_dump, const wchar_t *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		if (file_to_dump)
		{
			fwprintf(file_to_dump, L"[INFO] ");
			vfwprintf(file_to_dump, format, argptr);
		}

		fwprintf(stderr, L"[INFO] ");
		vfwprintf(stderr, format, argptr);
		fwprintf(stdout, L"[INFO] ");
		vfwprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_INFO(const wchar_t *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		fwprintf(stderr, L"[INFO] ");
		vfwprintf(stderr, format, argptr);
		fwprintf(stdout, L"[INFO] ");
		vfwprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_ERROR(FILE *file_to_dump, const wchar_t *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		if (file_to_dump)
		{
			fwprintf(file_to_dump, L"[ERROR] ");
			vfwprintf(file_to_dump, format, argptr);
		}
		fwprintf(stderr, L"[ERROR] ");
		vfwprintf(stderr, format, argptr);
		fwprintf(stdout, L"[ERROR] ");
		vfwprintf(stdout, format, argptr);

		va_end(argptr);
	}


	void LOGGER_ERROR(const wchar_t *format, ...)
	{
		va_list argptr;
		va_start(argptr, format);

		fwprintf(stderr, L"[ERROR] ");
		vfwprintf(stderr, format, argptr);
		fwprintf(stdout, L"[ERROR] ");
		vfwprintf(stdout, format, argptr);

		va_end(argptr);
	}
}

namespace LIEF 
{
	uint64_t align(uint64_t value, uint64_t align_on) 
	{
		if ((align_on > 0) && (value % align_on) > 0) {
			return  value + (align_on - (value % align_on));
		}
		else {
			return value;
		}
	}
}
