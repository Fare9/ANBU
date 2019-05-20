#pragma once
#ifndef UTILS_H
#define UTILS_H

#include "common.h"

namespace ANBU
{
	void LOGGER(FILE *file_to_dump, const char *format, ...);
	void LOGGER(const char *format, ...);
	void LOGGER_INFO(FILE *file_to_dump, const char *format, ...);
	void LOGGER_INFO(const char *format, ...);
	void LOGGER_ERROR(FILE *file_to_dump, const char *format, ...);
	void LOGGER_ERROR(const char *format, ...);

	void LOGGER(FILE *file_to_dump, const wchar_t *format, ...);
	void LOGGER(const wchar_t *format, ...);
	void LOGGER_INFO(FILE *file_to_dump, const wchar_t *format, ...);
	void LOGGER_INFO(const wchar_t *format, ...);
	void LOGGER_ERROR(FILE *file_to_dump, const wchar_t *format, ...);
	void LOGGER_ERROR(const wchar_t *format, ...);
}

namespace LIEF 
{
	uint64_t align(uint64_t value, uint64_t align_on);
	
	template<typename T>
	inline constexpr T round(T x) {
		return static_cast<T>(round<uint64_t>(x));
	}

	template<>
	inline uint64_t round<uint64_t>(uint64_t x) {
		//From http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
		x--;
		x |= x >> 1;  // handle  2 bit numbers
		x |= x >> 2;  // handle  4 bit numbers
		x |= x >> 4;  // handle  8 bit numbers
		x |= x >> 8;  // handle 16 bit numbers
		x |= x >> 16; // handle 32 bit numbers
		x |= x >> 32; // handle 64 bit numbers
		x++;
		return x;
	}


}

#endif // !UTILS_H
