#pragma once
#ifndef UTILS_H
#define UTILS_H

#include "common.h"

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
