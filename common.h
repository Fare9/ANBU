#pragma once

#ifndef COMMON_H
#define COMMON_H

#include "pin.H"

namespace WINDOWS {
#include <stdio.h>
#include <wchar.h>
#include <Windows.h>
#include <tlhelp32.h>
}

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <map>


typedef struct _write_memory
{
	ADDRINT address;
	size_t  size;
	std::vector<uint8_t> data;
} write_memory_t;


#endif // COMMON_H
