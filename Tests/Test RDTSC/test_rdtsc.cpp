// test_rdtsc.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include "pch.h"
#include <iostream>
#include <Windows.h>

int main()
{
	uint64_t rdtsc = 0;
	uint32_t low_value = 0, high_value = 0;

	printf("[!] RDTSC test\n");

	__asm
	{
		rdtsc;
		mov low_value, eax;
		mov high_value, edx;
	}

	rdtsc = (uint64_t)((((uint64_t)high_value) << 32) | (uint64_t)low_value);
	printf("[+] First rdtsc executed\n");
	printf("\t[+] Low value: 0x%x\n", low_value);
	printf("\t[+] High value: 0x%x\n", high_value);
	printf("\t[+] RDTSC value: 0x%llx\n", rdtsc);

	printf("[!] Execute some instructions\n");
	int a = 2, b = 4, c = 2, d = 6;
	a += b;
	b *= c;
	c /= d;
	d %= a;

	__asm
	{
		rdtsc;
		mov low_value, eax;
		mov high_value, edx;
	}

	rdtsc = (uint64_t)((((uint64_t)high_value) << 32) | (uint64_t)low_value);
	printf("[+] Second rdtsc executed\n");
	printf("\t[+] Low value: 0x%x\n", low_value);
	printf("\t[+] High value: 0x%x\n", high_value);
	printf("\t[+] RDTSC value: 0x%llx\n", rdtsc);

	getchar();
}