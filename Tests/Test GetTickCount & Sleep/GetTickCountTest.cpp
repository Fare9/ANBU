// GetTickCountTest.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <Windows.h>
int main()
{
	printf("GetTickCount() = 0x%x\n", GetTickCount());
	printf("GetTickCount() = 0x%x\n", GetTickCount());
	printf("Do Sleep of 10 seconds\n");
	Sleep(10000);
	printf("GetTickCount() = 0x%x\n", GetTickCount());
}