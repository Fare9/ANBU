#pragma once

#ifndef ANTI_METHODS_H
#define ANTI_METHODS_H

#include "common.h"
#include "utils.h"

/******************************
*	INSTRUMENTATION CODE
*******************************/
void									hook_functions(IMG img, VOID *v);
void									hook_instructions(INS ins, void *v);


/******************************
*	HOOKS
*******************************/
WINDOWS::BOOL			WINAPI			MyIsDebuggerPresent();
void									MySleep(WINDOWS::DWORD dwMilliseconds);
WINDOWS::DWORD			WINAPI			MyGetTickCount();
WINDOWS::ULONGLONG		WINAPI			MyGetTickCount64();
void									MyRDTSC(ADDRINT *gax, ADDRINT *gdx);
WINDOWS::BOOL							MyProcess32First(WINDOWS::HANDLE hSnapshot, WINDOWS::LPPROCESSENTRY32 lppe);
WINDOWS::BOOL							MyProcess32Next(WINDOWS::HANDLE hSnapshot, WINDOWS::LPPROCESSENTRY32 lppe);


#endif // !ANTI_METHODS_H
