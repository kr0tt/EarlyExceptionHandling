#pragma once

#include <Windows.h>

DWORD64 ReturnSyscallInstructionAddress(UINT_PTR instructionPointer);
DWORD64 ReturnFunctionsSSN(UINT_PTR rip);
