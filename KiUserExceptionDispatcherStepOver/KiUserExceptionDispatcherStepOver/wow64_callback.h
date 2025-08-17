#pragma once

#include <Windows.h>
//#include "structs.h"

PVOID ReturnWow64FunctionPointer(PBYTE moduleBase);

#define RTL_CONSTANT_ANSI_STRING(s) { sizeof(s) - 1,  sizeof(s), (PCHAR)(s) }

