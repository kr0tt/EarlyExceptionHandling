#pragma once

#pragma once

#include <Windows.h>

PVOID ReturnWow64FunctionPointer(PBYTE moduleBase);

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

#define RTL_CONSTANT_ANSI_STRING(s) { sizeof(s) - 1,  sizeof(s), (PCHAR)(s) }

