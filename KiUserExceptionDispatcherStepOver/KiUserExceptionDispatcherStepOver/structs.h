#pragma once

#include <Windows.h>

typedef struct _STRING{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

typedef struct _FUNCTION_ADDRESS_TABLE {
    ULONG_PTR	NtAllocateVirtualMemoryAddress;
    ULONG_PTR	NtProtectVirtualMemoryAddress;
} FUNCTION_ADDRESS_TABLE, * PFUNCTION_ADDRESS_TABLE;

