#pragma once

#include <Windows.h>

//
// https://github.com/winsiderss/systeminformer/tree/master/phnt
//

typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
	);

EXTERN_C NTSTATUS NTAPI NtContinue(
	_In_ PCONTEXT ContextRecord,
	_In_ BOOLEAN TestAlert
);
