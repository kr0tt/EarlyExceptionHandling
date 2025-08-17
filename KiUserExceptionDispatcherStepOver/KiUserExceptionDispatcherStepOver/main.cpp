#include <Windows.h>
#include <stdio.h>
#include "structs.h"
#include "typedef.h"
#include "wow64_callback.h"
#include "hook_and_handler.h"

#pragma comment(lib, "ntdll.lib")

PFUNCTION_ADDRESS_TABLE	functionAddressTable = { 0 };

int main() {

	NTSTATUS status = 0x00;
	PVOID baseAddress = NULL;
	DWORD oldProtect = 0x00;
	SIZE_T size = 0x1000; 

	HMODULE module = GetModuleHandleA("ntdll.dll");

	PVOID wow64PrepareForException = HookExceptionDispatcher((PBYTE)module);
	if (!wow64PrepareForException) {
		return -1;
	}

	functionAddressTable = (PFUNCTION_ADDRESS_TABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FUNCTION_ADDRESS_TABLE));
	
	functionAddressTable->NtAllocateVirtualMemoryAddress = (ULONG_PTR)GetProcAddress(module, "NtAllocateVirtualMemory");
	functionAddressTable->NtProtectVirtualMemoryAddress = (ULONG_PTR)GetProcAddress(module, "NtProtectVirtualMemory");

	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)functionAddressTable->NtAllocateVirtualMemoryAddress;
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)functionAddressTable->NtProtectVirtualMemoryAddress;

	SetHardwareBreakpoint(functionAddressTable->NtAllocateVirtualMemoryAddress);

	if ((status = NtAllocateVirtualMemory((HANDLE)-1,
										  &baseAddress, 
										  0, 
										  &size, 
										  MEM_COMMIT | MEM_RESERVE, 
										  PAGE_READWRITE)) != 0x00) {

		printf("[ - ] NtAllocateVirtualMemory failed with status: 0x%08X\n", status);
		return -1;
	}

	printf("[ + ] Memory allocated at address: 0x%p\n", baseAddress);

	SetHardwareBreakpoint(functionAddressTable->NtProtectVirtualMemoryAddress);

	if ((status = NtProtectVirtualMemory((HANDLE)-1,
							             &baseAddress, 
										 &size, 
										 PAGE_EXECUTE_READ, 
										 &oldProtect)) != 0x00) {

		printf("[ - ] NtProtectVirtualMemory failed with status: 0x%08X\n", status);
		return -1;
	}

	printf("[ + ] Memory protection changed at address: 0x%p\n", baseAddress);

	if (!UnhookExceptionDispatcher(wow64PrepareForException)) {
		printf("[ - ] Failed to unhook exception dispatcher\n");
		return -1;
	}
	
	return 0;
}