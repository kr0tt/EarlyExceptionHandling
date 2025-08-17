#include <Windows.h>
#include <stdio.h>
#include "return_ssn.h"
#include "typedef.h"
#include "wow64_callback.h"

PVOID ExceptionHandler(PEXCEPTION_RECORD exceptionRecord, PCONTEXT contextRecord) {
	
	if (exceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		if (contextRecord->Rip == contextRecord->Dr0) {

			contextRecord->Dr0 = 0;														// remove the hardware breakpoint
			contextRecord->Rax = ReturnFunctionsSSN(contextRecord->Rip);				// set rax to SSN						
			contextRecord->Rip = ReturnSyscallInstructionAddress(contextRecord->Rip);	// set rip to syscall instruction address
			NtContinue(contextRecord, FALSE);											// continue execution									
		}
	}
	
	return NULL; 
}

VOID SetHardwareBreakpoint(ULONG_PTR ntFunctionAddress){
	
	DWORD64 inlineHookAddress = ntFunctionAddress + 3ull;
	
	//
	// check if the the hook is present
	// skip setting a HWBP if it is not and call the NT function normally
	//

	if (*(PBYTE)inlineHookAddress != 0xE9) {
		printf("[ * ] Instruction at address 0x%p is not hooked\n", inlineHookAddress);
		return;
	}
	
	printf("[ * ] Setting hardware breakpoint at address: 0x%p\n", inlineHookAddress);
	
	CONTEXT context = { 0 };
	RtlCaptureContext(&context);

	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	context.Dr0 = inlineHookAddress;
	context.Dr7 = 0x00000001;

	NtContinue(&context, FALSE);
}

PVOID HookExceptionDispatcher(PBYTE moduleBase) {
	
	PVOID wow64PrepareForException = ReturnWow64FunctionPointer(moduleBase);
	if (wow64PrepareForException == NULL) {
		printf("[ - ] Failed to get Wow64PrepareForException function pointer.\n");
		return NULL;
	}

	printf("[ * ] Wow64PrepareForException address: %p\n", wow64PrepareForException);

	DWORD oldProtect = 0x00;
	if (!VirtualProtect(wow64PrepareForException, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
		return NULL;
	}

	//
	// write pointer to ExceptionHandler
	//

	*(PVOID*)wow64PrepareForException = ExceptionHandler;

	if (!VirtualProtect(wow64PrepareForException, sizeof(PVOID), PAGE_READONLY, &oldProtect)) {
		return NULL;
	}

	printf("[ * ] pointer to ExceptionHandler written to: %p\n", wow64PrepareForException);

	return wow64PrepareForException;
}

BOOL UnhookExceptionDispatcher(PVOID wow64PrepareForException) {

	DWORD oldProtect = 0x00;

	if (!VirtualProtect(wow64PrepareForException, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
		return FALSE;
	}

	//
	// restore original function pointer
	//

	*(PVOID*)wow64PrepareForException = NULL;

	if (!VirtualProtect(wow64PrepareForException, sizeof(PVOID), PAGE_READONLY, &oldProtect)) {
		return FALSE;
	}

	return TRUE;
}