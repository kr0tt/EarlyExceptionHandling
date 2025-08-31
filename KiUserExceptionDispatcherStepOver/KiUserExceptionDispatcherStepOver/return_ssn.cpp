#include <Windows.h>
#include <stdio.h>
#include "structs.h"
#include "return_ssn.h"

extern PFUNCTION_ADDRESS_TABLE	functionAddressTable;

DWORD64 ReturnFunctionsSSN(UINT_PTR instructionPointer) {

    //
    // we adjust it back to the entry of the function stub because we are currently at the jmp instruction
    //
	
    ULONG_PTR ntFunctionAddress = instructionPointer - 3ull; 

    //
    // the SSNs are currently hardcoded for this POC
	// tested on Windows 10 22H2 19045.6093
    // use whatever method to get SSNs more reliably
    // 

	if (ntFunctionAddress == functionAddressTable->NtAllocateVirtualMemoryAddress) {
        return 0x18;
	}
	else if (ntFunctionAddress == functionAddressTable->NtProtectVirtualMemoryAddress) {
        return 0x50;
	}
    
	return 0x00; // fail miserably 
}

DWORD64 ReturnSyscallInstructionAddress(UINT_PTR instructionPointer) {

    BYTE opcodes[] = { 0x0F, 0x05 };
    for (UINT i = 0; i < (UINT)25; i++) {
		if (memcmp((PVOID)(instructionPointer + i), opcodes, sizeof(opcodes)) == 0) {
            return instructionPointer + i;
		}
    }
    
    return 0x00;
}
