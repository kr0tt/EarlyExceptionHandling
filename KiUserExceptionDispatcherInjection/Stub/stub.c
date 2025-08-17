#include <Windows.h>

#define NtCurrentProcess()(( HANDLE )( LONG_PTR )-1)
typedef VOID ( *Exec )( _In_ PVOID );
typedef NTSTATUS (NTAPI* _NtProtectVirtualMemory)(_In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );
	
int main(){

	PVOID wow64PrepareForException 				   = (PVOID)0xAAAAAAAAAAAAAAAA;
    Exec continueRun      		   				   = (PVOID)0xBBBBBBBBBBBBBBBB;
	_NtProtectVirtualMemory NtProtectVirtualMemory = ((_NtProtectVirtualMemory)0xCCCCCCCCCCCCCCCC);
	
	PVOID baseAddress 	 = wow64PrepareForException;
	SIZE_T regionSize 	 = sizeof(PVOID);
	ULONG oldProtect 	 = NULL;
	ULONG currentProtect = NULL;

	NtProtectVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, PAGE_READWRITE, &oldProtect);
	
	*(volatile PVOID*)wow64PrepareForException = NULL;
	
	NtProtectVirtualMemory(NtCurrentProcess(), &baseAddress, &regionSize, oldProtect, &currentProtect);
	
	continueRun(NULL);
	
}