#include <Windows.h>
#include <stdio.h>
#include "wow64_callback.h"

//
// these are all taken from here, all credits belong to @modexpblog:
//      - https://gist.github.com/odzhan/b4898fa96f36b131973f62b797c4f639
//      - https://modexp.wordpress.com/2023/04/19/finding-the-wow64-callback-table/
//

PIMAGE_SECTION_HEADER GetSectionFromRva(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    auto section = IMAGE_FIRST_SECTION(ntHeaders);

    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->SizeOfRawData)
        {
            return section;
        }
        section++;
    }

    return NULL;
}

//
// determines if data resides within read-only section of dll
//

BOOL IsReadOnlyPointer(PVOID moduleBase, PVOID pointer) {

    if (!pointer) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);

    ULONG_PTR imageStart = (ULONG_PTR)moduleBase;
    ULONG_PTR imageEnd = (imageStart + ntHeader->OptionalHeader.SizeOfImage);
    ULONG_PTR imagePointer = (ULONG_PTR)pointer;
  
    if (!(imagePointer > imageStart && imagePointer < imageEnd)) {
        return FALSE;
    }

    DWORD rva = (DWORD)(imagePointer - imageStart);
    PIMAGE_SECTION_HEADER section = GetSectionFromRva(ntHeader, rva);
    if (!section) {
        return FALSE;
    }

    return (*(PDWORD)section->Name == *(PDWORD)".rdata");
}

PVOID ReturnWow64FunctionPointer(PBYTE moduleBase) {

    STRING callbackFunction = RTL_CONSTANT_ANSI_STRING("Wow64PrepareForException");
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

    for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (*(PDWORD)section[i].Name == *(PDWORD)".rdata") {
            DWORD rva = section[i].VirtualAddress;
            DWORD entryCount = (section[i].Misc.VirtualSize - sizeof(STRING)) / sizeof(ULONG_PTR);
            PULONG_PTR pointer = (PULONG_PTR)(moduleBase + rva);

            for (DWORD j = 0; j < entryCount; j++) {

                if (!IsReadOnlyPointer(moduleBase, (LPVOID)pointer[j])) {
                    continue;
                }

                PSTRING api = (PSTRING)pointer[j];

                if (api->Length == callbackFunction.Length && api->MaximumLength == callbackFunction.MaximumLength) {
                    if (!strncmp(api->Buffer, callbackFunction.Buffer, callbackFunction.Length)) {
                        return (PVOID)pointer[j + 1];
                    }
                }
            }
            break;
        }
    }

    return NULL;
}


