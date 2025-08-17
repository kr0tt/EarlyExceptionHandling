#pragma once

#include <Windows.h>

VOID SetHardwareBreakpoint(ULONG_PTR ntFunctionAddress);
PVOID HookExceptionDispatcher(PBYTE moduleBase);
BOOL UnhookExceptionDispatcher(PVOID wow64PrepareForException);
