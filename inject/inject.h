#pragma once
#include <windows.h>
#include <cstdint>

DWORD     pid(const char* name);
uintptr_t base(HANDLE proc, const char* name);
uintptr_t cave(HANDLE proc, uintptr_t mod, size_t start, size_t end, size_t len);
DWORD     hijack(HANDLE proc, DWORD tid, uintptr_t dest, LPVOID vstack);
