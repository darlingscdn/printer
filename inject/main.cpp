#include "config.h"
#include "inject.h"
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>

// big shellcode i did better this time then i did with py2py
static const uint8_t kShell[] = {
    0x41, 0x57,
    0x49, 0xBF,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x4C, 0x87, 0xFC,
    0x41, 0x5E,
    0x58,
    0x5A,
    0x4C, 0x87, 0xFC,
    0x41, 0x5F,
    0x48, 0x83, 0xEC, 0x20,
    0x33, 0xC9,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x20,
    0x48, 0xB8,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xC6, 0x00, 0x01,
    0x41, 0xFF, 0xE6
};

static bool alive(HANDLE proc) {
    return WaitForSingleObject(proc, 0) == WAIT_TIMEOUT;
}

static bool print(HANDLE proc, DWORD id, uintptr_t dst, LPVOID vs,
                     const uint8_t* code, size_t code_len,
                     const uint8_t* orig, uintptr_t flag,
                     const char* msg) {
    uintptr_t zero = 0;
    uint8_t   zero8 = 0;
    // main function of the entire project

    WriteProcessMemory(proc, (BYTE*)vs + 0x18,  msg,    strlen(msg) + 1, nullptr);
    WriteProcessMemory(proc, (BYTE*)vs + 0x800, &zero8, 1,               nullptr);

    DWORD prot = 0;
    VirtualProtectEx(proc, (LPVOID)dst, code_len, PAGE_EXECUTE_READWRITE, &prot);
    SIZE_T written = 0;
    bool ok = WriteProcessMemory(proc, (LPVOID)dst, code, code_len, &written)
              && written == code_len;
    VirtualProtectEx(proc, (LPVOID)dst, code_len, prot, &prot);
    if (!ok)
        return false;

    // long
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD  tid  = 0;
    THREADENTRY32 te{ sizeof(te) };
    if (snap != INVALID_HANDLE_VALUE && Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == id) {
                tid = hijack(proc, te.th32ThreadID, dst, vs);
                if (tid) break;
            }
        } while (Thread32Next(snap, &te));
    }
    if (snap != INVALID_HANDLE_VALUE)
        CloseHandle(snap);

    if (tid) {
        uint8_t done = 0;
        for (int i = 0; i < 200 && !done; i++) {
            Sleep(5);
            ReadProcessMemory(proc, (LPCVOID)flag, &done, 1, nullptr);
        }
    }

    DWORD tmp = 0;
    VirtualProtectEx(proc, (LPVOID)dst, code_len, PAGE_EXECUTE_READWRITE, &tmp);
    WriteProcessMemory(proc, (LPVOID)dst, orig, code_len, nullptr);
    VirtualProtectEx(proc, (LPVOID)dst, code_len, tmp, &tmp);

    return tid != 0;
}

int main() {
    DWORD id = pid("RobloxPlayerBeta.exe"); // you would think roblox is not in beta anymore
    if (!id) {
        printf("Roblox not found\n");
        return 1;
    }

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
    if (!proc) {
        printf("OpenProcess failed\n");
        return 1;
    }

    uintptr_t roblox = base(proc, "RobloxPlayerBeta.exe");
    uintptr_t win32u = base(proc, "win32u.dll");
    // setup
    if (!roblox || !win32u) {
        CloseHandle(proc);
        return 1;
    }

    uintptr_t dst = cave(proc, win32u, kCaveStart, kCaveEnd, sizeof(kShell));
    if (!dst) {
        CloseHandle(proc);
        return 1;
    }

    LPVOID vs = VirtualAllocEx(proc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!vs) {
        CloseHandle(proc);
        return 1;
    }

    uintptr_t fn   = roblox + kPrint;
    uintptr_t str  = (uintptr_t)vs + 0x18;
    uintptr_t flag = (uintptr_t)vs + 0x800;
    uintptr_t zero = 0;

    WriteProcessMemory(proc, (BYTE*)vs + 0x00, &zero, 8, nullptr);
    WriteProcessMemory(proc, (BYTE*)vs + 0x08, &fn,   8, nullptr);
    WriteProcessMemory(proc, (BYTE*)vs + 0x10, &str,  8, nullptr);

    uint8_t code[sizeof(kShell)];
    memcpy(code, kShell, sizeof(code));
    uintptr_t vp = (uintptr_t)vs;
    memcpy(code + 4,  &vp,  8);
    memcpy(code + 38, &flag, 8);

    uint8_t orig[sizeof(code)];
    ReadProcessMemory(proc, (LPCVOID)dst, orig, sizeof(code), nullptr);

    char msg[256]; // reduced from 512 because it has some issues or something i dont remember
    while (alive(proc)) {
        printf("print > ");
        if (!fgets(msg, sizeof(msg), stdin))
            break;

        for (int i = 0; msg[i]; i++)
            if (msg[i] == '\n') { msg[i] = 0; break; }

        if (!_stricmp(msg, "exit")) // ngl i forgot i did this i just ctrl c
            break;

        if (!msg[0])
            continue;

        print(proc, id, dst, vs, code, sizeof(code), orig, flag, msg);
    }

    VirtualFreeEx(proc, vs, 0, MEM_RELEASE);
    CloseHandle(proc);
    return 0;
}
