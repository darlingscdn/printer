#include "sig.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

static uintptr_t search(const char* path) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE)
        return 0;

    DWORD sz = GetFileSize(f, nullptr);
    std::vector<uint8_t> buf(sz);
    DWORD rd = 0;
    ReadFile(f, buf.data(), sz, &rd, nullptr);
    CloseHandle(f); // some of this looks like junk but its not
    if (rd != sz)
        return 0;

    auto* dos = (IMAGE_DOS_HEADER*)buf.data();
    auto* nt  = (IMAGE_NT_HEADERS64*)(buf.data() + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5))
            continue;

        DWORD rva  = sec[i].VirtualAddress;
        DWORD raw  = sec[i].PointerToRawData;
        DWORD size = sec[i].SizeOfRawData ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;

        for (DWORD j = 0; j + sizeof(kSig) <= size; j++)
            if (!memcmp(buf.data() + raw + j, kSig, sizeof(kSig)))
                return rva + j;

        break;
    }

    return 0;
}

static void patch(uintptr_t rva) {
    char exe[MAX_PATH];
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    char* p = strrchr(exe, '\\'); if (p) *p = 0;
    p = strrchr(exe, '\\');       if (p) *p = 0;

    char cfg[MAX_PATH];
    snprintf(cfg, MAX_PATH, "%s\\inject\\config.h", exe); // you can rewrite updater if you want

    HANDLE f = CreateFileA(cfg, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE)
        return;
    DWORD sz = GetFileSize(f, nullptr);
    std::vector<char> content(sz + 1, 0);
    DWORD rd = 0;
    ReadFile(f, content.data(), sz, &rd, nullptr);
    CloseHandle(f);
    if (rd != sz)
        return;

    // format it so you dont just get the function
    const char* needle = "kPrint = 0x";
    char* pos       = strstr(content.data(), needle);
    if (!pos)
        return;
    char* val_start = pos + strlen(needle);
    char* val_end   = strchr(val_start, ';');
    if (!val_end)
        return;

    char hex[32];
    snprintf(hex, sizeof(hex), "%llX", (unsigned long long)rva);

    std::string out(content.data(), val_start);
    out += hex;
    out += val_end;

    f = CreateFileA(cfg, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    DWORD wr = 0;
    WriteFile(f, out.c_str(), (DWORD)out.size(), &wr, nullptr);
    CloseHandle(f);
}

int main(int argc, char** argv) {
    if (argc < 2) { // i know you are looking here because you are confused
        printf("update.exe <path>\n");
        return 1;
    }

    uintptr_t rva = search(argv[1]);
    if (!rva) {
        printf("Not found\n");
        return 1;
    }

    printf("kPrint = 0x%llX\n", (unsigned long long)rva);
    patch(rva);
    return 0;
}
