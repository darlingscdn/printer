#include "inject.h"
#include "config.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <cstddef>
#include <cstring>
#include <vector>

#pragma comment(lib, "psapi.lib")

// i hope you know what a pid is
static DWORD pid(const char* exe) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32 e{ sizeof e };
    DWORD          out = 0;
    for (BOOL ok = Process32First(s, &e); ok; ok = Process32Next(s, &e))
        if (!_stricmp(e.szExeFile, exe)) {
            out = e.th32ProcessID;
            break;
        }
    CloseHandle(s);
    return out;
}

static uintptr_t mod(HANDLE proc, const char* name) {
    HMODULE m[1024];
    DWORD   n = 0;
    if (!EnumProcessModules(proc, m, sizeof m, &n))
        return 0;
    char path[MAX_PATH];
    for (unsigned i = 0; i < n / sizeof(HMODULE); i++) // i dont know why but this took a while
        if (GetModuleBaseNameA(proc, m[i], path, MAX_PATH) && !_stricmp(path, name))
            return (uintptr_t)m[i];
    return 0;
}

static uintptr_t cave(HANDLE proc, uintptr_t dll, size_t lo, size_t hi, size_t need) { // pretty much this finds a place to shove our stuff
    size_t               span = hi - lo;
    std::vector<uint8_t> buf(span);
    SIZE_T               rd = 0;
    if (!ReadProcessMemory(proc, (LPCVOID)(dll + lo), buf.data(), span, &rd) || rd < need)
        return 0;
    for (size_t i = 0; i + need <= rd; i++) {
        if (buf[i] != 0xCC)
            continue;
        size_t run = 0;
        while (run < need && buf[i + run] == 0xCC)
            run++;
        if (run < 16) {
            i += run;
            continue;
        }
        size_t j = i + run; // pad
        for (; j < i + need; j++)
            if (!(buf[j] == 0xCC || buf[j] == 0x90 || buf[j] == 0xC3 || buf[j] == 0xC2 || buf[j] == 0))
                break;
        if (j < i + need) {
            i = j;
            continue;
        }
        return dll + lo + i;
    }
    return 0;
}

static bool route(HANDLE proc, DWORD pid, uintptr_t caveaddr, void* vs) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) // this is equal to a fucking a sanity check
        return false;
    THREADENTRY32 te{ sizeof te };
    bool          ok = false;
    for (BOOL b = Thread32First(snap, &te); b; b = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid)
            continue;
        HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0,
                               te.th32ThreadID);
        if (!th)
            continue;
        if (SuspendThread(th) == (DWORD)-1) {
            CloseHandle(th);
            continue;
        }
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(th, &ctx)) {
            ResumeThread(th);
            CloseHandle(th);
            continue;
        }
        uintptr_t ret = 0;
        SIZE_T    n   = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)ctx.Rsp, &ret, 8, &n) || n != 8 || ret < 0x10000) {
            ResumeThread(th);
            CloseHandle(th);
            continue;
        }
        WriteProcessMemory(proc, vs, &ret, 8, nullptr); // 8
        WriteProcessMemory(proc, (void*)ctx.Rsp, &caveaddr, 8, nullptr);
        ResumeThread(th);
        // 102-105
        CloseHandle(th); 
        ok = true;
        break;
    }
    CloseHandle(snap);
    return ok;
}

#pragma pack(push, 1)
struct RemoteCh {
    uint32_t cmd;
    uint32_t level;
    uint64_t print_fn;
    char     text[496];
    uint32_t done;

    static constexpr size_t kTextCap = sizeof text;
};
#pragma pack(pop)

static_assert(offsetof(RemoteCh, done) == 0x200, "");

static const uint8_t kWorker[] = {
    0x53, 0x48, 0x89, 0xcb, 0x8b, 0x03, 0x85, 0xc0, 0x74, 0x37, 0x83, 0xf8, 0x02, 0x74, 0x36, 0x83, 0xf8, 0x01, 0x75, 0xf0,
    0x48, 0x8d, 0x53, 0x10, 0x8b, 0x4b, 0x04, 0x48, 0x8b, 0x43, 0x08, 0x49, 0x89, 0xe4, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83,
    0xec, 0x20, 0xff, 0xd0, 0x4c, 0x89, 0xe4, 0xc7, 0x03, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x83, 0x00, 0x02, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0xeb, 0xc3, 0xf3, 0x90, 0xeb, 0xbf, 0x5b, 0xc3,
};
// shellcode i dont understand anymore
static const uint8_t kHijack[] = {
    0x41, 0x57, 0x49, 0xBF, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x4C, 0x87, 0xFC, 0x41, 0x5E, 0x58, 0x5A, 0x4C,
    0x87, 0xFC, 0x41, 0x5F, 0x48, 0x83, 0xEC, 0x20, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20, 0x48,
    0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xC6, 0x00, 0x01, 0x41, 0xFF, 0xE6,
};

static_assert(sizeof(kHijack) == RbxChannel::kHijackN); // it took me a while to understand the rbx stuff but this is for learning after all

bool RbxChannel::prep(uintptr_t game) {
    uintptr_t w32 = mod(proc_, "win32u.dll");
    if (!w32)
        return false;
    cave_ = cave(proc_, w32, kCaveLo, kCaveHi, sizeof kHijack);
    if (!cave_)
        return false;

    uintptr_t fn   = game + kPrint;
    uintptr_t strp = (uintptr_t)chan_ + 0x18;
    uintptr_t z    = 0;
    WriteProcessMemory(proc_, chan_, &z, 8, nullptr);
    WriteProcessMemory(proc_, (uint8_t*)chan_ + 8, &fn, 8, nullptr);
    WriteProcessMemory(proc_, (uint8_t*)chan_ + 0x10, &strp, 8, nullptr);

    memcpy(hijack_tpl_, kHijack, sizeof kHijack);
    {
        uintptr_t va = (uintptr_t)chan_;
        uintptr_t fl = (uintptr_t)chan_ + 0x800;
        memcpy(hijack_tpl_ + 4, &va, 8);
        memcpy(hijack_tpl_ + 41, &fl, 8);
    }
    ReadProcessMemory(proc_, (void*)cave_, hijack_orig_, sizeof kHijack, nullptr);
    return true; // rad ward 
}

bool RbxChannel::start() {
    stop();
    use_worker_ = true;
    cave_       = 0;

    // overflow 
    pid_ = pid("RobloxPlayerBeta.exe");
    if (!pid_)
        return false;

    proc_ = OpenProcess(PROCESS_ALL_ACCESS, 0, pid_);
    if (!proc_)
        return false;

    // overflow
    uintptr_t game = mod(proc_, "RobloxPlayerBeta.exe");
    if (!game) {
        CloseHandle(proc_);
        proc_ = nullptr;
        return false;
    }

    chan_   = VirtualAllocEx(proc_, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    worker_ = VirtualAllocEx(proc_, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!chan_ || !worker_) {
        stop();
        return false;
    }

    SIZE_T wz = 0;
    if (!WriteProcessMemory(proc_, worker_, kWorker, sizeof kWorker, &wz) || wz != sizeof kWorker) {
        stop();
        return false;
    }
    DWORD oldprot = 0;
    if (!VirtualProtectEx(proc_, worker_, 0x1000, PAGE_EXECUTE_READWRITE, &oldprot)) {
        stop();
        return false;
    }
    FlushInstructionCache(proc_, worker_, sizeof kWorker);

    RemoteCh init{};
    init.print_fn = game + kPrint;
    init.cmd      = 0;
    init.level    = kLevel;
    init.done     = 0;
    if (!WriteProcessMemory(proc_, chan_, &init, sizeof init, nullptr)) {
        stop();
        return false;
    }

    DWORD  tid = 0;
    // d1
    HANDLE th  = CreateRemoteThread(proc_, nullptr, 0, (LPTHREAD_START_ROUTINE)worker_, chan_, 0, &tid);
    if (!th) {
        VirtualFreeEx(proc_, worker_, 0, MEM_RELEASE);
        worker_ = nullptr;
        use_worker_ = false;
        if (!prep(game)) {
            stop();
            return false;
        }
        return true;
    }
    thread_ = th;

    Sleep(200);
    DWORD ec       = (DWORD)STILL_ACTIVE;
    BOOL  got_exit = GetExitCodeThread(thread_, &ec);
    // d2
    if (!got_exit || ec != STILL_ACTIVE) {
        WaitForSingleObject(thread_, 3000);
        CloseHandle(thread_);
        thread_ = nullptr;
        VirtualFreeEx(proc_, worker_, 0, MEM_RELEASE);
        worker_     = nullptr;
        use_worker_ = false;
        if (!prep(game)) {
            stop();
            return false;
        }
    }

    return true;
}
// all rbx stuff i am still a little confused
void RbxChannel::stop() {
    if (use_worker_ && proc_ && chan_) {
        uint32_t die = 2;
        WriteProcessMemory(proc_, chan_, &die, sizeof die, nullptr);
    }
    if (thread_) {
        WaitForSingleObject(thread_, 5000);
        CloseHandle(thread_);
        thread_ = nullptr;
    }
    if (proc_ && cave_) {
        DWORD j;
        VirtualProtectEx(proc_, (void*)cave_, kHijackN, PAGE_EXECUTE_READWRITE, &j);
        WriteProcessMemory(proc_, (void*)cave_, hijack_orig_, kHijackN, nullptr);
        VirtualProtectEx(proc_, (void*)cave_, kHijackN, j, &j);
        cave_ = 0;
    }
    if (proc_) {
        if (chan_)
            VirtualFreeEx(proc_, chan_, 0, MEM_RELEASE);
        if (worker_)
            VirtualFreeEx(proc_, worker_, 0, MEM_RELEASE);
        CloseHandle(proc_);
    }
    proc_ = chan_ = worker_ = nullptr;
    pid_  = 0;
}

bool RbxChannel::alive() const {
    return proc_ && WaitForSingleObject(proc_, 0) == WAIT_TIMEOUT;
}

bool RbxChannel::print(const char* msg, uint32_t level) {
    if (!proc_ || !chan_)
        return false;

    if (use_worker_)
        return post(msg, level);
    return trap(msg, level);
}

bool RbxChannel::post(const char* msg, uint32_t level) {
    for (int wait = 0; wait < 200; wait++) {
        uint32_t c = 0;
        ReadProcessMemory(proc_, chan_, &c, sizeof c, nullptr);
        if (c == 0)
            break;
        Sleep(5);
    }

    uint32_t z = 0;
    WriteProcessMemory(proc_, (uint8_t*)chan_ + offsetof(RemoteCh, done), &z, sizeof z, nullptr);

    size_t n = strlen(msg);
    if (n >= RemoteCh::kTextCap)
        n = RemoteCh::kTextCap - 1;
    WriteProcessMemory(proc_, (uint8_t*)chan_ + offsetof(RemoteCh, text), msg, n + 1, nullptr);
    WriteProcessMemory(proc_, (uint8_t*)chan_ + offsetof(RemoteCh, level), &level, sizeof level, nullptr);

    uint32_t one = 1;
    WriteProcessMemory(proc_, chan_, &one, sizeof one, nullptr);

    for (int i = 0; i < 500; i++) {
        uint32_t d = 0;
        ReadProcessMemory(proc_, (uint8_t*)chan_ + offsetof(RemoteCh, done), &d, sizeof d, nullptr);
        if (d)
            return true;
        Sleep(10);
    }
    return false;
}

bool RbxChannel::trap(const char* msg, uint32_t level) {
    uint8_t sc[kHijackN];
    memcpy(sc, hijack_tpl_, kHijackN);
    memcpy(sc + 29, &level, sizeof level);

    uint8_t zf = 0;
    WriteProcessMemory(proc_, (uint8_t*)chan_ + 0x18, msg, strlen(msg) + 1, nullptr);
    WriteProcessMemory(proc_, (uint8_t*)chan_ + 0x800, &zf, 1, nullptr);

    DWORD pr, jk;
    VirtualProtectEx(proc_, (void*)cave_, kHijackN, PAGE_EXECUTE_READWRITE, &pr);
    SIZE_T W = 0;
    if (!WriteProcessMemory(proc_, (void*)cave_, sc, kHijackN, &W) || W != kHijackN) {
        VirtualProtectEx(proc_, (void*)cave_, kHijackN, pr, &jk);
        return false;
    }
    VirtualProtectEx(proc_, (void*)cave_, kHijackN, pr, &jk);

    if (!route(proc_, pid_, cave_, chan_))
        return false;

    uintptr_t fl = (uintptr_t)chan_ + 0x800;
    uint8_t  d   = 0;
    for (int i = 0; i < 400 && !d; i++, Sleep(5))
        ReadProcessMemory(proc_, (LPCVOID)fl, &d, 1, nullptr);
    Sleep(20);

    VirtualProtectEx(proc_, (void*)cave_, kHijackN, PAGE_EXECUTE_READWRITE, &pr);
    WriteProcessMemory(proc_, (void*)cave_, hijack_orig_, kHijackN, nullptr);
    VirtualProtectEx(proc_, (void*)cave_, kHijackN, pr, &jk);

    return d != 0;
}
