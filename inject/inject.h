#pragma once
#include <windows.h>
#include <cstdint>

class RbxChannel {
public:
    static constexpr size_t kHijackN = 55; // MATCH THIS

    bool start();
    void stop();
    bool print(const char* msg, uint32_t level);
    bool alive() const;

private:
    HANDLE    proc_{};
    DWORD     pid_{};
    void*     chan_{};   // worker
    void*     worker_{}; // stub
    HANDLE    thread_{};

    bool       use_worker_{true};
    uintptr_t  cave_{};
    uint8_t    hijack_tpl_[64]{};
    uint8_t    hijack_orig_[64]{};

    bool prep(uintptr_t game);
    bool post(const char* msg, uint32_t level);
    bool trap(const char* msg, uint32_t level);
};
