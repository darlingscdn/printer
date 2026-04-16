#pragma once
#include <cstdint>

constexpr uintptr_t kPrint   = 0x1D96FB0; // use update.exe on new roblox update
constexpr uint32_t  kLvPrint = 0, kLvInfo = 1, kLvWarn = 2, kLvErr = 3;
constexpr uint32_t  kLevel   = kLvPrint;

constexpr size_t kCaveLo = 0x1000, kCaveHi = 0x20000;
