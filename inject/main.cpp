#include "config.h"
#include "inject.h"
#include <cstdio>
#include <cstring>

// why?
static uint32_t prefix(char* s) {
    while (*s == ' ' || *s == '\t')
        s++;
    struct {
        const char* k;
        uint32_t    v;
    } t[] = { { "error", kLvErr }, { "print", kLvPrint }, { "warn", kLvWarn }, { "info", kLvInfo } };
    for (auto& x : t) {
        size_t n = strlen(x.k);
        if (_strnicmp(s, x.k, n))
            continue;
        if (s[n] && s[n] != ' ' && s[n] != '\t')
            continue;
        size_t i = n;
        while (s[i] == ' ' || s[i] == '\t')
            i++;
        memmove(s, s + i, strlen(s + i) + 1);
        return x.v;
    }
    return kLevel;
}

int main() {
    RbxChannel ch;
    if (!ch.start())
        return puts("start failed"), 1;
    // i dont know what puts does :sob:
    puts("warn|error|info|print <msg>");
    char b[512];
    while (ch.alive()) {
        printf("> ");
        if (!fgets(b, sizeof b, stdin))
            break;
        b[strcspn(b, "\r\n")] = 0;
        if (!_stricmp(b, "exit"))
            break;
        if (!*b)
            continue;
        uint32_t lv = prefix(b);
        if (!*b)
            continue;
        if (!ch.print(b, lv))
            puts("(no ack)");
    }
    ch.stop();
    return 0;
}
