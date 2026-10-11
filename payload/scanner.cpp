// scanner.cpp — pattern search in mapped memory
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <android/log.h>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "scanner", __VA_ARGS__)

namespace scanner {

uintptr_t find(uintptr_t start, size_t size, const char* pat, const char* mask) {
    size_t plen = strlen(mask);
    if (plen == 0 || size < plen) return 0;
    for (uintptr_t i = 0; i < size - plen; i++) {
        bool match = true;
        for (size_t j = 0; j < plen; j++) {
            if (mask[j] == '?') continue;
            if (*(unsigned char*)(start + i + j) != (unsigned char)pat[j]) {
                match = false;
                break;
            }
        }
        if (match) return start + i;
    }
    return 0;
}

// read /proc/self/maps to find module range
struct Range { uintptr_t base; size_t size; };

Range module_range(const char* name) {
    Range out = {0, 0};
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return out;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        uintptr_t a, b;
        sscanf(line, "%lx-%lx", (unsigned long*)&a, (unsigned long*)&b);
        if (out.base == 0 || a < out.base) out.base = a;
        if (b > out.base + out.size) out.size = b - out.base;
    }
    fclose(f);
    return out;
}

} // namespace scanner
