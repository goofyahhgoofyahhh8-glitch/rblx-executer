// hook.cpp — aarch64 inline trampoline hook
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <android/log.h>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "hook", __VA_ARGS__)

namespace hook {

// aarch64 trampoline:
//   ldr x16, #8      ; 0x58000050
//   br  x16          ; 0xD61F0200
//   .quad <target>
static void build_trampoline(unsigned char* buf, void* dest) {
    uint32_t insn1 = 0x58000050;
    uint32_t insn2 = 0xD61F0200;
    memcpy(buf, &insn1, 4);
    memcpy(buf + 4, &insn2, 4);
    memcpy(buf + 8, &dest, 8);
}

// install — saves original bytes, patches target with jmp to hook_fn
bool install(void* target, void* hook_fn, void** original_trampoline) {
    uintptr_t tgt = (uintptr_t)target;
    long page = sysconf(_SC_PAGESIZE);

    // make page writable
    uintptr_t page_base = tgt & ~(page - 1);
    if (mprotect((void*)page_base, page * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOG("mprotect failed");
        return false;
    }

    // allocate original trampoline: [orig 16 bytes][jmp to target+16]
    unsigned char* orig = (unsigned char*)mmap(
        nullptr, 64, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (orig == MAP_FAILED) return false;

    memcpy(orig, (void*)tgt, 16);
    build_trampoline(orig + 16, (void*)(tgt + 16));
    __builtin___clear_cache((char*)orig, (char*)(orig + 32));
    *original_trampoline = orig;

    // write trampoline into target
    unsigned char tramp[16];
    build_trampoline(tramp, hook_fn);
    memcpy((void*)tgt, tramp, 16);
    __builtin___clear_cache((char*)tgt, (char*)(tgt + 16));

    // restore protection
    mprotect((void*)page_base, page * 2, PROT_READ | PROT_EXEC);
    return true;
}

} // namespace hook
