// remote_call.cpp — aarch64 remote function calling via ptrace
// sets up regs + stack in the target process, traps on brk, restores

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <elf.h>
#include <android/log.h>
#include "remote_call.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "remote_call", __VA_ARGS__)

struct RemoteCtx {
    int pid;
    uintptr_t scratch_page;   // for stack + trampoline
    uintptr_t saved_regs[34]; // x0-x30, sp, pc, pstate
    bool inited;
};
static RemoteCtx g_ctx = {0};

// -------- primitive read/write --------
static bool rd(int pid, uintptr_t a, void* out, size_t n) {
    struct iovec l = { out, n };
    struct iovec r = { (void*)a, n };
    return process_vm_readv(pid, &l, 1, &r, 1, 0) == (ssize_t)n;
}
static bool wr(int pid, uintptr_t a, const void* in, size_t n) {
    struct iovec l = { (void*)in, n };
    struct iovec r = { (void*)a, n };
    return process_vm_writev(pid, &l, 1, &r, 1, 0) == (ssize_t)n;
}

// -------- register access --------
struct user_pt_regs_a64 {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static bool get_regs(int pid, struct user_pt_regs_a64* r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}
static bool set_regs(int pid, const struct user_pt_regs_a64* r) {
    struct iovec iov = { (void*)r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == 0;
}

// -------- module / symbol lookup --------
static uintptr_t module_base(int pid, const char* name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            sscanf(line, "%lx", (unsigned long*)&base);
            break;
        }
    }
    fclose(f);
    return base;
}

// parse dynamic symbol table of a mapped module using its on-disk file
// this is simplified; android maps .so from /data/app/.../base.apk!/lib/...
// we locate the mapped file via /proc/<pid>/map_files
static uintptr_t module_sym(int pid, const char* module, const char* sym) {
    // find the map_files entry for the module
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[1024];
    uintptr_t base = 0;
    char backing[512] = {0};
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module)) {
            sscanf(line, "%*lx-%*lx %*s %*x %*s %*s %511s", backing);
            sscanf(line, "%lx", (unsigned long*)&base);
            break;
        }
    }
    fclose(f);
    if (!base) return 0;

    // try to open the backing file directly
    FILE* so = fopen(backing, "rb");
    if (!so) {
        LOG("cannot open %s (apk-internal? need extraction)", backing);
        return 0;
    }

    // parse ELF dynsym
    Elf64_Ehdr eh;
    fread(&eh, 1, sizeof(eh), so);
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) { fclose(so); return 0; }

    Elf64_Shdr shstr;
    fseek(so, eh.e_shoff + eh.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    fread(&shstr, 1, sizeof(shstr), so);

    char* shstrtab = (char*)malloc(shstr.sh_size);
    fseek(so, shstr.sh_offset, SEEK_SET);
    fread(shstrtab, 1, shstr.sh_size, so);

    uintptr_t result = 0;
    for (int i = 0; i < eh.e_shnum; i++) {
        Elf64_Shdr sh;
        fseek(so, eh.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
        fread(&sh, 1, sizeof(sh), so);
        const char* nm = shstrtab + sh.sh_name;

        if ((sh.sh_type == SHT_DYNSYM || sh.sh_type == SHT_SYMTAB)) {
            Elf64_Shdr linked;
            fseek(so, eh.e_shoff + sh.sh_link * sizeof(Elf64_Shdr), SEEK_SET);
            fread(&linked, 1, sizeof(linked), so);

            char* strtab = (char*)malloc(linked.sh_size);
            fseek(so, linked.sh_offset, SEEK_SET);
            fread(strtab, 1, linked.sh_size, so);

            size_t n = sh.sh_size / sizeof(Elf64_Sym);
            for (size_t j = 0; j < n; j++) {
                Elf64_Sym sym_entry;
                fseek(so, sh.sh_offset + j * sizeof(Elf64_Sym), SEEK_SET);
                fread(&sym_entry, 1, sizeof(sym_entry), so);
                if (strcmp(strtab + sym_entry.st_name, sym) == 0) {
                    result = base + sym_entry.st_value;
                    break;
                }
            }
            free(strtab);
            if (result) break;
        }
    }
    free(shstrtab);
    fclose(so);
    return result;
}

// -------- public API --------
bool remote_call_init(int pid) {
    g_ctx.pid = pid;

    // reserve a page in the target for stack + trampoline
    uintptr_t dlopen_addr = module_sym(pid, "libdl.so", "mmap");
    if (!dlopen_addr) {
        LOG("cannot locate mmap in target");
        return false;
    }

    // call mmap(NULL, 0x1000, RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
    uint64_t args[6] = { 0, 0x1000, 7, 0x22, (uint64_t)-1, 0 };
    g_ctx.scratch_page = remote_call(pid, dlopen_addr, args, 6);
    if (!g_ctx.scratch_page) {
        LOG("mmap in target failed");
        return false;
    }
    LOG("scratch page @ 0x%lx", (unsigned long)g_ctx.scratch_page);

    // save regs — we'll restore after each call
    struct user_pt_regs_a64 r;
    if (!get_regs(pid, &r)) return false;
    memcpy(g_ctx.saved_regs, &r, sizeof(r));
    g_ctx.inited = true;
    return true;
}

void remote_call_free(int pid) {
    g_ctx.inited = false;
}

uintptr_t remote_mmap(int pid, size_t size, int prot) {
    uintptr_t mmap_addr = module_sym(pid, "libdl.so", "mmap");
    if (!mmap_addr) return 0;
    uint64_t args[6] = { 0, size, (uint64_t)prot, 0x22, (uint64_t)-1, 0 };
    return remote_call(pid, mmap_addr, args, 6);
}

bool remote_write(int pid, uintptr_t addr, const void* data, size_t len) {
    return wr(pid, addr, data, len);
}
bool remote_read(int pid, uintptr_t addr, void* out, size_t len) {
    return rd(pid, addr, out, len);
}

uintptr_t remote_sym(int pid, const char* module, const char* symbol) {
    return module_sym(pid, module, symbol);
}

uintptr_t remote_call(int pid, uintptr_t fn, const uint64_t* args, int nargs) {
    if (!g_ctx.inited && g_ctx.scratch_page == 0) return 0;

    struct user_pt_regs_a64 saved, r;
    if (!get_regs(pid, &saved)) return 0;
    r = saved;

    // set up args x0-x5
    for (int i = 0; i < nargs && i < 6; i++) r.regs[i] = args[i];

    // use top of scratch page as stack
    uintptr_t stack = g_ctx.scratch_page + 0x800;
    r.sp = stack;
    r.pc = fn;
    r.regs[30] = 0; // lr = 0 so we trap when fn returns

    // push a trap marker at stack top
    uint32_t brk = 0xd4200000; // brk #0
    wr(pid, stack - 4, &brk, 4);
    r.sp = stack - 4;

    if (!set_regs(pid, &r)) return 0;

    // continue until SIGTRAP/SIGSEGV
    ptrace(PTRACE_CONT, pid, 0, 0);
    int status = 0;
    waitpid(pid, &status, 0);

    if (!WIFSTOPPED(status)) return 0;
    int sig = WSTOPSIG(status);
    if (sig != SIGTRAP && sig != SIGSEGV) {
        LOG("unexpected signal %d during remote call", sig);
        set_regs(pid, &saved);
        return 0;
    }

    // read return value from x0
    struct user_pt_regs_a64 after;
    get_regs(pid, &after);
    uintptr_t retval = after.regs[0];

    // restore
    set_regs(pid, &saved);
    return retval;
}
