// libexecutor.cpp — injected payload entry point
// finds Luau functions, hooks luau_load, exposes bridge

#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <android/log.h>
#include "scanner.cpp"
#include "hook.cpp"
#include "bridge.cpp"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "libexecutor", __VA_ARGS__)

// ---------- signatures ----------
// these MUST be re-derived from the current libroblox.so in IDA/Ghidra
// each entry is a byte pattern + mask ('x' = match, '?' = wildcard)
struct Pattern {
    const char* bytes;
    const char* mask;
    const char* name;
};

static Pattern PATTERNS[] = {
    // example placeholder — replace with real bytes from IDA
    // luau_load prologue on aarch64 typically starts with a stp x29,x30 store
    {
        "\xFD\x7B\xBF\xA9\xF4\x4F\x01\xA9",
        "xxxxxxxx",
        "luau_load_candidate"
    },
    // add more as you find them (luaD_call, luaH_new, etc.)
};

// ---------- state ----------
static uintptr_t g_libroblox_base = 0;
static size_t    g_libroblox_size = 0;
static void*     g_luau_load_orig = nullptr;
static uintptr_t g_luau_load_addr = 0;

// saved lua_State pointer — updated every time a script loads
static void*     g_lua_state = nullptr;

// ---------- hooked luau_load ----------
extern "C" int hook_luau_load(void* L, const char* chunkname,
                              const char* data, size_t size, int env) {
    LOG("luau_load: %s (%zu bytes)", chunkname ? chunkname : "?", size);
    g_lua_state = L;
    typedef int (*fn_t)(void*, const char*, const char*, size_t, int);
    return ((fn_t)g_luau_load_orig)(L, chunkname, data, size, env);
}

// ---------- exec callback (from bridge) ----------
static void execute_lua(const char* src) {
    LOG("execute requested (%zu bytes)", strlen(src));
    if (!g_lua_state) {
        LOG("no lua_State yet — load a game first");
        return;
    }
    if (!g_luau_load_orig) {
        LOG("luau_load not hooked");
        return;
    }
    // call luau_load(L, "@executor", src, strlen(src), 0)
    // then luaD_call / lua_pcall — needs more signatures from IDA
    // left as extension point
}

// ---------- payload entry ----------
__attribute__((constructor))
static void on_load() {
    LOG("libexecutor loaded");

    auto range = scanner::module_range("libroblox.so");
    g_libroblox_base = range.base;
    g_libroblox_size = range.size;
    LOG("libroblox.so @ 0x%lx (%zu bytes)",
        (unsigned long)g_libroblox_base, g_libroblox_size);

    if (!g_libroblox_base) {
        LOG("libroblox.so not mapped — abort");
        return;
    }

    // scan for patterns
    for (auto& p : PATTERNS) {
        uintptr_t hit = scanner::find(g_libroblox_base, g_libroblox_size,
                                      p.bytes, p.mask);
        if (hit) {
            LOG("pattern '%s' hit @ 0x%lx", p.name, (unsigned long)hit);
            if (strcmp(p.name, "luau_load_candidate") == 0) {
                g_luau_load_addr = hit;
            }
        } else {
            LOG("pattern '%s' not found", p.name);
        }
    }

    if (g_luau_load_addr) {
        if (hook::install((void*)g_luau_load_addr,
                          (void*)hook_luau_load,
                          &g_luau_load_orig)) {
            LOG("luau_load hooked");
        } else {
            LOG("hook install failed");
        }
    }

    // start bridge
    bridge::start(execute_lua);
    LOG("bridge started");
}
