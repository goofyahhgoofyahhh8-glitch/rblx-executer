#pragma once
#include <cstdint>

bool remote_call_init(int pid);
void remote_call_free(int pid);

uintptr_t remote_mmap(int pid, size_t size, int prot);
bool remote_write(int pid, uintptr_t addr, const void* data, size_t len);
bool remote_read(int pid, uintptr_t addr, void* out, size_t len);

uintptr_t remote_sym(int pid, const char* module, const char* symbol);

// call a remote function with up to 6 aarch64 args
uintptr_t remote_call(int pid, uintptr_t fn, const uint64_t* args, int nargs);
