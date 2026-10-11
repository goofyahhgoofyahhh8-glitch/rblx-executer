cd ~/rblx-executer && cat > injector/injector.cpp << 'KANHA_EOF'
// injector.cpp — ptrace-based .so injector for android
// usage: su -c "./injector <process_name> <path_to_so>"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <android/log.h>
#include "remote_call.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "injector", __VA_ARGS__)

pid_t find_pid(const char* name) {
    DIR* d = opendir("/proc");
    if (!d) return -1;
    struct dirent* e;
    pid_t found = -1;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR) continue;
        char* endp;
        long pid = strtol(e->d_name, &endp, 10);
        if (*endp || pid <= 1) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[512] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        if (strstr(buf, name)) { found = (pid_t)pid; break; }
    }
    closedir(d);
    return found;
}

static char* slurp(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) return nullptr;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = (char*)malloc(sz);
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return nullptr; }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <process_name> <path_to_so>\n", argv[0]);
        return 1;
    }
    const char* proc_name = argv[1];
    const char* so_path   = argv[2];

    size_t so_size = 0;
    char* so_data = slurp(so_path, &so_size);
    if (!so_data) { LOG("cannot read %s", so_path); return 1; }
    LOG("loaded payload: %zu bytes", so_size);

    pid_t pid = find_pid(proc_name);
    if (pid <= 0) { LOG("process '%s' not found", proc_name); return 1; }
    LOG("target pid: %d", pid);

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        LOG("ptrace attach failed — root required?");
        return 1;
    }
    int status;
    waitpid(pid, &status, 0);
    LOG("attached");

    if (!remote_call_init(pid)) {
        LOG("remote_call init failed");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }
    LOG("remote_call ready");

    uintptr_t remote_so = remote_mmap(pid, so_size, PROT_READ | PROT_WRITE);
    if (!remote_so) { LOG("remote mmap failed"); goto cleanup; }
    LOG("remote_so = 0x%lx", (unsigned long)remote_so);

    if (!remote_write(pid, remote_so, so_data, so_size)) {
        LOG("remote write failed"); goto cleanup;
    }
    LOG("payload written");

    uintptr_t dlopen_addr = remote_sym(pid, "libdl.so", "dlopen");
    if (!dlopen_addr) { LOG("dlopen lookup failed"); goto cleanup; }
    LOG("dlopen @ 0x%lx", (unsigned long)dlopen_addr);

    const char* remote_path = "/data/local/tmp/libexecutor.so";
    uintptr_t path_addr = remote_mmap(pid, strlen(remote_path) + 1, PROT_READ | PROT_WRITE);
    remote_write(pid, path_addr, remote_path, strlen(remote_path) + 1);

    uint64_t args[2] = { (uint64_t)path_addr, 2 /* RTLD_NOW */ };
    uintptr_t handle = remote_call(pid, dlopen_addr, args, 2);
    LOG("dlopen returned 0x%lx", (unsigned long)handle);
    LOG(handle ? "PAYLOAD LOADED" : "PAYLOAD FAILED");

cleanup:
    ptrace(PTRACE_DETACH, pid, 0, 0);
    LOG("detached");
    free(so_data);
    return 0;
}
KANHA_EOF
echo "wrote injector.cpp — lines: $(wc -l < injector/injector.cpp)"
