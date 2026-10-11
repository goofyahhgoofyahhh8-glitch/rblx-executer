// bridge.cpp — unix socket server inside the injected so
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <android/log.h>

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "bridge", __VA_ARGS__)

namespace bridge {

static const char* SOCK_PATH = "/data/local/tmp/executor.sock";
static int g_client = -1;
static void (*g_execute)(const char*) = nullptr;

static void* server_thread(void*) {
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { LOG("socket failed"); return nullptr; }

    unlink(SOCK_PATH);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG("bind failed"); return nullptr;
    }
    chmod(SOCK_PATH, 0666);
    listen(srv, 1);
    LOG("listening on %s", SOCK_PATH);

    while (true) {
        int cli = accept(srv, nullptr, nullptr);
        if (cli < 0) continue;
        LOG("client connected");
        g_client = cli;

        char buf[65536];
        ssize_t n;
        while ((n = recv(cli, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = 0;
            if (g_execute) g_execute(buf);
        }
        close(cli);
        g_client = -1;
        LOG("client disconnected");
    }
    return nullptr;
}

void start(void (*exec_fn)(const char*)) {
    g_execute = exec_fn;
    pthread_t t;
    pthread_create(&t, nullptr, server_thread, nullptr);
}

} // namespace bridge
