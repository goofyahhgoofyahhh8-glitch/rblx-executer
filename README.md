# rblx-executor

A from-scratch Roblox executor — injector, hook engine, and script bridge.

## architecture

    [injector binary] --ptrace--> [Roblox process]
                                      |
                                      v
                              [libexecutor.so]
                                 - pattern scanner
                                 - luau_load hook
                                 - unix socket bridge
                                      ^
                                      |
                          [UI / script sender]

## requirements (build)

- Android NDK r25+ (aarch64)
- cmake 3.20+
- rooted android device for runtime

## build

    ./build.sh

output: `build/injector` (executable) and `build/libexecutor.so`

## runtime

    su -c "./injector com.roblox.client ./libexecutor.so"
    # in another shell:
    python sender.py my_script.lua

## status

research scaffold. signature patterns must be re-derived
from the current libroblox.so for each Roblox version.
