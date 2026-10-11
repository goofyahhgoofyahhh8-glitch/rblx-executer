cmake_minimum_required(VERSION 3.20)
project(rblx-executor CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT ANDROID)
    message(FATAL_ERROR "must be built with Android NDK toolchain")
endif()

# injector — standalone binary
add_executable(injector
    injector/injector.cpp
    injector/remote_call.cpp
)
target_link_libraries(injector log)

# payload — shared library injected into roblox
add_library(executor SHARED
    payload/libexecutor.cpp
    payload/scanner.cpp
    payload/hook.cpp
    payload/bridge.cpp
)
set_target_properties(executor PROPERTIES
    OUTPUT_NAME "executor"
    PREFIX "lib"
)
target_link_libraries(executor log)
