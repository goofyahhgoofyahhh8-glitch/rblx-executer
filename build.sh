#!/data/data/com.termux/files/usr/bin/bash
# rblx-executor build script
# requires: android ndk, cmake, ninja

set -e

NDK="${ANDROID_NDK_HOME:-/opt/android-ndk}"
if [ ! -d "$NDK" ]; then
    echo "error: set ANDROID_NDK_HOME to your NDK path"
    echo "  example: export ANDROID_NDK_HOME=/data/data/com.termux/files/home/android-ndk-r25c"
    exit 1
fi

TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN" ]; then
    echo "error: NDK toolchain not found at $TOOLCHAIN"
    exit 1
fi

mkdir -p build
cd build

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-26 \
    -DCMAKE_BUILD_TYPE=Release \
    -G Ninja

ninja

echo
echo "built:"
ls -lh injector libexecutor.so 2>/dev/null || true
