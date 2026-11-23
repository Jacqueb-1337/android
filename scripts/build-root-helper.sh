#!/usr/bin/env bash
# Build the root-only TUN broker for the Android ABIs we ship.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "$ANDROID_NDK_HOME" ]]; then echo "Set ANDROID_NDK_HOME" >&2; exit 1; fi
llvm="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
for abi in arm64-v8a armeabi-v7a; do
  if [[ "$abi" == "arm64-v8a" ]]; then cc=aarch64-linux-android26-clang
  else cc=armv7a-linux-androideabi26-clang; fi
  mkdir -p "app/src/main/jniLibs/$abi"
  "$llvm/$cc" -O2 -Wall -Wextra -Werror -fPIE -pie \
    -o "app/src/main/jniLibs/$abi/libnetmerge_root.so" \
    app/src/main/cpp/netmerge_root.c
done

