#!/usr/bin/env sh
# 火漆 · Sealing Wax — JNI bridge host smoke test.
#
# Builds the C core + wax_jni.cpp as a host shared library against a desktop
# JVM's jni.h, then drives the full bridge surface from Java: pairing, text
# seal/open (incl. multi-piece + partial), padding, replay/tamper errors,
# state export/import, file sealing with metadata, last-frame introspection
# and the ledger hash.
#
# Usage:  tools/jni-smoke/run.sh [path-to-jdk]
# Needs:  cmake, a C/C++ toolchain, and a JDK (javac/java with jni.h).
set -eu

JDK="${1:-${JAVA_HOME:-}}"
if [ -z "$JDK" ]; then
    for c in javac java; do command -v "$c" >/dev/null 2>&1 || {
        echo "error: no JDK found; pass one as argument or set JAVA_HOME" >&2; exit 1; };
    done
    JDK="$(dirname "$(dirname "$(command -v javac)")")"
fi
[ -f "$JDK/include/jni.h" ] || { echo "error: $JDK/include/jni.h missing" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building PIC core + libsodium =="
cmake -S "$ROOT/app/src/main/cpp/tests" -B "$WORK/build" \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS=-fPIC \
      -DCMAKE_CXX_FLAGS=-fPIC >/dev/null
cmake --build "$WORK/build" -j"$(nproc)" >/dev/null

echo "== building libwaxhost.so =="
g++ -shared -fPIC -O2 -std=c++17 \
    -I "$ROOT/app/src/main/cpp/core" -I "$ROOT/app/src/main/cpp/spake2" \
    -I "$WORK/build/libsodium" \
    -I "$ROOT/app/src/main/cpp/libsodium/src/libsodium/include" \
    -I "$ROOT/app/src/main/cpp/libsodium/src/libsodium/include/sodium" \
    -I "$JDK/include" -I "$JDK/include/linux" \
    "$ROOT/app/src/main/cpp/wax_jni.cpp" \
    "$ROOT/app/src/main/cpp/core/swx_frame.c" \
    "$ROOT/app/src/main/cpp/core/swx_session.c" \
    "$ROOT/app/src/main/cpp/core/swx_hash.c" \
    "$ROOT/app/src/main/cpp/spake2/spake2.c" \
    "$ROOT/app/src/main/cpp/spake2/sha512.c" \
    "$WORK/build/libsodium/libsodium.a" \
    -o "$WORK/libwaxhost.so" -lm

echo "== compiling & running Java smoke =="
mkdir -p "$WORK/classes"
javac -encoding UTF-8 -d "$WORK/classes" \
      "$ROOT/tools/jni-smoke/WaxNative.java" "$ROOT/tools/jni-smoke/JniSmoke.java"
java -Djava.library.path="$WORK" --enable-native-access=ALL-UNNAMED \
     -cp "$WORK/classes" JniSmoke
