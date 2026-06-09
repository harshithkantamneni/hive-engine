# HIVE Android — CMakeLists.txt for libhive_zeroize.so
#
# Native library build config for the JNI zeroize primitive. Consumed from
# Gradle via
# `android.externalNativeBuild.cmake.path = "src/main/jni/CMakeLists.txt"`.
#
# Target:   libhive_zeroize.so
# Loaded:   System.loadLibrary("hive_zeroize") — see DeviceSaltHandle.kt
#           companion-object init block.
# ABIs:     arm64-v8a, armeabi-v7a, x86_64, x86 (standard Android four).
#
# hive_zeroize.c calls into the Rust crate's `hive_core_zeroize` symbol
# (extern "C") rather than branching between bionic `memset_explicit` and an
# in-source volatile memset. The Rust-side `libhive_core.so` is built by
# cargo-ndk per the build.gradle.kts cargo block and lives at
# `target/<rust-triple>/release/libhive_core.so` for each ABI. This CMakeLists
# declares an IMPORTED library for `libhive_core.so` and links it into
# `libhive_zeroize.so`. The Rust impl handles all API levels uniformly via
# `zeroize::Zeroize::zeroize()`.
#
# NDK: r25+ is required for the toolchain (clang + linker). Since
# `memset_explicit` is no longer linked, the NDK requirement is purely for the
# toolchain itself.

cmake_minimum_required(VERSION 3.22.1)

project(hive_zeroize C)

# Position-independent code — required by Android NDK for .so targets.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# C standard: C11 minimum (we don't use C23 features in the source since the
# `memset_explicit` declaration is a local extern; bionic surfaces the symbol
# at runtime). C11 is the NDK r25+ default.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Warnings-as-errors posture — catch silent-regression at build time.
# `-Wall -Wextra -Werror` plus specific crypto-hygiene flags:
#   -Wstrict-prototypes    : catch function pointers with missing signatures
#   -Wvla                  : forbid variable-length arrays (stack exhaustion)
#   -Wshadow               : catch local/parameter shadowing bugs
add_compile_options(
    -Wall
    -Wextra
    -Werror
    -Wstrict-prototypes
    -Wvla
    -Wshadow
    # Hardening: stack protector + FORTIFY_SOURCE. Matches bionic defaults.
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    # PIE / full RELRO — mandatory for Android NDK output.
    -fPIE
)

# Link-time hardening.
add_link_options(
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

# Library target.
add_library(hive_zeroize SHARED
    hive_zeroize.c
)

# Declare `libhive_core.so` (built by cargo-ndk per the build.gradle.kts cargo
# block) as an IMPORTED SHARED library so the linker can resolve the
# `hive_core_zeroize` extern reference in hive_zeroize.c.
#
# The cargo-ndk integration writes per-ABI .so artifacts to:
#   <repo-root>/target/<rust-triple>/release/libhive_core.so
# where <rust-triple> is one of:
#   aarch64-linux-android   (ANDROID_ABI=arm64-v8a)
#   armv7-linux-androideabi (ANDROID_ABI=armeabi-v7a)
#   x86_64-linux-android    (ANDROID_ABI=x86_64)
#   i686-linux-android      (ANDROID_ABI=x86)
# CMake's per-ABI build (driven by Gradle's externalNativeBuild) sets
# ${ANDROID_ABI}; we map ABI → Rust triple via CMake conditionals. The
# `--target-dir ../../target` in build.gradle.kts cargo{} block places the
# artifacts at <android-module>/../../target/ which is <repo-root>/target/
# per the directory layout (mobile/android/../../target/ = ./target/).
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(HIVE_CORE_RUST_TRIPLE "aarch64-linux-android")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(HIVE_CORE_RUST_TRIPLE "armv7-linux-androideabi")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(HIVE_CORE_RUST_TRIPLE "x86_64-linux-android")
elseif(ANDROID_ABI STREQUAL "x86")
    set(HIVE_CORE_RUST_TRIPLE "i686-linux-android")
else()
    message(FATAL_ERROR "Unsupported ANDROID_ABI=${ANDROID_ABI};")
endif()

# CMAKE_CURRENT_LIST_DIR is mobile/android/src/main/jni; up four = repo root.
set(HIVE_CORE_SO_PATH
    "${CMAKE_CURRENT_LIST_DIR}/../../../../../target/${HIVE_CORE_RUST_TRIPLE}/release/libhive_core.so"
)

add_library(hive_core SHARED IMPORTED)
set_target_properties(hive_core PROPERTIES
    IMPORTED_LOCATION "${HIVE_CORE_SO_PATH}"
)

# Link the Rust-side crate into the JNI shim. The `hive_core_zeroize` extern
# reference in hive_zeroize.c resolves to libhive_core.so at link time. At
# load time, System.loadLibrary("hive_zeroize") triggers the dynamic linker
# to resolve `libhive_core.so` from the APK's `lib/<abi>/` directory (where
# rust-android-gradle's cargoBuild task placed it).
target_link_libraries(hive_zeroize
    hive_core   # cargo-ndk-built libhive_core.so per build.gradle.kts cargo{} block
)

# Install target (Gradle picks .so from CMake's default output dir).
set_target_properties(hive_zeroize PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${ANDROID_ABI}"
)
