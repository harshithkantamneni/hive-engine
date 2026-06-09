/*
 * HIVE Android — hive_zeroize.c
 *
 * JNI C shim implementing `DeviceSaltHandle.nativeZeroize(ByteArray)`.
 *
 * The zeroize call delegates to `hive_core_zeroize(ptr, len)`, exported from
 * the Rust crate at `mobile/android/rust/src/lib.rs`. The Rust impl uses
 * `zeroize::Zeroize::zeroize()`, which compiles to `core::ptr::write_volatile`
 * per Rust `std::ptr` library docs — the same compiler-cannot-elide guarantee
 * as a C-side `volatile` loop, and uniform across all API levels supported by
 * HIVE (minSdk 31+; no bionic dependency, no API-level runtime gate needed).
 *
 * The public API contract is byte-identical to a libc-based implementation:
 * `DeviceSaltHandle.close()` / nativeZeroize signatures and semantics are
 * unchanged, and ZERO-TELEMETRY is unchanged.
 *
 * Cross-platform note: `hive_core_zeroize` is exported from `libhive_core.so`
 * and consumed transitively via the Gradle externalNativeBuild link line (the
 * shared object is already in the APK's `lib/<abi>/` dir via cargo-ndk
 * integration in `build.gradle.kts`). The same Rust crate is consumed by
 * Android (cdylib) and iOS (staticlib), so cross-platform zeroize-parity is
 * structural rather than a parallel reimplementation. Silent-fallthrough on a
 * failed library load is handled at the Kotlin-side `System.loadLibrary` call,
 * not here.
 *
 * JNI API-pair discipline:
 *   This file uses `GetByteArrayElements` + `ReleaseByteArrayElements` paired.
 *   It does NOT mix with `GetPrimitiveArrayCritical` +
 *   `ReleasePrimitiveArrayCritical`. Mixing the pairs causes a silent
 *   zeroize-bug where the fill is performed on a JVM-owned copy that is never
 *   committed back to the backing array — the salt would survive in heap after
 *   `close()`. The `ReleaseByteArrayElements(..., 0)` mode argument commits
 *   the changes back to the Java array AND frees the C-side buffer; mode `0`
 *   is mandatory here (mode `JNI_ABORT` would discard the fill; mode
 *   `JNI_COMMIT` would leak the C buffer).
 *
 * SECURITY: No network surface. Pure in-process primitives; ZERO-TELEMETRY.
 * No dynamic allocation, no logging, no crash-dump export. The `jbyte*`
 * returned by `GetByteArrayElements` may be a copy (implementation-defined per
 * the JNI spec); `ReleaseByteArrayElements(..., 0)` commits the zeroed bytes
 * back to the JVM heap unconditionally. The Kotlin-side `Arrays.fill` that
 * immediately follows the JNI call provides defense-in-depth for the case
 * where the JNI implementation returned a pinned pointer (no copy) — the fill
 * happens twice at different compilation boundaries, making dead-store
 * elimination on BOTH elision events necessary to leak bytes.
 *
 * Rationale for delegating to the Rust primitive rather than branching on the
 * API level: the Rust `zeroize` crate's primitive is uniformly available
 * across all minSdk-supported API levels (no bionic dependency). This:
 *   (1) Removes any dependency on `libcrypto.so` or bionic
 *       `__INTRODUCED_IN(34)` weak-linkage.
 *   (2) Makes cross-platform zeroize-parity with iOS structural (a single
 *       Rust crate consumed by both platforms; byte-identity is a
 *       build-artifact property, not a parallel-reimplementation discipline).
 *   (3) Eliminates an API-level runtime gate
 *       (`android_get_device_api_level()`) — fewer branches in the privacy
 *       hot-path.
 *   (4) Preserves all existing defense-in-depth: the Kotlin-side
 *       `Arrays.fill` still runs after this JNI call; the JNI API-pair
 *       discipline is unchanged; mode-0 ReleaseByteArrayElements still
 *       commits.
 */

#include <stddef.h>
#include <stdint.h>

#include <jni.h>

/*
 * `hive_core_zeroize` extern "C" symbol exported from `libhive_core.so`
 * (`mobile/android/rust/src/lib.rs::hive_core_zeroize`). Linked at APK build
 * time via cargo-ndk integration in `build.gradle.kts`. The signature
 * matches the Rust source exactly:
 *
 *   void hive_core_zeroize(uint8_t *ptr, size_t len);
 *
 * (Rust `*mut u8` is ABI-equivalent to C `uint8_t *`; Rust `usize` is
 * ABI-equivalent to C `size_t` per the Rust reference / cbindgen mapping.)
 *
 * Defensive contract is mirrored on the Rust side: NULL ptr or zero len is a
 * no-op (no dereference, no crash). The double-defense (C-side guard +
 * Rust-side guard) is intentional — the privacy hot-path must complete under
 * all conditions.
 */
extern void hive_core_zeroize(uint8_t *ptr, size_t len);

/*
 * JNI entry point: `DeviceSaltHandle.nativeZeroize(ByteArray)`.
 *
 * Symbol: `Java_computer_hive_app_security_DeviceSaltHandle_nativeZeroize`
 *   - Java class:  computer.hive.app.security.DeviceSaltHandle
 *   - Java method: private external fun nativeZeroize(buf: ByteArray): Unit
 *
 * Defensive posture:
 *   - NULL `buf` silently returns (no-op) rather than crashing — matches the
 *     Kotlin `Arrays.fill` contract on a null array (NullPointerException).
 *     The Kotlin caller is expected to pass a non-null ByteArray; this guard
 *     is defense-in-depth for a misuse already forbidden at the wrapper layer.
 *   - Zero-length arrays are valid no-ops.
 *   - We do NOT call JNI exception-raising APIs — the zeroize primitive is
 *     on the privacy hot-path and must complete under all conditions. If the
 *     JVM passes an invalid array, the `GetByteArrayElements` call returns
 *     NULL and we return without mutating anything; the Kotlin-side
 *     `Arrays.fill` defense-in-depth still runs post-return.
 */
JNIEXPORT void JNICALL
Java_computer_hive_app_security_DeviceSaltHandle_nativeZeroize(
        JNIEnv *env, jobject thiz, jbyteArray buf) {
    (void)thiz; /* static-method-equivalent; `thiz` unused */

    if (buf == NULL) {
        return;
    }

    jsize len = (*env)->GetArrayLength(env, buf);
    if (len <= 0) {
        return;
    }

    /*
     * `GetByteArrayElements` paired with `ReleaseByteArrayElements`.
     * Must not mix with `GetPrimitiveArrayCritical` /
     * `ReleasePrimitiveArrayCritical` — a mismatched pair is a silent
     * zeroize-bug. The JNI API-pair discipline lives at this shim layer; the
     * inner primitive is delegated to the Rust crate but the pair contract is
     * identical.
     */
    jbyte *ptr = (*env)->GetByteArrayElements(env, buf, NULL);
    if (ptr == NULL) {
        /*
         * OOM or pending exception — the JVM has already flagged the error
         * condition. Return without touching anything; the Kotlin caller's
         * `Arrays.fill` defense-in-depth still runs post-return.
         */
        return;
    }

    /*
     * Single Rust-FFI call: `hive_core_zeroize(ptr, len)` is uniform across
     * all API levels and delegates to `zeroize::Zeroize::zeroize()` in Rust,
     * which compiles to `core::ptr::write_volatile` per Rust `std::ptr`
     * library docs. Same compiler-cannot-elide guarantee, with structural
     * cross-platform zeroize-parity with iOS via the single shared Rust crate.
     *
     * `(uint8_t *)ptr` cast: jbyte is signed-char (`int8_t`); the Rust API
     * takes `*mut u8` (unsigned). The cast is ABI-safe because the bit
     * pattern is identical and the function only writes (zeros) — no signed
     * arithmetic occurs across the FFI boundary.
     */
    hive_core_zeroize((uint8_t *)ptr, (size_t)len);

    /*
     * Mode `0` commits the zeroed bytes back to the JVM heap AND frees the
     * C-side buffer. Mandatory.
     *   - mode `JNI_ABORT`  : would discard the fill (silent zeroize-bug).
     *   - mode `JNI_COMMIT` : would leak the C buffer.
     *   - mode `0`          : commit + free (correct).
     */
    (*env)->ReleaseByteArrayElements(env, buf, ptr, 0);
}
