package computer.hive.app.security

/**
 * HiveCoreHkdf — Kotlin FFI consumer of `hive_core_hkdf_sha256` (Rust core).
 *
 * Wires Kotlin → JNI → the Rust `extern "C" fn hive_core_hkdf_sha256`. The Rust
 * symbol is exported from `libhive_core.so`; this object is the Android-side
 * consumer that the Compose surface may invoke for derivation operations that
 * REQUIRE byte-identity with the iOS sibling.
 *
 * ## Why this exists alongside DeviceSaltHandle.deriveHkdfSha256
 *
 * `DeviceSaltHandle.deriveHkdfSha256` (this package) routes HKDF through
 * `javax.crypto.Mac` — a pure Kotlin/Java path, used for the device-salt →
 * trustee-alias / BLE-adv-id derivations because that path was structurally
 * complete pre-Rust-FFI and has its own zeroize-defense-in-depth for the
 * per-device salt material.
 *
 * `HiveCoreHkdf.derive` is the structurally-cross-platform Rust-FFI path: any
 * HKDF derivation that REQUIRES byte-identity with the iOS sibling (the Swift
 * `HiveCoreHkdf` consuming the same `hive_core_hkdf_sha256` symbol from the same
 * compiled-once `libhive_core` object) routes through this shim. The FFI path is
 * byte-identical by CONSTRUCTION (the same compiled object on both platforms) —
 * the discipline-enforced parity of `Mac` vs `CryptoKit.HKDF` is collapsed to
 * structural parity at the Rust source-of-truth layer.
 *
 * Future work: migrating the `DeviceSaltHandle.deriveHkdfSha256` body to route
 * through this same FFI symbol is contract-preserving (RFC 5869 byte-output
 * identity is guaranteed by the same algorithm), minimizing the per-binding
 * zeroize pressure during the cutover.
 *
 * ## Caller-visible contract
 *
 * The Rust impl wraps every transient binding (PRK, intermediate HMAC instances,
 * intermediate prev/output arrays) in HIVE-internal `ZeroOnDrop<T>` wrappers
 * consumed via by-value `FixedOutput::finalize_into` (per the `digest 0.10.7`
 * signature). The Kotlin caller sees ONLY the i32 return code + the populated
 * OKM byte array; the zeroize discipline lives entirely INSIDE the Rust call
 * frame. There are NO Kotlin-side residency concerns BEYOND the OKM bytes
 * themselves (which the caller owns and SHOULD zeroize via `nativeZeroize` on
 * the existing `DeviceSaltHandle` JNI binding when the OKM scope ends).
 *
 * ## Caller contract
 *
 * - `ikm`     — non-null; MAY be empty (RFC 5869 §2.2 allows zero-length IKM).
 *               Most call sites SHOULD pass a non-empty protocol-binding IKM.
 * - `salt`    — MAY be null (semantically "string of HashLen zeros" per RFC
 *               5869 §2.2). MAY be empty (treated identically to null).
 * - `info`    — MAY be empty (RFC 5869 §2.3). For HIVE this SHOULD be a
 *               UTF-8-encoded protocol label binding the OKM to a context
 *               (e.g., "hive-trustee-alias-v1", "hive-ble-adv-v1||<be_u64>").
 * - `length`  — Output length in bytes; MUST satisfy `1 <= length <= 8160`
 *               per RFC 5869 §2.3 (`L <= 255 * HashLen = 255 * 32 = 8160`).
 *
 * Returns the OKM byte array on success.
 *
 * Throws [HkdfError.InvalidArgument] for length out-of-range, [HkdfError.ExpandFailure]
 * for any internal HKDF expand failure (defensive — the length pre-check covers
 * the empirical failure mode). On any error throw, the OKM bytes ARE NOT
 * consumed by the caller (the contract bytes are UNDEFINED on non-zero return
 * code per the Rust function doc-comment).
 *
 * ## SECURITY
 *
 * - ZERO-TELEMETRY: no logging, no allocation beyond the OKM byte array itself,
 *   no outbound RPC, no metrics. The underlying Rust path applies a
 *   zeroize-on-drop discipline.
 * - The caller SHOULD treat the returned `ByteArray` as security-sensitive
 *   and zeroize it via `Arrays.fill(okm, 0x00.toByte())` (or the JNI
 *   nativeZeroize primitive on `DeviceSaltHandle`) when the derivation
 *   scope ends. This shim does NOT auto-zeroize the OKM — it is the caller's
 *   bookkeeping per the RFC 5869 §2.3 output-handling rules.
 *
 * ## Cross-platform parity
 *
 * The iOS sibling (`mobile/ios/Sources/HIVECore/HiveCoreHkdf.swift`) exposes a
 * structurally-identical Swift API consuming the SAME `hive_core_hkdf_sha256` C
 * symbol from the SAME compiled `libhive_core` object code. Cross-platform
 * byte-identity is structural by construction.
 */
object HiveCoreHkdf {
    /**
     * RFC 5869 §2.3 max OKM length: 255 * HashLen = 255 * 32 = 8160 bytes.
     * MUST match the `mobile/android/rust/src/lib.rs` defensive-validation upper
     * bound.
     */
    const val MAX_OKM_LENGTH_BYTES: Int = 8160

    /**
     * Derive [length] bytes of HKDF-SHA256 OKM from the given [ikm], optional
     * [salt], and [info] context-binding string.
     *
     * @throws HkdfError.InvalidArgument if length is out of range [1..8160].
     * @throws HkdfError.ExpandFailure if the underlying Rust expand step
     *         returns an internal error (rc=-2).
     */
    fun derive(
        ikm: ByteArray,
        salt: ByteArray?,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        if (length !in 1..MAX_OKM_LENGTH_BYTES) {
            throw HkdfError.InvalidArgument(
                "HKDF-SHA256 length must be in 1..$MAX_OKM_LENGTH_BYTES; got $length"
            )
        }
        // Allocate the OKM buffer in Kotlin. The native impl writes directly
        // into the underlying byte array via `GetByteArrayElements` paired with
        // `ReleaseByteArrayElements(..., 0)` (JNI API-pair discipline).
        val okm = ByteArray(length)
        val rc = nativeHkdfSha256(ikm, salt, info, okm)
        when (rc) {
            0 -> return okm
            -1 -> throw HkdfError.InvalidArgument(
                "HKDF-SHA256 native call rejected arguments (rc=-1; null pointer with non-zero length OR length out of range)"
            )
            -2 -> throw HkdfError.ExpandFailure(
                "HKDF-SHA256 expand step returned internal error (rc=-2; defensive — pre-check should cover this empirically)"
            )
            else -> throw HkdfError.ExpandFailure(
                "HKDF-SHA256 native call returned unexpected code $rc"
            )
        }
    }

    /**
     * JNI binding to the Rust `hive_core_hkdf_sha256` symbol.
     *
     * The C-side JNI shim adapts `(jbyteArray, jbyteArray?, jbyteArray, jbyteArray) -> jint`
     * to the Rust signature `(*const u8, usize, *const u8, usize, *const u8, usize, *mut u8, usize) -> i32`
     * by extracting array pointers + lengths via `GetByteArrayElements` /
     * `ReleaseByteArrayElements(..., 0)` (mode 0 = copy back + free; JNI
     * API-pair discipline).
     *
     * Implementation: `mobile/android/src/main/jni/hive_hkdf.c` (TODO — the
     * Kotlin shim shape lands first via the call-site reservation pattern).
     *
     * Symbol: `Java_computer_hive_app_security_HiveCoreHkdf_nativeHkdfSha256`.
     *
     * @return  0 = success (OKM populated)
     *         -1 = invalid argument (null pointer with non-zero length, length out of range)
     *         -2 = HKDF expand failure (defensive)
     */
    private external fun nativeHkdfSha256(
        ikm: ByteArray,
        salt: ByteArray?,
        info: ByteArray,
        okm: ByteArray,
    ): Int

    /**
     * Companion init: load `libhive_core.so` (Rust core) — the same unguarded
     * load-or-die loader posture as `MainActivity`.
     *
     * The library is already loaded by `MainActivity.companion object init`
     * at app boot; this `init` block is idempotent (subsequent
     * `System.loadLibrary` calls on an already-loaded library are no-ops in
     * the JVM/ART). The redundant load is intentional: it preserves the
     * load-or-die posture for any future caller that instantiates
     * `HiveCoreHkdf` BEFORE `MainActivity` (e.g., a unit test that bypasses
     * the Activity lifecycle).
     */
    init {
        System.loadLibrary("hive_core")
    }
}

/**
 * HKDF error class hierarchy. Sealed for exhaustive `when` mapping by callers
 * (the LEDGER Compose surface resolves `HkdfError.InvalidArgument` to a
 * developer-facing crash log; `ExpandFailure` is a defensive case the caller MAY
 * surface as a generic "secure derivation failed" chip).
 */
sealed class HkdfError(message: String) : RuntimeException(message) {
    /** Length out of range, or null pointer with non-zero length on the Rust side. */
    class InvalidArgument(message: String) : HkdfError(message)

    /** RFC 5869 expand step returned internal error (rc=-2). Defensive — should not occur if InvalidArgument pre-check is satisfied. */
    class ExpandFailure(message: String) : HkdfError(message)
}
