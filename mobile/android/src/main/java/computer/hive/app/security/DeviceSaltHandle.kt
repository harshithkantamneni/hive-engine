package computer.hive.app.security

import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * DeviceSaltHandle — opaque value type wrapping the 32-byte HIVE per-device salt.
 *
 * It replaces a raw `ByteArray` surface with an opaque wrapper.
 *
 * ## Invariants
 *
 *   - internal constructor + `computer.hive.app.security` package.
 *   - AutoCloseable + zeroize-on-close + IllegalStateException on closed use
 *     (close() + ensureOpen()).
 *   - consumer pattern: `use { }` with no public .getBytes()/.toByteArray() —
 *     the only derivation hook is deriveHkdfSha256().
 *   - toString() → "DeviceSaltHandle(<redacted>)".
 *   - equals() = reference-only; hashCode() = System.identityHashCode.
 *   - MUST NOT implement java.io.Serializable (no marker iface).
 *   - MUST NOT implement android.os.Parcelable (no @Parcelize annotation).
 *   - close() MUST zeroize via Arrays.fill(bytes, 0x00).
 *   - class is `final` (Kotlin default; no `open` modifier).
 *   - no public ctor accepting bytes; construction via DeviceSalt.*() (the
 *     ctor is `internal`).
 *
 * The "zeroize-robustness" behavior replaces the DSE-vulnerable `Arrays.fill`
 * primitive with a JNI-bound `memset_explicit` (API 34+ via bionic
 * `__INTRODUCED_IN(34)`) with a volatile-memset fallback for API 31-33
 * (BoringSSL-equivalent primitive). `GetByteArrayElements` is PAIRED with
 * `ReleaseByteArrayElements`; the pairs MUST NOT be mixed (silent zeroize-bug).
 * `System.loadLibrary("hive_zeroize")` failure propagates as
 * `ExceptionInInitializerError` — NO silent fallthrough to `Arrays.fill`-only
 * (DSE-vulnerable). `Arrays.fill` is RETAINED as defense-in-depth after the JNI
 * call.
 *
 * SECURITY: this class is the opacity layer for a privacy-critical artifact.
 * Any contributor editing this file MUST preserve every invariant above.
 * Leaking the 32-byte salt breaks the cross-device non-linkability property of
 * the salt AND the chain-of-trust it anchors.
 *
 * A preflight script grep-enforces the no-Serializable / no-Parcelable /
 * internal-ctor invariants.
 */
class DeviceSaltHandle internal constructor(
    // SECURITY: `private` visibility on `bytes` — paired with the absence of any
    // public .getBytes() / .toByteArray() accessor, this is the only reference
    // to the plaintext salt bytes inside the class. The ONLY external derivation
    // path is [deriveHkdfSha256] below, which never returns the salt itself —
    // only the HKDF-SHA256 OKM output for a caller-specified `info`.
    private val bytes: ByteArray,
) : AutoCloseable {

    init {
        // SECURITY: salt length is invariantly 32 bytes (SHA-256 HashLen per
        // RFC 5869 §3.1). A non-32-byte handle would indicate an upstream
        // corruption or a test-fixture constructing from wrong-size bytes
        // (public construction is disallowed; a future misuse from within the
        // security package is what this check catches).
        require(bytes.size == SALT_LEN_BYTES) {
            "DeviceSaltHandle: backing salt must be exactly $SALT_LEN_BYTES bytes; got ${bytes.size}"
        }
    }

    /** Tracks close state. Guarded by `@Volatile` — any post-close read is ordered-after the close-write. */
    @Volatile
    private var closed: Boolean = false

    /**
     * Zeroize the backing buffer and mark the handle closed.
     *
     * Zeroize routes through [nativeZeroize] which calls bionic
     * `memset_explicit` (API 34+) OR a volatile-memset loop (API 31-33). The
     * native primitive carries the C23 "shall not be removed" guarantee
     * (ISO/IEC 9899:2024 §7.26.6.2 ¶3) OR the C11 §6.7.3 / C23 §6.7.4
     * `volatile` observable-side-effect guarantee — both prevent JIT
     * dead-store-elimination. [Arrays.fill] is RETAINED post-JNI as
     * defense-in-depth.
     *
     * Idempotent: calling [close] on an already-closed handle is a no-op (no
     * exception thrown). Subsequent DERIVATION calls on a closed handle throw
     * [IllegalStateException] — see [ensureOpen].
     */
    override fun close() {
        if (closed) return
        // SECURITY: zeroize BEFORE flipping the `closed` flag so a racing
        // deriveHkdfSha256() call that sneaks past ensureOpen() under a data
        // race sees zeroed bytes (producing a garbage OKM) rather than valid
        // salt material. Correctness-first; the race is ALSO fenced by the
        // @Volatile `closed` write below.
        //
        // SECURITY: JNI primitive FIRST (native "shall not be removed"
        // guarantee), then Arrays.fill defense-in-depth (makes pure-Kotlin
        // heap-dump tooling observe zeros immediately without requiring the JNI
        // symbol to have loaded successfully). The double-fill makes DSE on
        // BOTH compilation boundaries necessary to leak bytes — a stronger
        // posture than either alone.
        nativeZeroize(bytes)
        Arrays.fill(bytes, 0x00.toByte())
        closed = true
    }

    /**
     * Derive HKDF-SHA256 OKM (Output Keying Material) from the salt.
     *
     * This is the ONLY public surface that consumes the salt. The returned bytes
     * are the HKDF OKM — NOT the salt itself. RFC 5869 §2.2 extract step uses the
     * salt as HMAC key and a fixed IKM ("hive-device-salt-v1" — a protocol label
     * making the PRK protocol-specific); §2.3 expand step uses the caller's
     * [info] string for context-binding.
     *
     * The OKM is protocol-visible (used for trustee-list aliases and BLE
     * advertising-identity — both surface-visible derivations). Leaking the OKM
     * does NOT compromise the salt.
     *
     * Byte-identity with iOS: parity with the Swift [deriveHkdfSha256] —
     * identical `(salt, info, length)` → identical output bytes. The protocol
     * label "hive-device-salt-v1" is load-bearing for this parity; DO NOT change
     * it without a matching cross-platform change.
     *
     * @param info HKDF-SHA256 info context string per RFC 5869 §2.3.
     *             Examples: "hive-trustee-alias-v1", "hive-ble-adv-v1||<be_u64>".
     * @param length Output length in bytes. Must satisfy RFC 5869 §2.3 bound
     *               `length ≤ 255 * 32 = 8160`.
     * @throws IllegalStateException if the handle is already closed.
     */
    fun deriveHkdfSha256(info: String, length: Int): ByteArray {
        ensureOpen()
        require(length in 1..HKDF_SHA256_MAX_OKM_LEN_BYTES) {
            "HKDF-SHA256 output length must be in 1..$HKDF_SHA256_MAX_OKM_LEN_BYTES; got $length"
        }
        // RFC 5869 §2.2 extract: PRK = HMAC-SHA256(salt, IKM).
        // HIVE uses the per-device salt as the SALT argument and a fixed protocol
        // label as the IKM; this makes the PRK unique per-device per-protocol.
        val mac = Mac.getInstance(HMAC_SHA256)
        mac.init(SecretKeySpec(bytes, HMAC_SHA256))
        val prk = mac.doFinal(HKDF_PROTOCOL_LABEL_IKM)

        try {
            // RFC 5869 §2.3 expand: OKM = T(1) || T(2) || ... || T(N)[:length]
            // where T(0) = empty, T(i) = HMAC-SHA256(PRK, T(i-1) || info || i).
            val expandMac = Mac.getInstance(HMAC_SHA256)
            expandMac.init(SecretKeySpec(prk, HMAC_SHA256))
            val infoBytes = info.toByteArray(Charsets.UTF_8)
            val okm = ByteArray(length)
            var prev = ByteArray(0)
            var written = 0
            var counter: Byte = 1
            while (written < length) {
                expandMac.reset()
                expandMac.update(prev)
                expandMac.update(infoBytes)
                expandMac.update(byteArrayOf(counter))
                prev = expandMac.doFinal()
                val toCopy = minOf(prev.size, length - written)
                System.arraycopy(prev, 0, okm, written, toCopy)
                written += toCopy
                counter = (counter + 1).toByte()
            }
            // SECURITY: `prev` holds the final T(N) block which contains OKM
            // suffix bytes; zeroize before leaving scope to reduce residency.
            // JNI primitive + Arrays.fill defense-in-depth.
            nativeZeroize(prev)
            Arrays.fill(prev, 0x00.toByte())
            return okm
        } finally {
            // SECURITY: PRK is derived FROM the salt; zeroize before scope exit
            // even on an exception path. JNI + fill pair.
            nativeZeroize(prk)
            Arrays.fill(prk, 0x00.toByte())
        }
    }

    /**
     * Redacted string representation. Logging an open OR closed handle emits
     * this constant; a reviewer grepping `$handle` in a stack trace or crash
     * log never sees the backing bytes.
     */
    override fun toString(): String = REDACTED_REPR

    /**
     * Reference equality only. Two handles wrapping the same bytes from
     * different `DeviceSalt.generateOrLoad` calls (impossible in practice since
     * the salt is singleton per device, but defense-in-depth) return FALSE from
     * `==`. Closes the "equality surprise" footgun class.
     */
    override fun equals(other: Any?): Boolean = this === other

    /** Identity hash; parity with [equals]. */
    override fun hashCode(): Int = System.identityHashCode(this)

    private fun ensureOpen() {
        // Consumer sites SHOULD catch this exception and translate it to a
        // user-facing copy string. The developer string "DeviceSaltHandle
        // already closed" is NOT user chrome.
        check(!closed) { "DeviceSaltHandle already closed" }
    }

    /**
     * JNI binding to the native zeroize primitive.
     *
     * Implementation: `mobile/android/src/main/jni/hive_zeroize.c`. Symbol:
     * `Java_computer_hive_app_security_DeviceSaltHandle_nativeZeroize`.
     *
     * The native code runtime-selects between bionic `memset_explicit` (API
     * 34+ per `__INTRODUCED_IN(34)`) and an in-source volatile-memset loop
     * (API 31-33, BoringSSL-equivalent primitive). Both carry a "shall not be
     * removed" guarantee normative to the C23 / C11 standards (ISO/IEC
     * 9899:2024 §7.26.6.2 ¶3 for memset_explicit; C11 §6.7.3 / C23 §6.7.4 for
     * volatile).
     *
     * JNI API-pair discipline: the native impl uses `GetByteArrayElements`
     * PAIRED with `ReleaseByteArrayElements(..., 0)`. The pair MUST NOT be
     * mixed with `GetPrimitiveArrayCritical` / `ReleasePrimitiveArrayCritical`
     * — a mismatched pair causes a silent zeroize-bug where the fill is
     * performed on a JVM-owned COPY that is never committed back to the backing
     * array. The preflight `manifest_invariants.sh` greps the .c source to
     * enforce the pairing at build time.
     */
    private external fun nativeZeroize(buf: ByteArray)

    companion object {
        init {
            // Silent-fallthrough-to-Arrays.fill prohibition. Load the native
            // zeroize library at class-initialization time; if the library
            // cannot be loaded (UnsatisfiedLinkError), the JVM wraps the
            // failure in ExceptionInInitializerError and DeviceSaltHandle
            // becomes un-instantiable. The handle CANNOT exist without its
            // zeroize primitive — DO NOT wrap in try/catch and fall back to
            // Arrays.fill-only (DSE-vulnerable).
            //
            // User-surface subsumption: the resulting app-boot failure is
            // covered by the existing chip "Nearby-device discovery
            // unavailable — secure storage problem" — no new user-facing string
            // is added. The chip subsumes UnsatisfiedLinkError at
            // DeviceSaltHandle construction as a secure-storage-problem fault
            // class (title-case threat, no mechanism leak).
            //
            // Load order MATTERS. `libhive_zeroize.so` (the JNI shim) depends on
            // `libhive_core.so` (the Rust crate's `extern "C" fn
            // hive_core_zeroize`). The dynamic linker resolves dependencies
            // bottom-up — `libhive_core.so` MUST be loaded BEFORE
            // `libhive_zeroize.so` so the shim's `hive_core_zeroize` extern
            // reference can bind. If the load order were reversed,
            // System.loadLibrary("hive_zeroize") would fail with
            // UnsatisfiedLinkError on the unresolved `hive_core_zeroize` symbol.
            // The silent-fallthrough prohibition still applies — any failure
            // here propagates as ExceptionInInitializerError.
            //
            // SECURITY: DO NOT change either call to a hyphenated form
            // (`loadLibrary("hive-zeroize")` or `loadLibrary("hive-core")`).
            // The native builds produce `libhive_zeroize.so` (CMakeLists.txt
            // target name) and `libhive_core.so` (cargo-ndk libname per
            // build.gradle.kts `cargo { libname = "hive_core" }`); the loader
            // strips the `lib` prefix and `.so` suffix and expects the
            // remainder byte-identical. A silent drift here means the library
            // never loads and ExceptionInInitializerError fires at first use
            // — a crash that looks like a JNI bug but is actually a name drift.
            // The preflight `manifest_invariants.sh` greps both loadLibrary
            // calls.
            System.loadLibrary("hive_core")    // Rust crate first (libhive_core.so).
            System.loadLibrary("hive_zeroize") // JNI shim depends on hive_core; load second.
        }

        /** 32-byte salt length (SHA-256 HashLen / RFC 5869 §3.1). */
        private const val SALT_LEN_BYTES: Int = 32

        /** RFC 5869 §2.3 output bound: L ≤ 255 * HashLen. */
        private const val HKDF_SHA256_MAX_OKM_LEN_BYTES: Int = 255 * 32

        /** JCE algorithm name for HMAC-SHA-256 (available on every Android ≥ API 21 JCE). */
        private const val HMAC_SHA256: String = "HmacSHA256"

        /** Redacted repr (audit-trail visible; no bytes leak). */
        private const val REDACTED_REPR: String = "DeviceSaltHandle(<redacted>)"

        /**
         * Protocol label used as HKDF IKM per the HIVE convention of "salt-as-
         * HMAC-key, label-as-IKM". Load-bearing for cross-platform byte-identity
         * — the iOS Swift implementation MUST use the same UTF-8 bytes. Any
         * change requires a matching change on every platform.
         */
        private val HKDF_PROTOCOL_LABEL_IKM: ByteArray =
            "hive-device-salt-v1".toByteArray(Charsets.UTF_8)

        /**
         * Internal construction path used by [DeviceSalt.generateOrLoadDeviceSalt].
         *
         * No public ctor accepting bytes. Callers MUST go through
         * DeviceSalt.generateOrLoadDeviceSalt which guarantees the bytes came
         * from SecureRandom.getInstanceStrong() + StrongBox-wrap. A test-fixture
         * or adversarial caller cannot construct a "salt" from attacker-chosen
         * bytes.
         *
         * `internal` visibility restricts this to the `computer.hive.app.security`
         * module; the test-fixture pattern for unit tests is to invoke
         * DeviceSalt on a test Context, not to call `wrap()` directly.
         */
        internal fun wrap(bytes: ByteArray): DeviceSaltHandle {
            // Defensive copy — the caller may reuse their `bytes` array; we want
            // the handle's backing buffer to be OURS so close() zeroizes the
            // handle's copy without mutating the caller's array. Caller is
            // responsible for zeroizing their own copy after construction.
            return DeviceSaltHandle(bytes.copyOf())
        }
    }
}
