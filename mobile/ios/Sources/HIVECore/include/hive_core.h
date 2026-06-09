#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

extern "C" {

/// Volatile-zeroizes a caller-owned byte buffer across the FFI boundary.
///
/// SAFETY contract — caller MUST guarantee:
///   - `ptr` is either NULL or a valid, properly-aligned, writable pointer
///     to AT LEAST `len` bytes of single-allocation backing storage.
///   - The backing storage outlives this call (no concurrent free).
///   - No other thread reads or writes the `[ptr, ptr+len)` window for the
///     duration of this call.
///
/// Caller contracts on each platform:
///   - Android JNI side: `GetByteArrayElements` returns a writable `jbyte*`;
///     `ReleaseByteArrayElements(..., 0)` commits. Lifetime carried by the
///     Kotlin `DeviceSaltHandle` private state.
///   - iOS Swift side: `UnsafeMutableRawBufferPointer.baseAddress` from a
///     heap-allocated buffer that survives until the next ARC tick; lifetime
///     carried by the `DeviceSaltHandle` private state.
///
/// Body: `Zeroize::zeroize()` from the `zeroize` crate compiles down to
/// `core::ptr::write_volatile` per Rust `std::ptr` library docs. The
/// `write_volatile` instruction is the compiler-cannot-elide guarantee — the
/// compiler is REQUIRED to emit the store and is FORBIDDEN to dead-store-
/// eliminate it as an optimization.
///
/// Null/zero-length guard: a null pointer OR a zero length is a no-op (NOT a
/// fault). Mirrors the C-side `hive_volatile_memzero` defensive guard in
/// `mobile/android/src/main/jni/hive_zeroize.c`.
void hive_core_zeroize(uint8_t *ptr, uintptr_t len);

/// HKDF-SHA256 FFI consumer.
///
/// Byte-identity-in-practice: both Android + iOS consume the SAME `extern "C"`
/// Rust symbol → byte-identity becomes STRUCTURAL (single Rust symbol, single
/// `Cargo.lock`-pinned crate set: `hkdf =0.12.4` + `sha2 =0.10.9` +
/// `hmac =0.12.1` direct + `digest 0.10.7` transitive). The extern "C" surface
/// (signature + i32 status code mapping) is invariant; the interior delegates to
/// `hive_core_hkdf_sha256_impl` (crate-internal), which captures every transient
/// HKDF binding under `ZeroOnDrop<T>`.
///
/// SAFETY contract — caller MUST guarantee:
///   - Each (`*ptr`, `*len`) pair is either NULL+0 OR a valid, properly-
///     aligned, readable (input) / writable (output) pointer to AT LEAST
///     `len` bytes.
///   - The backing storage outlives this call (no concurrent free).
///   - No other thread reads or writes any of the four windows for the
///     duration of this call.
///   - `okm_len` MUST be in (0, 8160] (RFC 5869 §2.3 ceiling: 255 * 32B).
///
/// Returns:
///   - `0` on success — `okm_ptr[0..okm_len]` populated with derived OKM.
///   - `-1` on null `okm_ptr` with non-zero `okm_len`.
///   - `-2` on `okm_len == 0` or `okm_len > 8160` (RFC 5869 §2.3 ceiling).
///   - `-3` on internal HKDF failure (only path: `okm_len > 8160` defensively
///     guarded by `-2` above; preserved for future-proofing).
///
/// Parity: identical Rust source consumed by Android (`mobile/android/rust/
/// src/lib.rs`) AND iOS (this crate) — same fn signature, same `hkdf =0.12.4`
/// + `sha2 =0.10.9` + `hmac =0.12.1` pin set. Byte-identical OKM output for
/// byte-identical IKM/salt/info inputs is structural, not discipline-enforced.
///
/// SECURITY: zero logging, zero allocation outside the OKM write, zero
/// outbound. ZERO-TELEMETRY. Every transient HKDF binding (PRK, intermediate
/// HMAC instances, intermediate prev/output arrays, default salt) is captured
/// under `ZeroOnDrop<T>` so each scope-exit Drop volatile-zeros the byte
/// representation.
int32_t hive_core_hkdf_sha256(const uint8_t *ikm_ptr,
                              uintptr_t ikm_len,
                              const uint8_t *salt_ptr,
                              uintptr_t salt_len,
                              const uint8_t *info_ptr,
                              uintptr_t info_len,
                              uint8_t *okm_ptr,
                              uintptr_t okm_len);

}  // extern "C"
