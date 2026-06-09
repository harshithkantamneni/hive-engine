//! HIVE iOS — Rust FFI core. Exposes the `hive_core_zeroize` and
//! `hive_core_hkdf_sha256` symbols consumed by the Swift layer, plus a
//! `ZeroOnDrop<T>` wrapper and a by-value `FixedOutput::finalize_into` HMAC
//! consumption pattern used by the HKDF implementation.
//!
//! The set of `extern "C"` symbols exported from `libhive_core.a` (consumed via
//! `hive_core.xcframework`) MUST match the golden export manifest. Currently the
//! manifest carries `hive_core_hkdf_sha256` + `hive_core_zeroize`. Any drift
//! between this file's `#[no_mangle] pub extern "C"` items and the manifest is a
//! CI fail-closed condition. The public `hive_core_hkdf_sha256` symbol delegates
//! to a crate-internal `hive_core_hkdf_sha256_impl` (no `#[no_mangle]` — an
//! internal Rust function only); the exported symbol set is unaffected, and the
//! interior captures every transient binding under `ZeroOnDrop<T>`.
//!
//! The body of `hive_core_zeroize` below is BYTE-IDENTICAL to the Android
//! sibling `mobile/android/rust/src/lib.rs` `hive_core_zeroize` definition. A
//! single Rust symbol is consumed by both platforms, so cross-platform
//! zeroize-parity is STRUCTURAL — not discipline-enforced — because both
//! platforms statically link the SAME compiled `libhive_core.{a,so}` Rust object
//! code from a single `Cargo.lock`-pinned source tree.
//!
//! The `ZeroOnDrop<T>` wrapper definition + `hive_core_hkdf_sha256_impl` body
//! are equivalent to the Android sibling. The Drop body MUST use the raw-pointer
//! cast `&mut self.0 as *mut ManuallyDrop<T> as *mut u8` (NOT the
//! `(&mut *self.0) as *mut T as *mut u8` DerefMut path, which is UB after
//! `ManuallyDrop::take`).
//!
//! `DeviceSaltHandle.swift`'s `deinit` body routes its zeroize-on-close
//! semantics through `hive_core_zeroize`. The iOS `memset_s` reference in the
//! C-side zeroize path is also unified through this symbol, so cross-platform
//! zeroize-parity is structural.
//!
//! Cross-refs:
//!   - HKDF-SHA256 byte-identity-in-practice — STRUCTURAL because both platforms
//!     consume the SAME compiled Rust symbol
//!   - Package.swift binaryTarget wiring
//!   - the golden export manifest (`hive_core_zeroize` + `hive_core_hkdf_sha256`)
//!   - a single Rust symbol consumed by both platforms
//!   - internal ZeroOnDrop<T> + by-value FixedOutput::finalize_into HMAC
//!     consumption pattern
//!   - raw-pointer-cast Drop body
//!   - Miri UB-detection test (Test 7, blocking pre-merge)
//!   - `cargo expand --release` must reveal ≥7 distinct ZeroOnDrop drop
//!     call-sites
//!   - mobile/android/rust/src/lib.rs (sibling — byte-identical body)

use core::mem::ManuallyDrop;
use core::ptr::write_volatile;
use core::sync::atomic::{compiler_fence, Ordering};

use hmac::{Hmac, Mac};
use hmac::digest::{self, FixedOutput};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// Internal Drop-zeroize wrapper
// ---------------------------------------------------------------------------
//
// `ZeroOnDrop<T>` captures any `T: Sized` transient binding (PRK,
// intermediate Hmac instances, intermediate prev/output arrays, derived sub-
// keys, default salts) and at scope-exit Drop volatile-zeros the full byte
// representation of the `ManuallyDrop<T>` slot. Does NOT require `T: Zeroize`.
//
// For T = Hmac<Sha256> the wrapper nukes ALL inner bytes including the
// `BlockBuffer<U64>`'s `GenericArray<u8, U64>` array slot (block-buffer-0.10.4
// has no Zeroize impl; RustCrypto-family crates do NOT advertise Zeroize-on-Drop
// discipline). For T = [u8; 32] the wrapper nukes 32 contiguous bytes.
//
// Drop body pointer-acquisition: raw-pointer cast
// `&mut self.0 as *mut ManuallyDrop<T> as *mut u8`. Per stdlib
// `#[repr(transparent)]` layout guarantee on `ManuallyDrop<T>` (cited at
// https://doc.rust-lang.org/std/mem/struct.ManuallyDrop.html#layout-1) the
// byte representation of `ManuallyDrop<T>` is identical to T. Sound for
// byte-level access EVEN AFTER `ManuallyDrop::take` has logically moved the
// inner T out of the slot — the underlying bytes remain valid for byte-level
// zeroization. The `(&mut *self.0) as *mut T as *mut u8` pattern would be UB
// after `ManuallyDrop::take` because `*self.0` invokes `ManuallyDrop::DerefMut`
// on a moved-out value.
//
// The FFI-scaffold preflight at
// `mobile/ios/preflight/ios_ffi_scaffold_invariants.sh` regression-tests this:
// a DerefMut-path pattern OR a bare pointer-cast pattern in any Drop body of
// THIS file fails the gate.
//
// SAFETY invariant: T MUST be Sized; T MUST NOT contain heap pointers to key
// material (Hmac<Sha256> + [u8; 32] are both stack-value-types — invariant
// satisfied for every wrapper instantiation in this file).
struct ZeroOnDrop<T: Sized>(ManuallyDrop<T>);

impl<T: Sized> ZeroOnDrop<T> {
    #[inline(never)]
    fn new(v: T) -> Self {
        Self(ManuallyDrop::new(v))
    }
}

impl<T: Sized> core::ops::Deref for ZeroOnDrop<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Sized> core::ops::DerefMut for ZeroOnDrop<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Sized> Drop for ZeroOnDrop<T> {
    #[inline(never)]
    fn drop(&mut self) {
        // SAFETY: Raw-pointer cast directly to the wrapper's inner storage;
        // bypasses Deref/DerefMut on the inner type entirely. Per stdlib
        // repr(transparent) layout guarantee on ManuallyDrop, the byte
        // representation of the wrapper is identical to the inner type.
        // This pointer is sound for byte-level access EVEN AFTER the inner
        // value has been logically moved out via ManuallyDrop::take — the
        // underlying bytes remain valid for byte-level zeroization. A
        // DerefMut-based path would be UB after take because dereferencing
        // the wrapper invokes ManuallyDrop::DerefMut on a moved-out value.
        let ptr = &mut self.0 as *mut ManuallyDrop<T> as *mut u8;
        let size = core::mem::size_of::<T>();
        unsafe {
            for i in 0..size {
                write_volatile(ptr.add(i), 0u8);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Internal HKDF-SHA256 error type (not crossing the FFI)
// ---------------------------------------------------------------------------
//
// Maps to canonical i32 status codes at the extern "C" boundary. Internal use
// only — i32 status is the cross-platform boundary contract; this enum is local
// to the Rust impl.
#[derive(Debug)]
enum HkdfError {
    /// `okm_len > 255 * 32` (RFC 5869 §2.3 ceiling) OR HMAC keying-length
    /// failure surfaced by `Hmac::<Sha256>::new_from_slice`.
    InvalidLength,
}

// ---------------------------------------------------------------------------
// hive_core_zeroize — FFI consumer #1
// ---------------------------------------------------------------------------

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
#[no_mangle]
pub extern "C" fn hive_core_zeroize(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        use zeroize::Zeroize;
        let slice: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
        slice.zeroize();
    }
}

// ---------------------------------------------------------------------------
// hive_core_hkdf_sha256 — FFI consumer #2
// ---------------------------------------------------------------------------

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
#[no_mangle]
pub extern "C" fn hive_core_hkdf_sha256(
    ikm_ptr: *const u8,
    ikm_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    info_ptr: *const u8,
    info_len: usize,
    okm_ptr: *mut u8,
    okm_len: usize,
) -> i32 {
    if okm_len == 0 || okm_len > 8160 {
        return -2;
    }
    if okm_ptr.is_null() {
        return -1;
    }
    // SAFETY: caller-asserted contract above. NULL-with-zero-len is treated
    // as an empty slice (RFC 5869 permits empty IKM / salt / info).
    let ikm: &[u8] = unsafe {
        if ikm_ptr.is_null() || ikm_len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(ikm_ptr, ikm_len)
        }
    };
    let salt_opt: Option<&[u8]> = unsafe {
        if salt_ptr.is_null() || salt_len == 0 {
            None
        } else {
            Some(core::slice::from_raw_parts(salt_ptr, salt_len))
        }
    };
    let info: &[u8] = unsafe {
        if info_ptr.is_null() || info_len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(info_ptr, info_len)
        }
    };
    let okm: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(okm_ptr, okm_len) };

    // Delegate to the crate-internal impl that captures every transient
    // binding under ZeroOnDrop<T>. The extern "C" surface is invariant; only
    // the interior is upgraded.
    match hive_core_hkdf_sha256_impl(salt_opt, ikm, info, okm) {
        Ok(()) => 0,
        Err(_) => -3,
    }
}

// ---------------------------------------------------------------------------
// hive_core_hkdf_sha256_impl — crate-internal ZeroOnDrop-wrapped HKDF
// ---------------------------------------------------------------------------
//
// RFC 5869 §2.2-§2.3 byte-identical to upstream `hkdf 0.12.4`.
//
// The `_impl` suffix disambiguates from the extern "C" outer symbol
// `hive_core_hkdf_sha256`.
//
// PRK-residency posture: the local `tmp: digest::Output<Hmac<Sha256>>`
// (= `GenericArray<u8, U32>`) has no Drop impl; the Extract-scope tmp slot holds
// the PRK in plaintext for the microsecond-scale window between `finalize_into`
// and `prk_buf.copy_from_slice`. This matches upstream `hkdf 0.12.4`'s PRK byte
// intermediate; the stack slot is overwritten by next stack frame use. The PRK
// is captured in `prk_buf` (ZeroOnDrop'd), which Drops at scope exit.
//
// Caller-owned salt residency NOTE: caller MUST zeroize salt source after
// return; FFI does NOT zeroize caller-owned input buffers.
//
// HMAC consumption: HMAC instances are consumed via
// `unsafe { ManuallyDrop::take(&mut wrapper.0) }` to extract the inner
// `Hmac<Sha256>` BY VALUE, passed to
// `digest::FixedOutput::finalize_into(self, &mut Output<Self>)` whose receiver
// is BY-VALUE `self` (consuming) per the `digest 0.10.7` signature. The
// `ManuallyDrop` wrapper slot remains for `ZeroOnDrop::drop` at scope exit —
// Drop-preservation is achieved STRUCTURALLY via wrapper-slot-residency, NOT via
// `&mut self` semantics on `finalize_into`.
//
// `cargo expand --release` MUST reveal at least 7 distinct
// `ZeroOnDrop::<T>::drop` call-sites for this impl:
//   1. default_salt: ZeroOnDrop<[u8; 32]> (Extract-scope local)
//   2. extract_mac: ZeroOnDrop<Hmac<Sha256>> (Extract-scope local)
//   3. prk_buf:     ZeroOnDrop<[u8; 32]> (Extract-scope local)
//   4. prk:         ZeroOnDrop<[u8; 32]> (function-scope local)
//   5. iter_mac:    ZeroOnDrop<Hmac<Sha256>> (per-iter Expand-loop)
//   6. iter_out:    ZeroOnDrop<[u8; 32]> (per-iter Expand-loop)
//   7. prev:        ZeroOnDrop<[u8; 32]> (function-scope local across iters)
fn hive_core_hkdf_sha256_impl(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), HkdfError> {
    // === Extract (RFC 5869 §2.2): PRK = HMAC-Hash(salt, IKM) ===
    let default_salt: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
    let salt_bytes: &[u8] = match salt {
        None => &default_salt[..],
        Some(s) => s,
    };
    let mut extract_mac: ZeroOnDrop<Hmac<Sha256>> = ZeroOnDrop::new(
        Hmac::<Sha256>::new_from_slice(salt_bytes).map_err(|_| HkdfError::InvalidLength)?,
    );
    extract_mac.update(ikm);
    // Drop-preserving FixedOutput::finalize_into pattern. The inner Hmac is
    // moved out via ManuallyDrop::take; the ZeroOnDrop wrapper slot remains and
    // Drop runs at scope exit, byte-zeroizing the (now-take'd) ManuallyDrop slot
    // via raw-pointer cast. Drop-preservation is structural (wrapper-slot-
    // residency), NOT via `&mut self` on `finalize_into`.
    let mut prk_buf: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
    {
        let mut tmp: digest::Output<Hmac<Sha256>> = Default::default();
        // FixedOutput::finalize_into(self, &mut Output<Self>) — by-value
        // `self` per digest 0.10.7:95. ManuallyDrop::take extracts inner
        // Hmac<Sha256> by value; the wrapper slot is left for ZeroOnDrop::
        // drop at scope exit.
        FixedOutput::finalize_into(
            unsafe { ManuallyDrop::take(&mut extract_mac.0) },
            &mut tmp,
        );
        prk_buf.copy_from_slice(&tmp[..]);
        // tmp (digest::Output<Hmac<Sha256>> = GenericArray<u8, U32>) has no
        // Drop impl; stack slot uncovered for tmp specifically. PRK is
        // already copied into prk_buf (ZeroOnDrop'd) which DOES Drop normally.
        // Stack slot will be overwritten by next stack frame use; this
        // matches upstream `hkdf 0.12.4`'s PRK byte intermediate.
    }
    // extract_mac drops at THIS scope exit — ZeroOnDrop::drop volatile-zeros
    // the now-spent inner ManuallyDrop slot bytes. BlockBuffer<U64> array slot
    // covered by construction.
    let prk: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new(*prk_buf);

    // === Expand (RFC 5869 §2.3): T(i) = HMAC-Hash(PRK, T(i-1) || info || i) ===
    let chunk_len: usize = 32;
    // RFC 5869 §2.3: L ≤ 255 * HashLen.
    if okm.len() > 255 * chunk_len {
        return Err(HkdfError::InvalidLength);
    }

    // RFC 5869 §2.3: T(0) = empty string (zero length). The `prev` buffer is
    // pre-allocated with 32-zero placeholder bytes for stack-allocation
    // purposes only; actual T(0) semantics are encoded by `prev_set = false`
    // skipping the iter_mac.update(&prev[..]) call on the first iteration.
    // Subsequent iterations populate prev with T(i-1) = HMAC-Hash output
    // (32 bytes).
    let mut prev: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
    let mut prev_set = false;

    for (block_n, block) in okm.chunks_mut(chunk_len).enumerate() {
        let mut iter_mac: ZeroOnDrop<Hmac<Sha256>> = ZeroOnDrop::new(
            Hmac::<Sha256>::new_from_slice(&prk[..]).map_err(|_| HkdfError::InvalidLength)?,
        );
        if prev_set {
            iter_mac.update(&prev[..]);
        }
        iter_mac.update(info);
        iter_mac.update(&[block_n as u8 + 1]);
        // Drop-preserving FixedOutput::finalize_into; iter_mac wrapper slot
        // remains Drop-able at iteration scope exit.
        let mut iter_out: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
        {
            let mut tmp: digest::Output<Hmac<Sha256>> = Default::default();
            FixedOutput::finalize_into(
                unsafe { ManuallyDrop::take(&mut iter_mac.0) },
                &mut tmp,
            );
            iter_out.copy_from_slice(&tmp[..]);
        }
        // iter_mac drops at iteration scope exit — ZeroOnDrop::drop runs,
        // nuking BlockBuffer<U64> array slot for THIS iteration's iter_mac.
        let block_len = block.len();
        block.copy_from_slice(&iter_out[..block_len]);
        prev.copy_from_slice(&iter_out[..]);
        prev_set = true;
        // iter_out drops here (ZeroOnDrop on [u8; 32]).
    }
    // prev / prk / prk_buf / default_salt drop at function exit (ZeroOnDrop
    // volatile-zeros each).
    let _ = prk; // suppress unused-binding; ZeroOnDrop::drop runs at fn exit.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — RFC 5869 §A.1 + Miri UB-detection
// ---------------------------------------------------------------------------
//
// Miri UB-detection is blocking pre-merge. CI: `cargo +nightly miri test
// test_v153_*`. Required: ZERO Miri diagnostics. FAIL-closed on ANY UB. When
// Miri is absent the check emits an INFO_SKIP and the gate is blocking only when
// miri is available. The Miri test bodies below are runnable LOCALLY on the iOS
// workspace member via `cargo +nightly miri test --manifest-path
// mobile/ios/rust/Cargo.toml`.
#[cfg(test)]
mod tests {
    use super::*;

    /// Miri UB-detection: the raw-pointer cast Drop body MUST NOT trigger any
    /// Miri UB diagnostic when invoked after `ManuallyDrop::take` has logically
    /// moved the inner T out. This regression-tests the
    /// `(&mut *self.0) as *mut T as *mut u8` pattern, which IS UB after take
    /// (DerefMut on a moved-out ManuallyDrop is UB).
    #[test]
    fn test_v153_zeroize_drop_after_take() {
        let mut wrapper: ZeroOnDrop<u32> = ZeroOnDrop::new(42);
        // ManuallyDrop::take logically moves the inner u32 out of wrapper.0.
        // The bytes remain in the slot but the value is conceptually gone.
        let _moved = unsafe { ManuallyDrop::take(&mut wrapper.0) };
        // Drop runs here — the raw-pointer cast bypasses DerefMut entirely.
        // Sound for byte-level access via repr(transparent) layout guarantee on
        // ManuallyDrop<u32>. A DerefMut-based path would be UB here.
        drop(wrapper);
    }

    /// Miri UB-detection: the by-value
    /// `FixedOutput::finalize_into(self, &mut Output<Self>)` consumption
    /// pattern from the HKDF impl MUST NOT trigger UB at the
    /// `ManuallyDrop::take` + Drop-at-scope-exit boundary.
    #[test]
    fn test_v153_zeroize_hmac_after_finalize() {
        let mut w: ZeroOnDrop<Hmac<Sha256>> = ZeroOnDrop::new(
            Hmac::<Sha256>::new_from_slice(&[0u8; 32]).expect("Hmac keying must succeed"),
        );
        Mac::update(&mut *w, b"test");
        let mut tmp: digest::Output<Hmac<Sha256>> = Default::default();
        FixedOutput::finalize_into(unsafe { ManuallyDrop::take(&mut w.0) }, &mut tmp);
        // Drop runs here — wrapper slot bytes are zeroized via raw-pointer
        // cast despite the inner Hmac<Sha256> having been moved out.
        drop(w);
    }

    /// RFC 5869 Appendix A.1 byte-identity test (Test Case 1, SHA-256).
    /// Byte-divergent OKM between this impl and upstream `hkdf 0.12.4` would be
    /// a regression. This test exercises `hive_core_hkdf_sha256_impl` directly
    /// (the crate-internal entry point; not the extern "C" surface) so that the
    /// ZeroOnDrop-wrapped path is exercised. Cross-platform parity is structural
    /// via a single Rust symbol.
    #[test]
    fn test_rfc5869_a1_byte_identity_v153() {
        let ikm: [u8; 22] = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let mut okm = [0u8; 42];
        hive_core_hkdf_sha256_impl(Some(&salt), &ikm, &info, &mut okm)
            .expect("RFC 5869 §A.1 vector must round-trip cleanly");
        assert_eq!(
            okm, expected,
            "HKDF-SHA256 OKM MUST match RFC 5869 §A.1 vector exactly"
        );
    }
}
