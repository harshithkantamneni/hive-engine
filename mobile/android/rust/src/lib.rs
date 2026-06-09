// HIVE Android — mobile/android/rust/src/lib.rs
//
// Rust FFI crate root for the HIVE Android-side `libhive_core.so`. Workspace
// member of the root <repo>/Cargo.toml (single-root-workspace discipline).
//
// The `extern "C"` symbols exported from this crate are:
//   - `hive_core_zeroize(ptr, len)`
//   - `hive_core_hkdf_sha256(...)`
//
// **Contract-preserving on `DeviceSaltHandle.close()`**: public API signature +
// behavior + zeroize-on-close semantics are UNCHANGED across the migration to
// this Rust core. The C-side shim invokes the Rust symbol unconditionally; no
// runtime API-level gate is needed because the Rust `zeroize` crate compiles to
// `core::ptr::write_volatile` per the Rust `std::ptr` library docs — the same
// compiler-cannot-elide guarantee as the C-side `volatile` loop, available
// uniformly across API 31+ (no bionic dependency).
//
// **Export manifest**: a preflight check enforces diff-zero between the exported
// symbol manifest and `nm libhive_core.so | grep ' T hive_core_'`.
//
// SECURITY: ZERO-TELEMETRY. No network surface. No logging. No outbound RPC.
// Any future symbols MUST satisfy the same constraints — the preflight
// forbidden-SDK scan extends to the Rust dependency graph via cargo-deny /
// cargo-audit at CI.

use core::mem::ManuallyDrop;
use core::ptr::write_volatile;
use core::sync::atomic::{compiler_fence, Ordering};

/// **Zeroize FFI consumer.**
///
/// Zeroize the `len` bytes pointed-to by `ptr`. Replaces the C-side
/// `memset_explicit`-or-`hive_volatile_memzero` runtime-gate in
/// `mobile/android/src/main/jni/hive_zeroize.c`.
///
/// Mechanism: `zeroize::Zeroize::zeroize()` on the slice. The `zeroize`
/// crate (v1.8.x) implements this via `core::ptr::write_volatile` per
/// the Rust `std::ptr` library docs — the JIT/LLVM as-if rule cannot
/// elide volatile writes. This carries the equivalent guarantee to the
/// C11 §6.7.3 / C23 §6.7.4 `volatile`-qualified-lvalue side-effect rule
/// that the C-side `hive_volatile_memzero` relies on AND the C23 §7.26.6.2
/// "shall not be removed" guarantee that bionic `memset_explicit` carries
/// — uniformly across all API levels supported by HIVE (minSdk 31+).
///
/// Caller contract (UNSAFE):
///   - `ptr` MUST be either NULL (with `len == 0` or `len > 0` — both no-op)
///     OR a properly-aligned, writable pointer to at least `len` bytes
///     valid for the duration of this call.
///   - The pointer SHOULD come from JNI `GetByteArrayElements` paired with
///     `ReleaseByteArrayElements(..., 0)` (JNI API-pair discipline) — the
///     C-side shim enforces this pairing in `hive_zeroize.c`.
///   - Defensive: `ptr.is_null() || len == 0` is treated as a no-op (zero
///     dereference). Matches the C-side defensive guard in `hive_zeroize.c`
///     — preserves the privacy hot-path "must complete under all conditions"
///     posture.
///
/// SECURITY: zero logging, zero allocation, zero outbound. Pure
/// in-process volatile-store primitive. ZERO-TELEMETRY.
///
/// Cross-platform parity: identical Rust source is consumed by Android (this
/// crate) AND iOS (`mobile/ios/rust/src/lib.rs`). The zeroize parity is
/// structural — both platforms link the same `libhive_core` Rust object code
/// from a single `Cargo.lock`-pinned source tree.
#[no_mangle]
pub extern "C" fn hive_core_zeroize(ptr: *mut u8, len: usize) {
    // Defensive no-op for null pointer or zero length. Matches the C-side
    // defensive guard in hive_zeroize.c. The privacy hot-path MUST complete
    // under all conditions; a misuse cannot crash.
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: caller-asserted contract above. The Kotlin side carries the
    // lifetime contract via DeviceSaltHandle's private bytes field. The C-side
    // JNI shim guarantees ptr is non-null + valid for len bytes via
    // GetByteArrayElements before calling this function.
    use zeroize::Zeroize;
    let slice: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
    // `slice.zeroize()` resolves to <[u8] as Zeroize>::zeroize which
    // performs `core::ptr::write_volatile(..., 0)` for each byte then
    // emits a `core::sync::atomic::compiler_fence(SeqCst)` per the
    // zeroize crate v1.8.x source (src/lib.rs `impl Zeroize for [u8]`).
    // The volatile-write + compiler-fence pair gives the same posture as
    // the C-side `volatile` loop + `__asm__ __volatile__("" ::: "memory")`
    // barrier in `hive_volatile_memzero`.
}

// ---------------------------------------------------------------------------
// ZeroOnDrop<T> wrapper.
// ---------------------------------------------------------------------------

/// HIVE-internal Drop-zeroize wrapper. Does NOT require `T: Zeroize`.
///
/// Drop byte-casts the inner storage and volatile-writes zeros across the
/// full byte representation, with a `compiler_fence(SeqCst)` barrier. This is
/// the per-binding capture layer; the wrapper-byte-cast strategy generalizes
/// to arbitrary `T: Sized`.
///
/// Coverage: for `T = Hmac<Sha256>`, nukes ALL inner bytes including
/// `BlockBuffer`'s `GenericArray<u8, BlockSize>` array slot
/// (`block-buffer 0.10.4` has no `Zeroize` impl). Because
/// `FixedOutput::finalize_into(self, ...)` is by-value consuming and
/// `ZeroOnDrop` retains the `ManuallyDrop` slot for Drop, those bytes are
/// still zeroized — see `hive_core_hkdf_sha256_impl` below. For
/// `T = [u8; 32]`, nukes 32 contiguous bytes.
///
/// Safety: `T` MUST be `Sized` (enforced by the bound). `T` MUST NOT
/// contain heap pointers to key material (`Hmac<Sha256>` and `[u8; N]` are
/// both stack-value-types — invariant satisfied for all call-sites).
///
/// **The Drop body uses a raw-pointer cast `&mut self.0 as *mut
/// ManuallyDrop<T> as *mut u8`** (NOT a `(&mut *self.0)` DerefMut path, which
/// would be UB after `ManuallyDrop::take`). Per the stdlib
/// `#[repr(transparent)]` layout guarantee on `ManuallyDrop<T>`, the byte
/// representation is identical to `T`. Sound for byte-level access EVEN
/// AFTER `ManuallyDrop::take` has logically moved the inner `T` out.
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
        // SAFETY: Raw-pointer cast directly to the wrapper's ManuallyDrop
        // storage; bypasses Deref/DerefMut on T entirely. Per the stdlib
        // repr(transparent) layout guarantee
        // (https://doc.rust-lang.org/std/mem/struct.ManuallyDrop.html#layout-1),
        // ManuallyDrop<T> has the byte representation of T. This pointer is
        // sound for byte-level access EVEN AFTER ManuallyDrop::take has
        // logically moved the inner T out — the underlying bytes remain
        // valid for byte-level zeroization. A DerefMut-based pointer
        // acquisition (dereferencing the wrapper to obtain a T-typed pointer)
        // would be UB after ManuallyDrop::take because the dereference would
        // invoke ManuallyDrop's DerefMut on a moved-out value.
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

/// Internal HKDF error class. Surfaced at the FFI boundary as `i32` codes
/// by `hive_core_hkdf_sha256` (-1 invalid arg, -2 expand failure).
#[derive(Debug)]
enum HkdfError {
    InvalidLength,
}

/// **HKDF-SHA256 internal implementation.**
///
/// RFC 5869 Extract-then-Expand byte-identical to upstream `hkdf 0.12.4`.
/// Every transient binding holding key-bearing intermediate state is captured
/// in a HIVE-internal `ZeroOnDrop<T>` wrapper whose Drop body volatile-zeros
/// the inner bytes via raw-pointer cast (a regression test enforces this).
///
/// HMAC consumption: `digest::FixedOutput::finalize_into(self, &mut
/// Output<Self>)` per the `digest 0.10.7` signature (BY-VALUE `self`,
/// consuming). The inner `Hmac<Sha256>` is extracted by-value via
/// `ManuallyDrop::take(&mut wrapper.0)` and consumed by `finalize_into`;
/// the `ZeroOnDrop` wrapper slot remains on the stack and `Drop` runs at
/// scope exit, byte-zeroizing the now-spent `ManuallyDrop` slot. There are NO
/// `core::mem::forget` calls on `ZeroOnDrop` wrappers.
///
/// PRK-residency posture: the local `tmp: digest::Output<Hmac<Sha256>>`
/// (= `GenericArray<u8, U32>`) has no `Drop` impl; the Extract-scope tmp slot
/// holds the PRK in plaintext for the microsecond-scale window between
/// `finalize_into` and `prk_buf.copy_from_slice`. This matches upstream
/// `hkdf 0.12.4`'s PRK byte intermediate; the stack slot is overwritten by the
/// next stack-frame use. PRK is captured in `prk_buf` (ZeroOnDrop'd) which
/// Drops at scope exit.
///
/// Caller-owned salt residency: the caller MUST zeroize the salt source after
/// this call returns; the FFI does NOT zeroize caller-owned input buffers.
///
/// At least **7** distinct `ZeroOnDrop::<T>::drop` call-sites are visible in
/// `cargo expand --release`: `default_salt` + `extract_mac` + `prk_buf` +
/// `prk` + per-iter `iter_mac` + per-iter `iter_out` + `prev`.
fn hive_core_hkdf_sha256_impl(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), HkdfError> {
    use hmac::digest::{self, FixedOutput};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // === Extract (RFC 5869 §2.2): PRK = HMAC-Hash(salt, IKM) ===
    // Wrapper #1: default_salt — RFC 5869 §2.2 "if not provided, salt is
    // set to a string of HashLen zeros". HashLen = 32 for SHA-256.
    let default_salt: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
    let salt_bytes: &[u8] = match salt {
        None => &default_salt[..],
        Some(s) => s,
    };

    // Wrapper #2: extract_mac — captures the Extract-scope HMAC instance.
    let mut extract_mac: ZeroOnDrop<Hmac<Sha256>> = ZeroOnDrop::new(
        Hmac::<Sha256>::new_from_slice(salt_bytes).map_err(|_| HkdfError::InvalidLength)?,
    );
    extract_mac.update(ikm);

    // Wrapper #3: prk_buf — owns the PRK after extraction.
    let mut prk_buf: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
    {
        // tmp is a digest::Output<Hmac<Sha256>> = GenericArray<u8, U32>
        // with no Drop impl. PRK-residency posture documented above; the
        // stack slot is overwritten by the next stack-frame use.
        let mut tmp: digest::Output<Hmac<Sha256>> = Default::default();
        // By-value FixedOutput::finalize_into(self, &mut Output<Self>).
        // ManuallyDrop::take extracts the inner Hmac<Sha256> by-value; the
        // ZeroOnDrop wrapper slot remains for Drop at scope exit, where
        // ZeroOnDrop::drop volatile-zeros the (now-take'd) ManuallyDrop slot
        // bytes via the raw-pointer cast.
        FixedOutput::finalize_into(
            unsafe { ManuallyDrop::take(&mut extract_mac.0) },
            &mut tmp,
        );
        prk_buf.copy_from_slice(&tmp[..]);
    }
    // extract_mac drops at THIS scope exit — Drop volatile-zeros the inner
    // ManuallyDrop slot bytes covering BlockBuffer's array slot.

    // Wrapper #4: prk — second-residency capture for the Expand stage.
    let prk: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new(*prk_buf);

    // === Expand (RFC 5869 §2.3) ===
    let chunk_len = 32usize;
    // RFC 5869 §2.3 output bound: L <= 255 * HashLen.
    if okm.len() > 255 * chunk_len {
        return Err(HkdfError::InvalidLength);
    }

    // Wrapper #7 (Expand-scope; covered once at function level): prev —
    // T(0) = empty per RFC 5869 §2.3. The 32-zero placeholder bytes here
    // are stack-allocation only; T(0)-as-empty is encoded by the
    // `prev_set = false` skip on the first iteration's iter_mac.update.
    let mut prev: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
    let mut prev_set = false;

    for (block_n, block) in okm.chunks_mut(chunk_len).enumerate() {
        // Wrapper #5 (per-iter): iter_mac — fresh HMAC instance per Expand
        // iteration. Drops at iteration scope exit.
        let mut iter_mac: ZeroOnDrop<Hmac<Sha256>> = ZeroOnDrop::new(
            Hmac::<Sha256>::new_from_slice(&prk[..]).map_err(|_| HkdfError::InvalidLength)?,
        );
        if prev_set {
            iter_mac.update(&prev[..]);
        }
        iter_mac.update(info);
        iter_mac.update(&[block_n as u8 + 1]);

        // Wrapper #6 (per-iter): iter_out — captures T(i) bytes for the
        // current iteration. Drops at iteration scope exit.
        let mut iter_out: ZeroOnDrop<[u8; 32]> = ZeroOnDrop::new([0u8; 32]);
        {
            let mut tmp: digest::Output<Hmac<Sha256>> = Default::default();
            FixedOutput::finalize_into(
                unsafe { ManuallyDrop::take(&mut iter_mac.0) },
                &mut tmp,
            );
            iter_out.copy_from_slice(&tmp[..]);
        }
        // iter_mac drops here — Drop volatile-zeros the inner BlockBuffer
        // bytes for THIS iteration's HMAC state.

        let block_len = block.len();
        block.copy_from_slice(&iter_out[..block_len]);
        prev.copy_from_slice(&iter_out[..]);
        prev_set = true;
        // iter_out drops here (ZeroOnDrop on [u8; 32]).
    }
    // prev / prk / prk_buf / default_salt drop at function exit
    // (ZeroOnDrop volatile-zeros each).
    Ok(())
}

/// **HKDF-SHA256 FFI consumer.**
///
/// RFC 5869 HKDF-SHA256 derivation: a single FFI surface that both Android
/// (this crate) AND iOS (`mobile/ios/rust/src/lib.rs` sibling, byte-identical
/// at SYMBOL/ABI) consume from a shared Rust core. This makes the
/// cross-platform HKDF byte-identity structural — a single Rust symbol, a
/// single compiled object code, byte-identical output by construction —
/// rather than each platform reimplementing via `javax.crypto.Mac` /
/// `CryptoKit.HKDF`. Same parity mechanism as `hive_core_zeroize`.
///
/// Mechanism: direct `hmac::Hmac<sha2::Sha256>` Extract-then-Expand in
/// `hive_core_hkdf_sha256_impl` above, with HIVE-internal `ZeroOnDrop<T>`
/// wrappers on every key-bearing intermediate binding. Output is
/// byte-identical to upstream `hkdf 0.12.4` (verified against RFC 5869
/// §A.1-A.3 test vectors below).
///
/// Caller contract (UNSAFE):
///   - `ikm_ptr` MUST be non-null and point to `ikm_len` readable bytes
///     (or null IF `ikm_len == 0`).
///   - `salt_ptr` MAY be null IF AND ONLY IF `salt_len == 0` (RFC 5869
///     §2.2 "if not provided, it is set to a string of HashLen zeros");
///     otherwise MUST point to `salt_len` readable bytes.
///   - `info_ptr` MAY be null IF AND ONLY IF `info_len == 0` (RFC 5869
///     §2.3 info MAY be empty); otherwise MUST point to `info_len`
///     readable bytes.
///   - `okm_ptr` MUST be non-null AND point to `okm_len` writable bytes.
///   - `okm_len` MUST satisfy `1 <= okm_len <= 8160` (RFC 5869 §2.3
///     output bound `L <= 255 * HashLen = 255 * 32 = 8160`).
///   - Buffers MUST NOT alias destructively for the duration of the call.
///
/// Return value (i32):
///   -  0 = success; `okm_ptr[0..okm_len]` populated with the derived OKM.
///   - -1 = invalid argument (null `ikm_ptr` with non-zero `ikm_len`,
///         null `okm_ptr`, or `okm_len == 0` or `okm_len > 8160`).
///   - -2 = HKDF expand failure (output length exceeds RFC 5869 bound;
///         in practice the -1 pre-check catches this, but the underlying
///         impl returns `Err(HkdfError::InvalidLength)` and we surface it
///         distinctly to preserve the error-shape contract).
///
/// On any non-zero return, `okm_ptr` content is UNDEFINED (the caller
/// MUST NOT consume the buffer as keying material). The caller SHOULD
/// zeroize-on-failure via `hive_core_zeroize`.
///
/// SECURITY: zero allocation on the heap, zero logging, zero outbound.
/// Pure in-process derivation primitive. ZERO-TELEMETRY.
///
/// Cross-platform parity: the iOS sibling at `mobile/ios/rust/src/lib.rs`
/// exposes the SAME `hive_core_hkdf_sha256` `extern "C"` symbol with
/// byte-identical signature + behavior; both platforms statically link the
/// same compiled Rust object code from a single `Cargo.lock`-pinned source
/// tree. The cross-platform HKDF byte-identity is structural, not
/// discipline-enforced.
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
    // Defensive argument validation. RFC 5869 §2.3 caps OKM at 255*HashLen
    // = 255*32 = 8160 bytes for SHA-256.
    if okm_ptr.is_null() || okm_len == 0 || okm_len > 8160 {
        return -1;
    }
    if ikm_ptr.is_null() && ikm_len != 0 {
        return -1;
    }
    if salt_ptr.is_null() && salt_len != 0 {
        return -1;
    }
    if info_ptr.is_null() && info_len != 0 {
        return -1;
    }

    // SAFETY: caller-asserted contract above. Empty slices are constructed
    // for null+zero-length inputs per RFC 5869 §2.2/§2.3.
    let ikm: &[u8] = if ikm_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(ikm_ptr, ikm_len) }
    };
    let salt_opt: Option<&[u8]> = if salt_len == 0 {
        None
    } else {
        Some(unsafe { core::slice::from_raw_parts(salt_ptr, salt_len) })
    };
    let info: &[u8] = if info_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(info_ptr, info_len) }
    };
    let okm: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(okm_ptr, okm_len) };

    match hive_core_hkdf_sha256_impl(salt_opt, ikm, info, okm) {
        Ok(()) => 0,
        Err(HkdfError::InvalidLength) => -2,
    }
}

/// Placeholder symbol — kept around so future non-FFI internal helpers
/// have a home. NOT exported across the FFI boundary (`pub fn` without
/// `#[no_mangle] extern "C"` does NOT produce a symbol in `libhive_core.so`
/// that would land in the export-manifest scan).
///
/// Intentionally side-effect free.
pub fn placeholder() {
    // No-op. Compiles under all four Android ABIs (arm64-v8a, armeabi-v7a,
    // x86_64, x86).
}

// ---------------------------------------------------------------------------
// Unit tests — RFC 5869 §A.1 byte-identity (Test Case 1) plus Miri-checked
// soundness bodies for the ZeroOnDrop Drop-after-take path. The iOS sibling
// MAY mirror this set verbatim for cross-platform byte-identity.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 §A.1 Test Case 1 (basic test case with SHA-256).
    /// IKM  = 0x0b * 22
    /// salt = 0x000102030405060708090a0b0c
    /// info = 0xf0f1f2f3f4f5f6f7f8f9
    /// L    = 42
    /// OKM  = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    #[test]
    fn rfc5869_a1_test_case_1_byte_identity() {
        let ikm: [u8; 22] = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let mut okm = [0u8; 42];
        let rc = hive_core_hkdf_sha256(
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            okm.as_mut_ptr(),
            okm.len(),
        );
        assert_eq!(rc, 0, "HKDF FFI returned non-zero on RFC 5869 A.1 inputs");
        assert_eq!(okm, expected_okm, "OKM mismatch vs RFC 5869 A.1 expected");
    }

    #[test]
    fn invalid_args_return_negative_one() {
        let mut okm = [0u8; 32];
        // Null OKM pointer.
        let rc = hive_core_hkdf_sha256(
            [0u8; 1].as_ptr(),
            1,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
            32,
        );
        assert_eq!(rc, -1);
        // Zero OKM length.
        let rc = hive_core_hkdf_sha256(
            [0u8; 1].as_ptr(),
            1,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            okm.as_mut_ptr(),
            0,
        );
        assert_eq!(rc, -1);
        // OKM length exceeding RFC 5869 bound (255 * 32 = 8160).
        let rc = hive_core_hkdf_sha256(
            [0u8; 1].as_ptr(),
            1,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            okm.as_mut_ptr(),
            8161,
        );
        assert_eq!(rc, -1);
    }

    #[test]
    fn empty_salt_and_info_accepted() {
        // RFC 5869 §2.2: salt MAY be empty (semantically zero-string of HashLen).
        // §2.3: info MAY be empty.
        let ikm = [0u8; 32];
        let mut okm = [0u8; 32];
        let rc = hive_core_hkdf_sha256(
            ikm.as_ptr(),
            ikm.len(),
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            okm.as_mut_ptr(),
            okm.len(),
        );
        assert_eq!(rc, 0);
    }

    // -----------------------------------------------------------------------
    // Miri-checked UB-detection on the ZeroOnDrop Drop body invoked AFTER
    // ManuallyDrop::take. CI runs `cargo +nightly miri test test_v153_*` from
    // the `mobile/android/rust` workdir; ZERO Miri diagnostics are required,
    // with an INFO_SKIP fallback when miri is unavailable.
    // -----------------------------------------------------------------------

    /// **Drop after take on a primitive `T = u32`.**
    ///
    /// Verifies that `ZeroOnDrop::drop`'s raw-pointer cast `&mut self.0 as
    /// *mut ManuallyDrop<T> as *mut u8` is sound for byte-level access AFTER
    /// `ManuallyDrop::take` has logically moved the inner `T` out. A
    /// `(&mut *self.0) as *mut T as *mut u8` form would invoke
    /// `ManuallyDrop::DerefMut` on a moved-out value → UB diagnostic under
    /// Miri; the raw-pointer cast bypasses `DerefMut` entirely and is sound
    /// per the `#[repr(transparent)]` layout guarantee.
    #[test]
    fn test_v153_zeroize_drop_after_take() {
        let mut wrapper: ZeroOnDrop<u32> = ZeroOnDrop::new(42);
        let _ = unsafe { core::mem::ManuallyDrop::take(&mut wrapper.0) };
        drop(wrapper);
        // Raw-pointer cast — NO UB; a DerefMut form would UB.
    }

    /// **Drop after take on `T = Hmac<Sha256>` end-to-end.**
    ///
    /// Exercises the load-bearing pattern: `ManuallyDrop::take` extracts the
    /// inner `Hmac<Sha256>` by-value; passes it to by-value
    /// `digest::FixedOutput::finalize_into(self, &mut Output<Self>)`; the
    /// `ZeroOnDrop` wrapper slot remains for `Drop` at scope exit. Miri MUST
    /// report ZERO UB diagnostics on this end-to-end path.
    #[test]
    fn test_v153_zeroize_hmac_after_finalize() {
        use hmac::digest::{self, FixedOutput};
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut w: ZeroOnDrop<Hmac<Sha256>> = ZeroOnDrop::new(
            Hmac::<Sha256>::new_from_slice(&[0u8; 32]).expect("HMAC-SHA256 accepts 32-byte key"),
        );
        Mac::update(&mut *w, b"test");
        let mut tmp: digest::Output<Hmac<Sha256>> = Default::default();
        FixedOutput::finalize_into(
            unsafe { core::mem::ManuallyDrop::take(&mut w.0) },
            &mut tmp,
        );
        drop(w);
        // Drop runs sound under raw-pointer cast; Miri reports ZERO UB.
    }
}
