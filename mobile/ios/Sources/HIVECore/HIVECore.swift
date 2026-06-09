// HIVE iOS — Swift wrapper around `extern "C"` Rust symbols. This file is the
// Swift-side consumer for `hive_core_hkdf_sha256`.
//
// The set of `extern "C"` symbols exported from `libhive_core.a` (consumed via
// `hive_core.xcframework`) MUST match the golden export manifest, which lists
// `hive_core_hkdf_sha256` + `hive_core_zeroize`. `DeviceSaltHandle.swift` is the
// consumer for `hive_core_zeroize`; THIS file is the consumer for
// `hive_core_hkdf_sha256`.
//
// Cross-refs:
//   - HKDF-SHA256 byte-identity-in-practice — STRUCTURAL because both platforms
//     consume the SAME compiled Rust symbol
//   - Sources/HIVECore directory layout
//   - Package.swift target wiring; deps `[hive_core]`
//   - the cbindgen-generated hive_core.h goes to
//     `Sources/HIVECore/include/hive_core.h` at build-time per build.sh
//   - the golden export manifest lists `hive_core_hkdf_sha256` +
//     `hive_core_zeroize`
//   - single Rust symbol both platforms; cross-platform parity is structural at
//     the FFI symbol layer
//   - the i32 status code set (canonical mapping: 0 success, -1 null OKM ptr,
//     -2 OKM length out of (0, 8160], -3 hkdf::expand failure)
//   - mobile/ios/rust/src/lib.rs (`extern "C" hive_core_hkdf_sha256`)
//   - module.modulemap in `Sources/HIVECore/include/` imports hive_core.h
//   - mobile/android/src/main/java/computer/hive/app/security/HiveCore.kt
//     (Kotlin sibling — same consumer pattern; cross-platform parity at the
//     symbol-import layer enforced by the golden manifest)

import Foundation

// MARK: — Rust FFI symbol declaration
//
// `hive_core_hkdf_sha256` is exported from `libhive_core.a` (xcframework
// binary target via Package.swift `.binaryTarget(name: "hive_core")`). The
// cbindgen-generated `Sources/HIVECore/include/hive_core.h` header carries the
// canonical C declaration; the `@_silgen_name` attribute below pins the linker
// symbol name to exactly `hive_core_hkdf_sha256` (no Swift name-mangling) so the
// linker resolves it against the Rust
// `#[no_mangle] pub extern "C" fn hive_core_hkdf_sha256` export. Verified by an
// nm-diff against the golden export manifest.
//
// Per the Rust SAFETY contract (mobile/ios/rust/src/lib.rs) every
// (`*ptr`, `*len`) pair is either NULL+0 OR a valid, properly-aligned
// readable (input) / writable (output) pointer to AT LEAST `len` bytes.
// The `HIVECore.hkdfSha256(...)` wrapper below threads the Swift `[UInt8]`
// + heap-allocated OKM buffer through this contract.
@_silgen_name("hive_core_hkdf_sha256")
private func hive_core_hkdf_sha256(_ ikmPtr: UnsafePointer<UInt8>?,
                                   _ ikmLen: Int,
                                   _ saltPtr: UnsafePointer<UInt8>?,
                                   _ saltLen: Int,
                                   _ infoPtr: UnsafePointer<UInt8>?,
                                   _ infoLen: Int,
                                   _ okmPtr: UnsafeMutablePointer<UInt8>?,
                                   _ okmLen: Int) -> Int32

/// Public Swift wrapper around HIVE's Rust FFI core.
///
/// Methods here surface the `extern "C"` symbols enumerated in the golden
/// export manifest. Each method enforces the SAFETY contract documented on the
/// Rust side and translates the i32 status-code return into a typed Swift
/// `Result`. The wrapper is intentionally THIN — it does NOT introduce business
/// logic; the cryptographic substrate is the Rust impl byte-identical with the
/// Android sibling.
///
/// ZERO-TELEMETRY: no logging, no crash-reporting, no analytics. Errors surface
/// to the caller as typed `Result.failure(Int32)` payloads — the caller decides
/// what to do.
public struct HIVECore {

    /// Result type for `hkdfSha256(...)`: success carries the 42-/L-byte OKM,
    /// failure carries the canonical i32 status from the Rust extern "C"
    /// entry point per this mapping:
    ///
    ///   - `-1` — null OKM pointer with non-zero `okmLength` (defensive guard;
    ///     unreachable from this Swift wrapper because `okmLength > 0`
    ///     guarantees a heap allocation, but exposed for cross-platform
    ///     completeness).
    ///   - `-2` — `okmLength == 0` OR `okmLength > 8160` (RFC 5869 §2.3
    ///     ceiling = 255 * 32 bytes for SHA-256).
    ///   - `-3` — `hkdf::Hkdf::expand` failure (only path: `okmLength > 8160`,
    ///     defensively guarded by `-2` above; reserved for future-proofing).
    public enum HkdfResult: Equatable {
        case success([UInt8])
        case failure(Int32)
    }

    /// Wrapper around `extern "C" fn hive_core_hkdf_sha256`
    /// (mobile/ios/rust/src/lib.rs). Computes RFC 5869 HKDF-SHA256 OKM
    /// derivation against caller-provided IKM / salt / info inputs.
    ///
    /// - Parameters:
    ///   - ikm:       input keying material (RFC 5869 §2.2 IKM).
    ///   - salt:      salt input (RFC 5869 §2.2; empty array permitted).
    ///   - info:      info / context input (RFC 5869 §2.2; empty permitted).
    ///   - okmLength: requested OKM length in bytes; MUST be in `(0, 8160]`
    ///                per RFC 5869 §2.3 ceiling.
    /// - Returns: `.success([UInt8])` of length `okmLength` on success; or
    ///   `.failure(Int32)` carrying the canonical status-code byte-identical
    ///   with the Android sibling.
    ///
    /// SECURITY: the Rust impl uses `hkdf::Hkdf::<sha2::Sha256>::new(...)
    /// .expand(info, okm)` — no allocation outside the OKM write, no logging,
    /// no outbound network. ZERO-TELEMETRY.
    ///
    /// SAFETY: each Swift array is bridged to a contiguous read-only buffer
    /// via `withUnsafeBufferPointer` for the duration of the FFI call; the
    /// OKM heap allocation is owned by this method and copied into the
    /// returned `[UInt8]` before deallocation. No raw pointer escapes the
    /// closure-scoped lifetime.
    public static func hkdfSha256(ikm: [UInt8],
                                  salt: [UInt8],
                                  info: [UInt8],
                                  okmLength: Int) -> HkdfResult {
        // Guard the OKM-length window before allocating. Mirrors the Rust
        // -2 path defensively at the Swift boundary so callers can fail-fast
        // without a transient heap allocation.
        guard okmLength > 0 && okmLength <= 8160 else {
            return .failure(-2)
        }

        // Heap-allocate the OKM buffer; deallocate before return on every
        // path. `.allocate(capacity:)` returns an uninitialized buffer; the
        // Rust extern "C" call writes ALL `okmLength` bytes on success.
        let okmBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: okmLength)
        defer { okmBuf.deallocate() }

        // Bridge each input slice into a pointer for the duration of the
        // FFI call. Empty arrays surface a NULL pointer + zero length,
        // matching the Rust SAFETY contract NULL-with-zero-len → empty
        // slice (RFC 5869 permits empty IKM / salt / info).
        let status = ikm.withUnsafeBufferPointer { ikmPtr in
            salt.withUnsafeBufferPointer { saltPtr in
                info.withUnsafeBufferPointer { infoPtr in
                    hive_core_hkdf_sha256(
                        ikmPtr.baseAddress,
                        ikm.count,
                        saltPtr.baseAddress,
                        salt.count,
                        infoPtr.baseAddress,
                        info.count,
                        okmBuf.baseAddress,
                        okmLength)
                }
            }
        }

        if status == 0 {
            // Copy heap bytes into a Swift Array before deallocate fires.
            return .success(Array(okmBuf))
        }
        return .failure(status)
    }
}
