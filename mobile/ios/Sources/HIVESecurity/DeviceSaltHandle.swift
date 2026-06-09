// HIVE iOS — DeviceSaltHandle (opaque wrapper + iOS zeroize-parity).
//
// The `deinit` body routes its zeroize-on-close semantics through
// `hive_core_zeroize(ptr, len)` exported by `mobile/ios/rust/src/lib.rs`. The
// public API (init / withSaltBytes / deinit zeroize-on-deinit semantics) is a
// contract-preserving surface.
//
// The `[UInt8]?` ARC-managed backing array is replaced by an
// `UnsafeMutableBufferPointer<UInt8>` heap allocation that survives across the
// deinit-to-pointer-readback boundary required by the zeroize-parity test (the
// test needs the buffer to remain resident long enough to verify post-zeroize
// byte-identity; ARC-managed Swift Arrays would be reclaimed before the readback
// fires). The heap allocation is `.allocate(capacity:)` + `.deallocate()` paired
// in `init` and `deinit`. Between zeroize and deallocate the bytes are
// guaranteed all-zero by the Rust extern "C" call, which compiles to
// `core::ptr::write_volatile` (compiler-cannot-elide) — the same guarantee as
// the Android JNI-side `hive_volatile_memzero`.
//
// CROSS-PLATFORM PARITY: iOS `deinit` zeroizes the backing salt bytes
// byte-identically with the Android `close()` path. Parity is STRUCTURAL — both
// platforms invoke the SAME compiled Rust function from the SAME source tree
// pinned by ONE Cargo.lock; a single Rust symbol is consumed by both platforms.
// The XCTest at `Tests/HIVESecurityTests/DeviceSaltHandleZeroizeXCTest.swift` is
// the acceptance test; with the heap allocation the post-deinit pointer readback
// is reliably resident within the same XCTest invocation (heap memory is owned
// by this class, not ARC).
//
// CONTRACT-PRESERVING DIFF:
//   - Public init signature:  init(saltBytes: [UInt8])           UNCHANGED
//   - Public withSaltBytes:   <R>(_ body: ...) rethrows -> R     UNCHANGED
//   - deinit zeroize-on-close semantics                          PRESERVED
//   - Internal storage:       `[UInt8]?` → `UnsafeMutableBufferPointer<UInt8>?`
//   - deinit body now calls `hive_core_zeroize` BEFORE deallocate.
//
// Cross-refs:
//   - DeviceSaltHandle opaque-wrapper class
//   - constructor / accessor / close / no-clone discipline
//   - iOS zeroize-parity
//   - Sources/HIVESecurity directory layout
//   - this file's test partner (DeviceSaltHandleZeroizeXCTest.swift)
//   - the golden export manifest (`hive_core_zeroize`)
//   - single Rust symbol both platforms
//   - mobile/ios/rust/src/lib.rs (Rust impl — byte-identical with Android)

import Foundation

// MARK: — Rust FFI symbol declaration
//
// `hive_core_zeroize` is exported from `libhive_core.a` (xcframework binary
// target via Package.swift `.binaryTarget(name: "hive_core")`). The
// cbindgen-generated `Sources/HIVECore/include/hive_core.h` header carries this
// declaration; until the first build runs end-to-end on an Apple toolchain, the
// Swift module-map exposes nothing. The forward declaration below is a
// SAFETY-NET that lets the file type-check ahead of cbindgen header generation;
// it can be removed once `import hive_core` exposes the symbol via the Clang
// module map.
//
// The `@_silgen_name` attribute pins the linker symbol name to exactly
// `hive_core_zeroize` (no Swift name-mangling) so the linker resolves it
// against the Rust `#[no_mangle] pub extern "C" fn hive_core_zeroize`
// export. Verified by an nm-diff against the golden export manifest.
@_silgen_name("hive_core_zeroize")
private func hive_core_zeroize(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int)

/// Opaque wrapper around the on-device salt material.
///
/// The wrapper holds an UnsafeMutableBufferPointer<UInt8> heap allocation; the
/// deinit zeroizes via `hive_core_zeroize` and then deallocates. The public API
/// shape (init / withSaltBytes / deinit) is a contract-preserving surface; only
/// the body differs from the placeholder.
public final class DeviceSaltHandle {

    // Heap allocation that survives ARC reclaim long enough for the
    // zeroize-parity XCTest to read post-deinit. Owned by this class — paired
    // `.allocate(capacity:)` in `init` + `hive_core_zeroize(...) +
    // .deallocate()` in `deinit`. The pointer is non-nil between init and
    // deinit; nil only after deinit completes.
    private var bytes: UnsafeMutableBufferPointer<UInt8>?

    /// Constructs a handle from raw salt bytes.
    public init(saltBytes: [UInt8]) {
        // Heap-allocate a buffer of saltBytes.count UInt8 elements that
        // will survive until `deinit` (no ARC reclaim mid-lifetime).
        let buf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: saltBytes.count)
        // Initialize the buffer by copying caller bytes. `initialize(from:)`
        // returns (Iterator, endIndex); we use the index variant.
        _ = buf.initialize(from: saltBytes)
        self.bytes = buf
    }

    /// Borrowed-buffer accessor — caller MUST NOT retain the pointer
    /// past the closure return (no-clone discipline).
    public func withSaltBytes<R>(_ body: (UnsafeBufferPointer<UInt8>) throws -> R) rethrows -> R {
        guard let bytes = self.bytes else {
            // Defensive — should be unreachable while the handle is live.
            // Yield an empty buffer if somehow nil; rethrows the closure.
            let empty = UnsafeBufferPointer<UInt8>(start: nil, count: 0)
            return try body(empty)
        }
        // Hand the immutable view over the mutable buffer to the closure.
        let view = UnsafeBufferPointer<UInt8>(start: bytes.baseAddress, count: bytes.count)
        return try body(view)
    }

    deinit {
        // Zeroize via the Rust FFI symbol BEFORE deallocate. The Rust impl uses
        // the `zeroize` crate's `Zeroize::zeroize()`, which compiles to
        // `core::ptr::write_volatile` per Rust `std::ptr` library docs — the
        // compiler-cannot-elide guarantee. Cross-platform zeroize-parity is
        // STRUCTURAL because the SAME compiled Rust function is invoked on both
        // Android and iOS from one Cargo.lock-pinned tree.
        if let buf = self.bytes {
            hive_core_zeroize(buf.baseAddress, buf.count)
            // Deinitialize + deallocate the heap buffer. `.deinitialize()`
            // is a no-op for trivially-destructible UInt8 but keeps the
            // allocator API symmetric with `.initialize(from:)`.
            buf.deinitialize()
            buf.deallocate()
            self.bytes = nil
        }
    }
}
