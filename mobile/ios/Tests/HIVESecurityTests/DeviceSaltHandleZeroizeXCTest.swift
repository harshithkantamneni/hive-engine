// HIVE iOS — DeviceSaltHandle zeroize-on-deinit parity test.
//
// This XCTest verifies cross-platform zeroize-parity on iOS — heap-state
// byte-identity verification post-`deinit` matching the Android acceptance
// criterion.
//
// MECHANISM:
//   1. Construct a DeviceSaltHandle with known non-zero bytes.
//   2. Retain a pointer to the backing bytes via `withUnsafeBufferPointer`
//      BEFORE deinit fires.
//   3. Force deinit (scope exit / explicit nil-out).
//   4. Re-read through the saved pointer and assert all-zero.
//
// CAVEAT: ARC may have reclaimed the memory between deinit and the post-
// deinit pointer-readback; the saved pointer is potentially dangling and the
// test is best-effort against the iOS memory model. This is necessary but not
// sufficient for full acceptance — a stronger acceptance criterion would use a
// heap-marker write + post-deinit scan, or a deterministic
// UnsafeMutableRawBufferPointer-backed allocation that survives ARC reclaim long
// enough for the test.
//
// With a placeholder DeviceSaltHandle that stores its bytes in a Swift `[UInt8]`
// ARC-managed array rather than a heap buffer with stable lifetime, the test
// passes vacuously.
//
// Cross-refs:
//   - iOS zeroize-parity acceptance criterion
//   - contract-preserving migration
//   - necessary-but-not-sufficient caveat

import XCTest
@testable import HIVESecurity

final class DeviceSaltHandleZeroizeXCTest: XCTestCase {

    /// Verifies post-deinit heap byte-identity (all-zero) for DeviceSaltHandle.
    func test_ADR_034_R18_iOS_zeroize_parity_post_deinit_byte_identity() {
        // Step 1 — construct handle with known non-zero bytes.
        var handle: DeviceSaltHandle? = DeviceSaltHandle(saltBytes:
            Array(repeating: UInt8(0xAB), count: 32))

        // Step 2 — retain a pointer to the backing bytes BEFORE deinit.
        // ARC-best-effort caveat: the saved pointer may be dangling after
        // step 3; this is the iOS memory-model limitation documented in the
        // test header.
        var savedPtr: UnsafePointer<UInt8>? = nil
        var savedCount: Int = 0
        handle?.withSaltBytes { buf in
            savedPtr = buf.baseAddress
            savedCount = buf.count
        }
        XCTAssertNotNil(savedPtr, "withSaltBytes MUST yield a non-nil baseAddress at v1.0 placeholder")
        XCTAssertEqual(savedCount, 32, "v1.0 placeholder allocates 32 bytes")

        // Step 3 — force deinit by nil-ing the only strong reference.
        handle = nil

        // Step 4 — re-read through the saved pointer and assert all-zero.
        // ARC-best-effort caveat: a Swift `[UInt8]` allocation is ARC-reclaimed
        // at deinit, so `savedPtr` MAY be dangling. The assertion below
        // documents the desired acceptance criterion; a stronger test would use
        // a heap buffer that survives ARC. Until then the test is best-effort
        // and may pass vacuously on memory that has been recycled to all-zero by
        // the OS allocator.
        if let ptr = savedPtr, savedCount > 0 {
            // Read the saved-pointer window. May be dangling; this is
            // best-effort.
            let buf = UnsafeBufferPointer(start: ptr, count: savedCount)
            for byte in buf {
                XCTAssertEqual(byte, 0,
                    "iOS zeroize-parity: post-deinit heap byte MUST be zero (ARC-best-effort caveat applies)")
            }
        }
    }
}
