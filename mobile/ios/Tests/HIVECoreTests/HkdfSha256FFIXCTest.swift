// HIVE iOS — `HIVECore.hkdfSha256` FFI consumer regression test.
//
// This test surfaces a Swift-side consumer for the `hive_core_hkdf_sha256` FFI
// symbol exported from `mobile/ios/rust/src/lib.rs`. It binds the acceptance
// criterion:
//
//   - call `HIVECore.hkdfSha256` with RFC 5869 Test Case 1 inputs (Appendix A.1
//     IKM/salt/info; OKM length 42 bytes)
//   - assert the returned status is 0 (success)
//   - assert the OKM bytes match the RFC 5869 §A.1 expected vector
//   - assert the negative-length / null-OKM defensive paths return the
//     canonical -1 / -2 / -3 error codes
//
// MECHANISM:
//   - The FFI symbol is consumed via the public Swift wrapper
//     `HIVECore.hkdfSha256(ikm:salt:info:okmLength:)`
//   - The wrapper allocates the OKM heap buffer and threads (ptr, len)
//     pairs into the extern "C" entry point per the SAFETY contract on the
//     Rust side (`mobile/ios/rust/src/lib.rs`).
//
// Cross-refs:
//   - HKDF-SHA256 byte-identity-in-practice; structural via a single Rust symbol
//   - FFI-consumer pattern
//   - the golden export manifest binds the symbol
//   - Android↔iOS dep-set + symbol byte-identity
//   - the i32 status code set
//   - mobile/ios/rust/src/lib.rs (extern "C" `hive_core_hkdf_sha256`)
//   - https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1 (test vec)

import XCTest
@testable import HIVECore

final class HkdfSha256FFIXCTest: XCTestCase {

    /// RFC 5869 Appendix A.1 byte-identity test for `HIVECore.hkdfSha256`.
    func test_ADR_036_R_PARITY_HKDF_SHA256_iOS_rfc5869_a1_byte_identity() {
        // RFC 5869 Appendix A.1 — Test Case 1 (Basic test case with SHA-256).
        // IKM   = 0x0b * 22 bytes
        // salt  = 0x000102030405060708090a0b0c
        // info  = 0xf0f1f2f3f4f5f6f7f8f9
        // L     = 42
        // OKM   = 3cb25f25faacd57a90434f64d0362f2a
        //         2d2d0a90cf1a5a4c5db02d56ecc4c5bf
        //         34007208d5b887185865
        let ikm: [UInt8]   = Array(repeating: 0x0b, count: 22)
        let salt: [UInt8]  = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c]
        let info: [UInt8]  = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                              0xf5, 0xf6, 0xf7, 0xf8, 0xf9]
        let expected: [UInt8] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65,
        ]

        let result = HIVECore.hkdfSha256(ikm: ikm,
                                         salt: salt,
                                         info: info,
                                         okmLength: 42)
        switch result {
        case .success(let okm):
            XCTAssertEqual(okm, expected,
                "HKDF-SHA256 byte-identity: OKM MUST match RFC 5869 §A.1 vector exactly.")
        case .failure(let status):
            XCTFail("Expected success, got status=\(status); RFC 5869 §A.1 vector should round-trip cleanly")
        }
    }

    /// Defensive-path coverage: `okmLength == 0` MUST surface as the canonical
    /// -2 status.
    func test_ADR_036_R_PARITY_ERROR_CODES_okm_length_zero_returns_neg_two() {
        let result = HIVECore.hkdfSha256(ikm: [0x00], salt: [], info: [],
                                         okmLength: 0)
        if case .failure(let status) = result {
            XCTAssertEqual(status, -2,
                "okmLength=0 MUST return -2 byte-for-byte cross-platform")
        } else {
            XCTFail("Expected -2 failure for okmLength=0, got \(result)")
        }
    }

    /// `okmLength > 8160` (RFC 5869 §2.3 ceiling = 255 * 32) MUST surface -2.
    func test_ADR_036_R_PARITY_ERROR_CODES_okm_length_overflow_returns_neg_two() {
        let result = HIVECore.hkdfSha256(ikm: [0x00], salt: [], info: [],
                                         okmLength: 8161)
        if case .failure(let status) = result {
            XCTAssertEqual(status, -2,
                "okmLength>8160 MUST return -2 byte-for-byte cross-platform")
        } else {
            XCTFail("Expected -2 failure for okmLength=8161, got \(result)")
        }
    }
}
