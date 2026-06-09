// swift-tools-version: 5.10
//
// HIVE iOS — Swift Package Manager manifest.
//
// SPM (NOT CocoaPods, NOT Carthage) is the only dependency manager. The Rust
// core is consumed as an XCFramework via `.binaryTarget`; the XCFramework is
// built by `mobile/ios/build.sh` from cargo-emitted static-lib slices
// (aarch64-apple-ios + aarch64-apple-ios-sim + x86_64-apple-ios), with
// `cbindgen` generating the `hive_core.h` C header consumed via the Swift
// module-map at `Sources/HIVECore/include/module.modulemap`.
//
// The dependencies list is EXPLICITLY EMPTY (ZERO-TELEMETRY): NO third-party
// Swift package. Any future addition triggers a transitive forbidden-SDK scan
// against `mobile/ios/preflight/ios_forbidden_sdks.txt`.
//
// `Package.resolved` IS committed alongside this manifest (same lock-file
// discipline as Cargo.lock + gradle/libs.versions.toml).
//
// Cross-refs:
//   - the cross-compile pipeline that produces hive_core.xcframework
//   - iOS 14.0 deployment target
//   - forbidden-SDK scan against Package.resolved
import PackageDescription

let package = Package(
    name: "HIVE",
    platforms: [.iOS(.v14)],
    products: [
        .library(name: "HIVESecurity", targets: ["HIVESecurity"]),
        .library(name: "HIVECore",     targets: ["HIVECore"])
    ],
    dependencies: [
        // EXPLICITLY EMPTY — zero third-party Swift packages. ZERO-TELEMETRY.
        // Any future addition triggers a transitive forbidden-SDK scan via
        // `preflight/ios_forbidden_sdks.txt`.
    ],
    targets: [
        // Rust core consumed as XCFramework binary target.
        // Path is relative to the Package.swift root (= `mobile/ios/`).
        // Built by `mobile/ios/build.sh` step 6 (`xcodebuild -create-xcframework`)
        // from cargo-emitted slices in `target/<triple>/release/libhive_core.a`.
        .binaryTarget(
            name: "hive_core",
            path: "Frameworks/hive_core.xcframework"
        ),
        .target(
            name: "HIVECore",
            dependencies: ["hive_core"],
            path: "Sources/HIVECore"
        ),
        .target(
            name: "HIVESecurity",
            dependencies: ["HIVECore"],
            path: "Sources/HIVESecurity"
        ),
        .testTarget(
            name: "HIVESecurityTests",
            dependencies: ["HIVESecurity"],
            path: "Tests/HIVESecurityTests"
        ),
        .testTarget(
            name: "HIVECoreTests",
            dependencies: ["HIVECore"],
            path: "Tests/HIVECoreTests"
        )
    ]
)
