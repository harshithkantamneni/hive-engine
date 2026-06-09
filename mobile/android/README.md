# HIVE Android

Android client for HIVE: device-salt storage, a zeroize-robust JNI primitive,
a Rust-FFI core crate (member of the root Cargo workspace), and the LEDGER
Compose surface.

## Layout

```
mobile/android/
├── AndroidManifest.xml
├── README.md                                    # this file
├── build.gradle.kts                             # Gradle Kotlin DSL
├── preflight/
│   ├── manifest_invariants.sh
│   ├── ffi_scaffold_invariants.sh               # 7 grep-anchors over the FFI scaffold
│   ├── android_permissions_whitelist.txt
│   └── android_forbidden_sdks.txt               # parity with the iOS list
├── res/
│   ├── values/strings.xml
│   └── xml/data_extraction_rules.xml
├── rust/                                         # Rust FFI crate
│   ├── Cargo.toml                               # workspace member of <repo>/Cargo.toml
│   └── src/lib.rs
└── src/
    ├── androidTest/java/computer/hive/app/security/
    │   └── DeviceSaltHandleHprofTest.kt         # HPROF heap-dump test
    ├── main/
    │   ├── java/computer/hive/app/security/
    │   │   ├── DeviceSalt.kt
    │   │   └── DeviceSaltHandle.kt
    │   └── jni/
    │       ├── CMakeLists.txt
    │       └── hive_zeroize.c
    └── test/java/computer/hive/app/security/
        └── DeviceSaltHandleZeroizeTest.kt
```

The root workspace at `<repo>/Cargo.toml` includes `mobile/android/rust` as a
member.

## Invariants (preflight-gated)

### `preflight/manifest_invariants.sh`

`AndroidManifest.xml` + `src/` sets:

- `android:allowBackup="false"` — NON-NEGOTIABLE.
- `android:dataExtractionRules="@xml/data_extraction_rules"` — A12+ all-exclude.
- `android:fullBackupContent="false"` — pre-A12 belt-and-suspenders.
- `android:hasFragileUserData="false"` — no keep-data-on-uninstall.
- `<uses-permission>` = the Bluetooth band plus legacy permissions
  (`neverForLocation` on `BLUETOOTH_SCAN`).
- `res/xml/data_extraction_rules.xml` all-exclude under `<cloud-backup>` +
  `<device-transfer>`.
- **JNI zeroize invariant** — `src/main/jni/hive_zeroize.c` MUST pair
  `GetByteArrayElements` ↔ `ReleaseByteArrayElements` (counts must match;
  cross-family mix with `GetPrimitiveArrayCritical` FORBIDDEN — silent
  zeroize-bug); source MUST contain a cleanse primitive (`memset_explicit` /
  `OPENSSL_cleanse` / `hive_volatile_memzero`).
- **loadLibrary guard** —
  `src/main/java/computer/hive/app/security/DeviceSaltHandle.kt` MUST contain
  exactly one `System.loadLibrary("hive_zeroize")` call.

### `preflight/ffi_scaffold_invariants.sh`

7 grep-anchors over the FFI scaffold + Rust workspace member:

1. `ndkVersion = "25.<patch>.<build>"` pin — exactly one hit.
2. `abiFilters` line MUST contain quoted-literal `"arm64-v8a"`, `"armeabi-v7a"`,
   `"x86_64"`, `"x86"` (quoted-literal match prevents `x86` substring-match-
   against-`x86_64` false-positive).
3. `"--locked"` exactly once in the build.gradle.kts cargo block (hermetic build).
4. Forbidden SDK negative scan over `build.gradle.kts` active surface (comment-
   stripped) against `preflight/android_forbidden_sdks.txt` (zero-dependency
   posture).
5. `src/main/jni/CMakeLists.txt` exactly once (binds the JNI build to Gradle).
6. `hive_core_zeroize` / `hive_core::zeroize` in `rust/src/lib.rs`.
7. `<repo-root>/Cargo.lock` exists AND `mobile/android/rust` is a workspace
   member of `<repo-root>/Cargo.toml`.

## JNI native library

`src/main/jni/hive_zeroize.c` + `src/main/jni/CMakeLists.txt` build
`libhive_zeroize.so`. The library exports
`Java_computer_hive_app_security_DeviceSaltHandle_nativeZeroize` which
runtime-gates between bionic `memset_explicit` (API 34+ via
`__INTRODUCED_IN(34)`) and an in-source volatile-memset loop for API 31-33
(BoringSSL-equivalent primitive; HIVE does NOT link libcrypto.so). Gradle
wiring lives in `build.gradle.kts` via `externalNativeBuild` —
`path = file("src/main/jni/CMakeLists.txt")`.

Load policy: `DeviceSaltHandle.kt` calls `System.loadLibrary("hive_zeroize")`
in a companion-object init block — `UnsatisfiedLinkError` propagates as
`ExceptionInInitializerError` (hard fail at construction). Silent fallthrough
to `Arrays.fill`-only (DSE-vulnerable) is forbidden. The user-facing surface
is the existing chip "Nearby-device discovery unavailable — secure storage
problem".

## Rust crate (`mobile/android/rust/`)

Workspace member of `<repo>/Cargo.toml`. Deps: `cxx 1.0` + `zeroize 1.8` +
`hkdf 0.13` + `sha2 0.10`; build-deps `cxx-build 1.0` + `cbindgen 0.27`. The
per-member `[profile.release]` block is intentionally OMITTED: Cargo silently
ignores per-member release blocks under workspace inheritance, so profile
settings inherit from the root.

The exported `extern "C"` symbols are `hive_core_zeroize` and
`hive_core_hkdf_sha256`; both are contract-preserving on
`DeviceSaltHandle.close()`.

## Tests

- `src/test/java/.../DeviceSaltHandleZeroizeTest.kt` — reflection pre-/post-close
  byte equality (Dalvik unit + ART instrumentation).
- `src/androidTest/java/.../DeviceSaltHandleHprofTest.kt` — HPROF heap-dump CI
  gate (AVD matrix API 31/33/34/35).

Both depend on a `DeviceSaltHandle.forTesting(ByteArray)` `@VisibleForTesting`
factory.

## Preflight invocation

```
# Manifest invariants:
./preflight/manifest_invariants.sh
# FFI scaffold invariants:
./preflight/ffi_scaffold_invariants.sh                         # v1.0 (default)
./preflight/ffi_scaffold_invariants.sh "" "" "" "" "" v1.1     # post-migration gate
./preflight/ffi_scaffold_invariants.sh "" "" "" "" "" v1.2     # flips deny.toml-absent WARN→FAIL
# Positional args: BUILD_GRADLE REPO_ROOT FORBIDDEN_LIST RUST_LIB_RS SHARED_FORBIDDEN_CRATES VERSION
```

Exit 0 = PASS; exit 1 = FAIL with a diagnostic citing the failing invariant.
