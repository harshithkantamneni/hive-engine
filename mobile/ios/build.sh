#!/usr/bin/env bash
# HIVE iOS — cross-compile pipeline.
#
# This is the canonical 7-step recipe from Rust source → iOS XCFramework →
# linked .ipa. CI invokes it (or an equivalent recipe) at every iOS build.
#
# Toolchain caveat: this pipeline requires a working Apple toolchain
# (xcrun + xcodebuild + lipo + cargo with iOS targets installed). On non-Apple
# CI runners or environments without the Apple Developer command-line tools,
# the steps below will fail with a `command not found` or rustup-target-missing
# error — that is expected. Live end-to-end execution requires an
# Apple-toolchain CI runner.
#
# Steps (each documented inline below):
#   1. cargo build --release --target aarch64-apple-ios       --locked  (device)
#   2. cargo build --release --target aarch64-apple-ios-sim   --locked  (M1+ sim)
#   3. cargo build --release --target x86_64-apple-ios        --locked  (Intel sim)
#   4. cbindgen --crate hive_mobile_ffi_ios --output Sources/HIVECore/include/hive_core.h
#   5. lipo -create <aarch64-sim.a> <x86_64.a> -output build/sim/libhive_core.a
#   6. xcodebuild -create-xcframework ... -output Frameworks/hive_core.xcframework
#   7. xcodegen generate
#
# Notes:
#   - `--locked` on every cargo build keeps the resolved graph hermetic.
#   - Release profile + xcodebuild stripping strips symbols.
#   - All three iOS triples MUST build cleanly.
#   - cbindgen output is preserved as a CI artifact (90-day audit window; NOT
#     committed to git).
#   - The post-build nm-diff checks the exported symbol set against the golden
#     export manifest.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUST_CRATE_DIR="${SCRIPT_DIR}/rust"
HEADER_OUT="${SCRIPT_DIR}/Sources/HIVECore/include/hive_core.h"
SIM_BUILD_DIR="${REPO_ROOT}/target/sim_universal"
XCFRAMEWORK_OUT="${SCRIPT_DIR}/Frameworks/hive_core.xcframework"

mkdir -p "${SIM_BUILD_DIR}"
mkdir -p "$(dirname "${HEADER_OUT}")"
mkdir -p "$(dirname "${XCFRAMEWORK_OUT}")"

# ---------------------------------------------------------------------------
# Step 1 — Build the Rust core for aarch64-apple-ios (device).
# ---------------------------------------------------------------------------
# The `--locked` flag asserts that Cargo.lock is byte-identical to the resolved
# graph (CI fail-closed if any drift).
echo "[ios-build][1/7] cargo build --release --target aarch64-apple-ios --locked"
cargo build --manifest-path "${RUST_CRATE_DIR}/Cargo.toml" \
    --release --target aarch64-apple-ios --locked

# ---------------------------------------------------------------------------
# Step 2 — Build the Rust core for aarch64-apple-ios-sim (M1+ simulator).
# ---------------------------------------------------------------------------
echo "[ios-build][2/7] cargo build --release --target aarch64-apple-ios-sim --locked"
cargo build --manifest-path "${RUST_CRATE_DIR}/Cargo.toml" \
    --release --target aarch64-apple-ios-sim --locked

# ---------------------------------------------------------------------------
# Step 3 — Build the Rust core for x86_64-apple-ios (Intel simulator).
# ---------------------------------------------------------------------------
echo "[ios-build][3/7] cargo build --release --target x86_64-apple-ios --locked"
cargo build --manifest-path "${RUST_CRATE_DIR}/Cargo.toml" \
    --release --target x86_64-apple-ios --locked

# ---------------------------------------------------------------------------
# Step 4 — Generate the cbindgen .h header.
# ---------------------------------------------------------------------------
# cbindgen output goes to the in-tree path
# `Sources/HIVECore/include/hive_core.h` for use by the Swift module-map. CI
# additionally preserves the artifact (build/cbindgen-audit.h or similar) for a
# 90-day audit window; that artifact is NOT committed to git.
echo "[ios-build][4/7] cbindgen --crate hive_mobile_ffi_ios --output ${HEADER_OUT}"
( cd "${RUST_CRATE_DIR}" \
  && cbindgen --crate hive_mobile_ffi_ios --output "${HEADER_OUT}" )

# ---------------------------------------------------------------------------
# Step 5 — Lipo-merge simulator slices (aarch64-sim + x86_64-sim → fat sim slice).
# ---------------------------------------------------------------------------
# An XCFramework wraps DEVICE + SIMULATOR slices; the simulator slice itself
# must contain BOTH aarch64 (M1+) and x86_64 (Intel) so that any Mac developer
# host can run the simulator target. lipo merges the two slices into a single
# fat archive.
echo "[ios-build][5/7] lipo -create simulator slices -> ${SIM_BUILD_DIR}/libhive_core.a"
lipo -create \
    "${REPO_ROOT}/target/aarch64-apple-ios-sim/release/libhive_core.a" \
    "${REPO_ROOT}/target/x86_64-apple-ios/release/libhive_core.a" \
    -output "${SIM_BUILD_DIR}/libhive_core.a"

# ---------------------------------------------------------------------------
# Step 6 — Build the XCFramework wrapping device + sim slices.
# ---------------------------------------------------------------------------
# Device slice = aarch64-apple-ios; simulator slice = lipo-merged sim build.
# Headers directory (Sources/HIVECore/include) ships the cbindgen-generated
# `hive_core.h` + the Clang `module.modulemap` that exposes the C symbols
# under the Swift module name `hive_core`.
echo "[ios-build][6/7] xcodebuild -create-xcframework -> ${XCFRAMEWORK_OUT}"
rm -rf "${XCFRAMEWORK_OUT}"
xcodebuild -create-xcframework \
    -library "${REPO_ROOT}/target/aarch64-apple-ios/release/libhive_core.a" \
        -headers "${SCRIPT_DIR}/Sources/HIVECore/include" \
    -library "${SIM_BUILD_DIR}/libhive_core.a" \
        -headers "${SCRIPT_DIR}/Sources/HIVECore/include" \
    -output "${XCFRAMEWORK_OUT}"

# ---------------------------------------------------------------------------
# Step 7 — Generate the Xcode project from project.yml.
# ---------------------------------------------------------------------------
# `.xcodeproj` is GENERATED at build time by `xcodegen` from the in-tree
# declarative `project.yml`. The generated `HIVE.xcodeproj` is NOT committed to
# git (it is rebuilt from project.yml at every CI run). This preserves
# merge-conflict immunity + audit clarity.
echo "[ios-build][7/7] xcodegen generate"
( cd "${SCRIPT_DIR}" && xcodegen generate )

echo "[ios-build] DONE: ${XCFRAMEWORK_OUT} + ${HEADER_OUT} + HIVE.xcodeproj generated."
# Scheme destination uses `generic/platform=iOS Simulator` which is SDK-level
# (no installed sim runtime required). For device builds use
# `generic/platform=iOS`. For a concrete sim run pass `-destination 'platform=iOS
# Simulator,name=<sim>'` (requires installed runtime — verify via `xcrun simctl
# list runtimes` first).
echo "[ios-build] Next: xcodebuild -scheme HIVE -configuration Release -destination 'generic/platform=iOS Simulator' build"
