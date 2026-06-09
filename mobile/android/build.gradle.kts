// HIVE Android — build.gradle.kts
//
// Gradle Kotlin DSL build script for the HIVE Android module. Defines plugin IDs,
// AGP / Kotlin / rust-android-gradle version pins, the externalNativeBuild path,
// the ABI filter set, the ndkVersion pin, --locked cargo discipline, and the
// forbidden-SDK negative-anchor block (ZERO-TELEMETRY compliance).
//
// Not yet in place:
//   - Symbol implementation in mobile/android/rust/src/lib.rs (placeholder only)
//   - Activity / runtime-prompt scaffolding
//   - Compose UI surface

plugins {
    // Plugin versions resolved via libs.versions.toml. See
    // `mobile/android/gradle/libs.versions.toml` for the [versions] / [plugins]
    // pin set. AGP 8.7+ minimum + Kotlin 2.0+ + rust-android-gradle 0.9.6.
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    // Kotlin Compose Compiler plugin — Kotlin 2.0+ ships the compiler as a separate
    // plugin (`org.jetbrains.kotlin.plugin.compose`) replacing the legacy
    // `composeOptions.kotlinCompilerExtensionVersion` config, so `@Composable`
    // annotations are processed at compile-time.
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.rust.android.gradle)
    // cargo-ndk integration (rust-android-gradle 0.9.6, per
    // github.com/mozilla/rust-android-gradle/releases 2025-01-13).
}

android {
    namespace = "computer.hive.app"               // Byte-identity with the iOS bundle ID.
    compileSdk = 35                                // Android 15.

    defaultConfig {
        applicationId = "computer.hive.app"
        minSdk = 31                                // API 31 baseline for BLE runtime permissions.
        targetSdk = 35                             // Match compileSdk.
        versionCode = 2
        versionName = "0.1.0"

        // ABI filter — exactly the four standard Android ABIs for the installed
        // Rust mobile targets. Build outputs four .so files per native lib.
        ndk {
            abiFilters += setOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }

        // Test runner — JUnit4 + Espresso for instrumentation.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // NDK pinning — r25+ provides the memset_explicit declaration.
    //
    // We carry r25c rather than upgrading to r27d LTS:
    //   1. The Bionic `memset_explicit __INTRODUCED_IN(34)` weak-link mechanism is
    //      preserved across NDK r25-r29 (per android.googlesource.com/platform/bionic/
    //      +/refs/heads/main/libc/include/string.h), so the structural mechanism we
    //      depend on is stable.
    //   2. Upgrading to r27d LTS (27.3.13750724) would require re-validating the
    //      four-ABI cross-compile matrix + Gradle DSL diff for a functionally
    //      equivalent end-state, with no security uplift unless a CVE lands on r25c.
    //   3. The runtime use of memset_explicit was removed entirely (a Rust-FFI
    //      primitive replaces it), so the binding to the toolchain is clang + linker
    //      only; no source change is required to stay on r25c.
    ndkVersion = "25.2.9519653"  // r25c.

    externalNativeBuild {
        cmake {
            path = file("src/main/jni/CMakeLists.txt")
            version = "3.22.1"  // Matches the CMakeLists.txt minimum.
        }
    }

    // Enable Jetpack Compose. The Compose-Compiler plugin is registered above
    // (kotlin.plugin.compose); buildFeatures.compose=true is the AGP-side toggle
    // that wires the plugin into resource-processing + R-class gen.
    buildFeatures {
        compose = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true                  // R8 / ProGuard.
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Strip Rust panic strings + native debug symbols from the release .so
            // to avoid leaking source paths via Rust panic messages.
            ndk {
                debugSymbolLevel = "NONE"           // Strip all native debug symbols in release.
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // Kotlin source-sets.
    sourceSets {
        getByName("main") {
            // AndroidManifest.xml lives at module-root; AGP defaults to src/main.
            manifest.srcFile("AndroidManifest.xml")
            // res/ lives at module-root, mirroring the AndroidManifest sibling layout.
            res.srcDirs("res")
            java.srcDirs("src/main/java")
        }
        getByName("test").java.srcDirs("src/test/java")
        getByName("androidTest").java.srcDirs("src/androidTest/java")
    }
}

// rust-android-gradle integration — cargo-ndk drop-in.
cargo {
    module       = "rust"                          // Path to Cargo.toml relative to this gradle file.
    libname      = "hive_core"                     // Output: libhive_core.so per ABI (zero exports for now).
    targets      = listOf("arm64", "arm", "x86_64", "x86")  // rust-android-gradle 0.9.6 uses "arm" (not "armv7"); maps to armv7-linux-androideabi.
    profile      = "release"
    pythonCommand = "python3"
    extraCargoBuildArguments = listOf(
        // The cargo module path is `mobile/android/rust` (set via `module = "rust"`,
        // resolved relative to this build.gradle.kts at `mobile/android/`). cargo runs
        // from `mobile/android/rust`, so `../../../target` resolves to the repo-root
        // `target/` (single-root workspace), matching the CMakeLists.txt path that also
        // anchors at repo-root. A `../../target` would resolve to `mobile/target/` instead.
        "--target-dir", "../../../target",         // Share the workspace target dir at repo-root.
        "--locked"                                 // Cargo.lock discipline for hermetic builds.
    )
}

// Wire cargo build into Gradle's native-library merge step.
project.afterEvaluate {
    tasks.named("preBuild") {
        dependsOn("cargoBuild")
    }
}

dependencies {
    // Android stdlib — minimum surface.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")

    // Jetpack Compose.
    // BOM-pinned: BOM 2024.10.01 transitively constrains compose-ui/foundation/material3.
    // androidx.activity:activity-compose 1.9.3 provides ComponentActivity.setContent.
    // androidx.lifecycle 2.8.7 supplies ViewModel + collectAsStateWithLifecycle.
    // ZERO-TELEMETRY: every dep is AndroidX-only (no Firebase, no Crashlytics,
    // no GMS analytics, no Sentry).
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    debugImplementation(libs.androidx.compose.ui.tooling.preview)

    // Test deps — JUnit + Espresso.
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.test:runner:1.6.1")
    androidTestImplementation("androidx.test:rules:1.6.1")

    // EXPLICITLY ABSENT — every line below is a forbidden telemetry/analytics SDK
    // (ZERO-TELEMETRY). The commented lines are kept as a negative reference so a
    // build-time scan can confirm none of these SDKs are present.
    //   implementation("com.google.firebase:firebase-bom:*")        // FORBIDDEN
    //   implementation("com.google.firebase:firebase-crashlytics")  // FORBIDDEN
    //   implementation("com.google.firebase:firebase-analytics")    // FORBIDDEN
    //   implementation("io.sentry:sentry-android")                  // FORBIDDEN
    //   implementation("com.appsflyer:af-android-sdk")              // FORBIDDEN
    //   implementation("io.branch.sdk.android:library")             // FORBIDDEN
    //   implementation("com.amplitude:android-sdk")                 // FORBIDDEN
    //   implementation("com.segment.analytics.android:analytics")   // FORBIDDEN
    //   implementation("com.mixpanel.android:mixpanel-android")     // FORBIDDEN
    //   implementation("com.adjust.sdk:adjust-android")             // FORBIDDEN
    //   implementation("com.google.android.gms:play-services-*")    // FORBIDDEN (transitively pulls GMS)
    //   implementation("com.bugsnag:bugsnag-android")               // FORBIDDEN
    //   implementation("com.newrelic.agent.android:android-agent")  // FORBIDDEN
    //   implementation("ly.count.android:sdk")                      // FORBIDDEN (countly)
    //   implementation("com.onesignal:OneSignal")                   // FORBIDDEN
    //   implementation("com.kochava.base:tracker")                  // FORBIDDEN
    //   implementation("com.singular.sdk:singular_sdk")             // FORBIDDEN
    //   implementation("com.posthog.android:posthog")               // FORBIDDEN
    //   implementation("com.urbanairship.android:urbanairship-fcm") // FORBIDDEN
    //   implementation("com.leanplum:leanplum-fcm")                 // FORBIDDEN
    //   implementation("com.optimizely.ab:android-sdk")             // FORBIDDEN
    //   implementation("com.launchdarkly:launchdarkly-android-client") // FORBIDDEN
    //   implementation("io.split.client:android-client")            // FORBIDDEN
    //   implementation("com.rollbar:rollbar-android")               // FORBIDDEN
    //   implementation("com.raygun:raygun4android")                 // FORBIDDEN
    //   implementation("com.microsoft.appcenter:appcenter-analytics") // FORBIDDEN
}
