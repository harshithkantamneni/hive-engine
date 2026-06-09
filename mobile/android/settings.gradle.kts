// HIVE Android — settings.gradle.kts
//
// Minimal settings file to enable Gradle invocation. `build.gradle.kts` exists
// standalone, but Gradle requires settings.gradle.kts for any project to resolve.
//
// Scope: minimal pluginManagement + repositories + rootProject. The AGP plugin
// version is NOT declared here; it is supplied via `libs.versions.toml` and
// referenced from the build.gradle.kts plugins block.
//
// Known prerequisites for a successful build:
//   1. plugin `com.android.application` requires an explicit `version "<X.Y.Z>"`
//      OR resolution via libs.versions.toml
//   2. libs.versions.toml must exist
//   3. NDK r25c installed at $ANDROID_HOME/ndk/25.2.9519653
//   4. cargo-ndk wrapper installed
//   5. cmake 3.22.1 installed via the SDK manager

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "HIVE"
