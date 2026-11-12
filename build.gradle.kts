// THE DPI — root build. Verified toolchain (see Engineering.md §2):
// Gradle 9.7.1 · AGP 9.3.1 · Kotlin 2.4.21 · Rust 1.99.1 · JDK 21 (build) · NDK 28.2.13676358
plugins {
    base
    id("com.android.application") version "9.5.1" apply false
    id("org.jetbrains.kotlin.jvm") version "2.5.0-RC" apply false
}

val nativeDir: Directory = layout.projectDirectory.dir("Native")

// Cargo is the single source of truth for the native crate; Gradle only orchestrates it.
val nativeFormatCheck = tasks.register<Exec>("nativeFormatCheck") {
    group = "verification"
    description = "Verifies rustfmt formatting of the Rust core."
    workingDir(nativeDir)
    commandLine("cargo", "fmt", "--check")
}

val nativeLint = tasks.register<Exec>("nativeLint") {
    group = "verification"
    description = "Runs clippy on the Rust core with warnings as errors."
    mustRunAfter(nativeFormatCheck)
    workingDir(nativeDir)
    commandLine("cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings")
}

val nativeTest = tasks.register<Exec>("nativeTest") {
    group = "verification"
    description = "Runs the Rust core test suite (release profile)."
    mustRunAfter(nativeFormatCheck, nativeLint)
    workingDir(nativeDir)
    commandLine("cargo", "test", "--release", "--locked")
}

val nativeBuildHost = tasks.register<Exec>("nativeBuildHost") {
    group = "build"
    description = "Builds the Rust core for the build host (loaded by the JVM tests)."
    mustRunAfter(nativeFormatCheck, nativeLint, nativeTest)
    workingDir(nativeDir)
    commandLine("cargo", "build", "--release", "--locked")
}

tasks.named("check") {
    dependsOn(nativeFormatCheck, nativeLint, nativeTest)
}

