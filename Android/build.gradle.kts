// THE DPI — Android module: API 30–37 (Android 11–17), arm64-v8a, Rust .so built by Cargo.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
}

val nativeDir: Directory = rootProject.layout.projectDirectory.dir("Native")
val jniOut = layout.buildDirectory.dir("generated/jniLibs")

android {
    namespace = "com.eaquelxonline.thedpi"
    compileSdk = 37
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.eaquelxonline.thedpi"
        minSdk = 30
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0"
        ndk { abiFilters += "arm64-v8a" }
    }

    sourceSets {
        named("main") {
            manifest.srcFile("Source/Main/AndroidManifest.xml")
            kotlin.directories.clear()
            kotlin.directories += listOf("Source/Main/Kotlin", "../Shared/Source/Main/Kotlin")
            java.directories.clear()
            res.directories.clear()
            res.directories += "Source/Main/Resources"
            assets.directories.clear()
            resources.directories.clear()
            jniLibs.directories.clear()
            jniLibs.directories += jniOut.get().asFile.absolutePath
        }
    }

    // Release signing material is never committed: provided through the environment only.
    val keystore = System.getenv("THEDPI_KEYSTORE")
    if (keystore != null) {
        signingConfigs.create("release") {
            storeFile = file(keystore)
            storePassword = System.getenv("THEDPI_KEYSTORE_PASSWORD")
            keyAlias = System.getenv("THEDPI_KEY_ALIAS")
            keyPassword = System.getenv("THEDPI_KEY_PASSWORD")
        }
    }

    buildTypes {
        named("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs { useLegacyPackaging = false } // stored uncompressed, page-aligned, mapped in place
    }

    dependenciesInfo {
        includeInApk = false // no dependency metadata blob in the APK
        includeInBundle = false
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = true
        disable += setOf(
            "SetTextI18n", // single Turkish catalogue shared with Windows lives in Shared/…/Bridge.kt (Text)
            "ChromeOsAbiSupport", // arm64-v8a is the only in-scope ABI
            "AndroidGradlePluginVersion", "GradleDependency", "NewerVersionAvailable", // versions are pinned by the verified matrix
        )
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

// ---- Rust core for arm64-v8a, linked with the NDK clang driver, 16 KB page aligned.
val cargoBuildAndroid = tasks.register<Exec>("cargoBuildAndroid") {
    group = "build"
    description = "Builds libthe_dpi.so for aarch64-linux-android with the NDK linker."
    val windowsHost = System.getProperty("os.name").startsWith("Windows")
    val hostTag = if (windowsHost) "windows-x86_64" else "linux-x86_64"
    val linker = androidComponents.sdkComponents.ndkDirectory.map {
        it.file("toolchains/llvm/prebuilt/$hostTag/bin/aarch64-linux-android30-clang" + if (windowsHost) ".cmd" else "").asFile.absolutePath
    }
    workingDir(nativeDir)
    inputs.property("linker", linker)
    doFirst { environment("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", linker.get()) }
    environment("CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS", "-C link-arg=-Wl,-z,max-page-size=16384")
    commandLine("cargo", "build", "--release", "--locked", "--target", "aarch64-linux-android")
}

val copyAndroidNative = tasks.register<Copy>("copyAndroidNative") {
    dependsOn(cargoBuildAndroid)
    from(nativeDir.file("target/aarch64-linux-android/release/libthe_dpi.so"))
    into(jniOut.map { it.dir("arm64-v8a") })
}

tasks.named("preBuild") { dependsOn(copyAndroidNative) }
