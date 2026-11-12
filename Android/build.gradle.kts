// THE DPI — Android module: API 30–37 (Android 11–17), arm64-v8a, Rust .so built by Cargo.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
}

val nativeDir: Directory = rootProject.layout.projectDirectory.dir("Native")
val jniOut = layout.buildDirectory.dir("generated/jniLibs")

android {
    namespace = "com.the.dpi"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "com.the.dpi"
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
            kotlin.directories += "Source/Main/Kotlin"
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
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
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
            "SetTextI18n", // the single Turkish catalogue (object Text) is shared verbatim with the Windows module
            "ChromeOsAbiSupport", // arm64-v8a is the only in-scope ABI
            "AndroidGradlePluginVersion", "GradleDependency", "NewerVersionAvailable", // versions are pinned by the verified matrix
            "InlinedApi", // API 34+ foreground service types are conditionally guarded by Build.VERSION.SDK_INT
            "ObsoleteSdkInt", // defensive version checks for backward compatibility patterns
            "DrawAllocation", // custom canvas cyber animations
            "ViewConstructor", // programmatic-only custom views
            "ClickableViewAccessibility", // custom animated touch interactions
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
    mustRunAfter(":nativeFormatCheck", ":nativeLint", ":nativeTest", ":nativeBuildHost")
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
