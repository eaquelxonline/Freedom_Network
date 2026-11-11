// THE DPI — Windows 10/11 x64 application module (Kotlin/JVM + JDK Swing + Rust DLL).
plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

version = "1.0.0"
base.archivesName.set("TheDPI")

val nativeDir: Directory = rootProject.layout.projectDirectory.dir("Native")
val hostLibDir: String = nativeDir.dir("target/release").asFile.absolutePath
val isWindowsHost = System.getProperty("os.name").startsWith("Windows")

kotlin {
    jvmToolchain(21)
    sourceSets {
        named("main") { kotlin.setSrcDirs(listOf("Source/Main/Kotlin", "../Shared/Source/Main/Kotlin")) }
        named("test") { kotlin.setSrcDirs(listOf("Source/Test/Kotlin")) }
    }
}

sourceSets {
    named("main") {
        java.setSrcDirs(emptyList<String>())
        resources.setSrcDirs(emptyList<String>())
    }
    named("test") {
        java.setSrcDirs(emptyList<String>())
        resources.setSrcDirs(emptyList<String>())
    }
}

application {
    mainClass.set("thedpi.CoreKt")
    applicationName = "TheDPI"
}

tasks.jar {
    manifest {
        attributes("Implementation-Title" to "THE DPI", "Implementation-Version" to project.version, "Main-Class" to "thedpi.CoreKt")
    }
}

tasks.named<JavaExec>("run") {
    dependsOn(":nativeBuildHost")
    jvmArgs("-Djava.library.path=$hostLibDir")
}

// Throwaway self-signed certificate for the loopback TLS tests. Generated at build time with the
// JDK keytool, never committed and never shipped; its password protects nothing.
val testKeystore = layout.buildDirectory.file("test/keystore.p12")
val testKeystorePassword = "thedpi-test-only"
val generateTestKeystore = tasks.register<Exec>("generateTestKeystore") {
    val ks = testKeystore.get().asFile
    val keytool = File(System.getProperty("java.home"), "bin/keytool" + if (isWindowsHost) ".exe" else "").absolutePath
    outputs.file(ks)
    doFirst {
        ks.parentFile.mkdirs()
        ks.delete()
    }
    commandLine(
        keytool, "-genkeypair", "-alias", "svc", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2",
        "-dname", "CN=svc.test", "-ext", "SAN=dns:svc.test", "-storetype", "PKCS12",
        "-keystore", ks.absolutePath, "-storepass", testKeystorePassword, "-keypass", testKeystorePassword,
    )
}

// JVM-side tests run by a zero-dependency runner (no JUnit) against the real JNI boundary.
val coreTest = tasks.register<JavaExec>("coreTest") {
    group = "verification"
    description = "Runs the JVM/JNI test suite against the host build of the Rust core."
    dependsOn(":nativeBuildHost", generateTestKeystore)
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("thedpi.CoreTestKt")
    jvmArgs(
        "-Djava.library.path=$hostLibDir",
        "-Xcheck:jni",
        "-Dthedpi.test.keystore=${testKeystore.get().asFile.absolutePath}",
        "-Dthedpi.test.keystore.password=$testKeystorePassword",
    )
}

tasks.test {
    enabled = false // no JUnit by policy; `coreTest` is the JVM test suite
    dependsOn(coreTest)
}

tasks.check { dependsOn(coreTest) }

// ---- Release packaging (Windows host only): MSVC DLL + jpackage app-image with a bundled runtime.
val nativeBuildWindows = tasks.register<Exec>("nativeBuildWindows") {
    group = "build"
    description = "Builds the_dpi.dll for x86_64-pc-windows-msvc (Windows host)."
    onlyIf { isWindowsHost }
    workingDir(nativeDir)
    commandLine("cargo", "build", "--release", "--locked", "--target", "x86_64-pc-windows-msvc")
}

val packageInput = tasks.register<Copy>("packageInput") {
    dependsOn(tasks.jar, nativeBuildWindows)
    from(tasks.jar)
    from(configurations.runtimeClasspath)
    from(nativeDir.file("target/x86_64-pc-windows-msvc/release/the_dpi.dll"))
    into(layout.buildDirectory.dir("package/input"))
}

val packageWindows = tasks.register<Exec>("packageWindows") {
    group = "distribution"
    description = "Creates the Windows app-image with jpackage (JDK tool). Sign with signtool afterwards."
    onlyIf { isWindowsHost }
    dependsOn(packageInput)
    val jdk = javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }.get().metadata.installationPath
    val out = layout.buildDirectory.dir("package/image").get().asFile
    doFirst { out.deleteRecursively() }
    commandLine(
        jdk.file("bin/jpackage" + if (isWindowsHost) ".exe" else "").asFile.absolutePath,
        "--type", "app-image", "--name", "TheDPI", "--app-version", project.version.toString(),
        "--vendor", "THE DPI", "--description", "Network intelligence and diagnostics",
        "--input", layout.buildDirectory.dir("package/input").get().asFile.absolutePath,
        "--main-jar", "TheDPI-${project.version}.jar", "--main-class", "thedpi.CoreKt",
        "--java-options", "-Djava.library.path=\$APPDIR",
        "--dest", out.absolutePath,
    )
}
