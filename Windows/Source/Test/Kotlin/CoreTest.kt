// THE DPI — JVM-side tests (no third-party test framework; run by the Gradle `coreTest` task).
//
// Exercises the real JNI boundary against the host build of Native/Core.rs, the Kotlin
// wire codec, the platform TLS prober against a local TLS server, and the Turkish text
// catalogue. All network activity is loopback-only.

package thedpi

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.io.File
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.random.Random
import kotlin.system.exitProcess

private var passed = 0
private val failures = ArrayList<String>()

private fun test(name: String, body: () -> Unit) {
    val start = System.nanoTime()
    try {
        body()
        passed++
        println("PASS  $name (${(System.nanoTime() - start) / 1_000_000} ms)")
    } catch (t: Throwable) {
        failures += name
        println("FAIL  $name: $t")
        t.printStackTrace(System.out)
    }
}

private fun expect(cond: Boolean, msg: () -> String) {
    if (!cond) throw AssertionError(msg())
}

private fun <T> eq(actual: T, expected: T, what: String) = expect(actual == expected) { "$what: expected <$expected> but was <$actual>" }

private inline fun <reified E : Throwable> throws(block: () -> Unit) {
    try {
        block()
    } catch (e: Throwable) {
        if (e is E) return
        throw AssertionError("expected ${E::class.simpleName}, got $e")
    }
    throw AssertionError("expected ${E::class.simpleName}, nothing thrown")
}

// ---------------------------------------------------------------- loopback fixtures

/** Minimal DNS responder: answers every A query with 127.0.0.1; other types with no data. */
class FakeDns : AutoCloseable {
    private val socket = DatagramSocket(0, InetAddress.getLoopbackAddress()).apply { soTimeout = 50 }
    private val stop = AtomicBoolean(false)
    val queries = AtomicInteger()
    val address: String get() = "127.0.0.1:${socket.localPort}"
    private val thread = Thread {
        val buf = ByteArray(1500)
        while (!stop.get()) {
            val p = DatagramPacket(buf, buf.size)
            try { socket.receive(p) } catch (_: SocketTimeoutException) { continue } catch (_: Exception) { break }
            queries.incrementAndGet()
            val q = buf.copyOf(p.length)
            var i = 12
            while (i < q.size && q[i].toInt() != 0) i += (q[i].toInt() and 0xFF) + 1
            if (i + 5 > q.size) continue
            val qtype = ((q[i + 1].toInt() and 0xFF) shl 8) or (q[i + 2].toInt() and 0xFF)
            val question = q.copyOfRange(12, i + 5)
            val a = qtype == 1
            val out = java.io.ByteArrayOutputStream()
            out.write(q, 0, 2)
            out.write(byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, if (a) 1 else 0, 0, 0, 0, 0))
            out.write(question)
            if (a) out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 127, 0, 0, 1))
            val r = out.toByteArray()
            socket.send(DatagramPacket(r, r.size, p.socketAddress))
        }
    }.apply { isDaemon = true; start() }

    override fun close() {
        stop.set(true)
        thread.join(2000)
        socket.close()
    }
}

/** Local TLS server using the build-generated, throwaway self-signed certificate for svc.test. */
class TlsServer(ks: KeyStore, password: CharArray) : AutoCloseable {
    private val server: SSLServerSocket
    private val stop = AtomicBoolean(false)
    val port: Int get() = server.localPort

    init {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, password)
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        server = ctx.serverSocketFactory.createServerSocket(0, 16, InetAddress.getLoopbackAddress()) as SSLServerSocket
        server.soTimeout = 100
        val params = server.sslParameters
        params.applicationProtocols = arrayOf("h2", "http/1.1")
        server.sslParameters = params
        Thread {
            while (!stop.get()) {
                val c = try { server.accept() as SSLSocket } catch (_: SocketTimeoutException) { continue } catch (_: Exception) { break }
                Thread {
                    c.use {
                        runCatching {
                            it.soTimeout = 2000
                            it.startHandshake()
                            it.inputStream.read()
                        }
                    }
                }.apply { isDaemon = true; start() }
            }
        }.apply { isDaemon = true; start() }
    }

    override fun close() {
        stop.set(true)
        server.close()
    }
}

private fun loopbackConnect(): (String, Int, Int) -> Socket = { _, port, timeout ->
    Socket().apply { connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), timeout) }
}

private fun testKeystore(): Pair<KeyStore, CharArray> {
    val path = System.getProperty("thedpi.test.keystore") ?: error("thedpi.test.keystore not set")
    val pw = (System.getProperty("thedpi.test.keystore.password") ?: error("password not set")).toCharArray()
    val ks = KeyStore.getInstance("PKCS12")
    FileInputStream(File(path)).use { ks.load(it, pw) }
    return ks to pw
}

private fun env(dns: String) = EnvironmentInfo(
    osName = "Windows", osVersion = "Windows 11 24H2", osBuild = 26100, arch = "x86_64",
    networkType = NetworkType.ETHERNET, interfaceName = "test0", dnsServers = listOf(dns),
    mtu = 1500, hasIpv4 = YES, hasIpv6 = NO, connected = YES, validated = YES,
)

/** Minimal DoH answer for a native-built query: echo ID/question, one A record, no EDNS. */
private fun dnsAnswer(q: ByteArray, addr: ByteArray): ByteArray {
    var i = 12
    while (q[i].toInt() != 0) i += (q[i].toInt() and 0xFF) + 1
    val question = q.copyOfRange(12, i + 5)
    val out = java.io.ByteArrayOutputStream()
    out.write(q, 0, 2)
    out.write(byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, 1, 0, 0, 0, 0))
    out.write(question)
    out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4))
    out.write(addr)
    return out.toByteArray()
}

private val fastConfig = EngineConfig(timeoutMs = 600, dnsSamples = 2, tcpSamples = 2, mtu = false, cooldownMs = 0)

// ---------------------------------------------------------------- tests

fun main() {
    println("THE DPI JVM tests · java ${System.getProperty("java.version")} · ${System.getProperty("os.name")}")

    test("native library loads and API version matches") {
        expect(Native.available) { "load error: ${Native.loadError}" }
        eq(Native.apiVersion(), Native.EXPECTED_API, "api")
        eq(Native.engineVersion(), "1.0.0", "engine version")
    }

    test("wire codec roundtrip (Kotlin)") {
        val inner = Record().int(1, -5).text(2, "çğıöşü ✓")
        val r = Record().int(0, 0).int(1, Long.MAX_VALUE).int(1, Long.MIN_VALUE).text(3, "").record(4, inner).record(4, Record())
        val back = Wire.decode(Wire.encode(r))
        eq(back, r, "roundtrip")
        eq(back.ints(1), listOf(Long.MAX_VALUE, Long.MIN_VALUE), "ints")
        eq(back.records(4)[0].getText(2), "çğıöşü ✓", "nested text")
    }

    test("wire codec rejects malformed input") {
        val bad = listOf(
            byteArrayOf(), "XX\u0001".toByteArray(), "DP\u0002".toByteArray(),
            byteArrayOf(68, 80, 1, 0, 1, 0), byteArrayOf(68, 80, 1, 0, 1, 0, 0, 0, 2, 0, 0),
            byteArrayOf(68, 80, 1, 0, 9, 0, 0, 0, 0), byteArrayOf(68, 80, 1, 0, 2, 0, 0, 0, 2, -1, -2),
            byteArrayOf(68, 80, 1, 0, 1, -1, -1, -1, -1),
        )
        bad.forEach { b -> throws<WireException> { Wire.decode(b) } }
        throws<WireException> { Wire.decode(ByteArray(Wire.MAX_MESSAGE + 1)) }
        var deep = Record()
        repeat(Wire.MAX_DEPTH) { deep = Record().record(1, deep) }
        throws<WireException> { Wire.encode(deep) }
    }

    test("wire fuzz only raises WireException") {
        val rnd = Random(42)
        repeat(20_000) {
            val b = rnd.nextBytes(rnd.nextInt(64))
            if (b.size >= 3 && rnd.nextBoolean()) { b[0] = 68; b[1] = 80; b[2] = 1 }
            try { Wire.decode(b) } catch (_: WireException) { }
        }
    }

    test("UTF-8 truncation keeps code points intact") {
        eq(Wire.truncateUtf8("aş", 2), "a", "split 2-byte char")
        val long = "ş".repeat(Wire.MAX_TEXT)
        val t = Record().text(1, long).getText(1)!!
        expect(t.toByteArray().size <= Wire.MAX_TEXT && t.all { it == 'ş' }) { "bad truncation" }
    }

    test("Kotlin-encoded records are accepted by Rust and vice versa") {
        val h = Native.create(Wire.encode(fastConfig.toRecord()))
        try {
            eq(Native.setEnvironment(h, Wire.encode(env("127.0.0.1:9").toRecord())), Codes.OK, "setEnvironment")
            val det = Wire.decode(Native.detectEnvironment()!!)
            val os = System.getProperty("os.name").lowercase()
            eq(det.status?.toInt(), if (os.contains("windows")) Codes.OK else Codes.UNSUPPORTED, "detect status")
            expect(det.getText(Tags.Env.ARCH)!!.isNotEmpty()) { "arch" }
            eq(EnvironmentInfo.fromRecord(env("1.1.1.1").toRecord()), env("1.1.1.1"), "env roundtrip")
        } finally {
            Native.destroy(h)
        }
    }

    test("JNI error handling and handle lifecycle") {
        val h = Native.create(null)
        expect(h > 0) { "handle $h" }
        eq(Native.create(byteArrayOf(1, 2, 3)), Codes.WIRE.toLong(), "garbage config")
        eq(Native.setEnvironment(h, byteArrayOf(9)), Codes.WIRE, "garbage env")
        eq(Decode.evaluation(Native.evaluate(h)).status, Codes.NO_DATA, "evaluate before diagnose")
        eq(Decode.run(Native.diagnose(h, Wire.encode(Record()))).status, Codes.NO_ENVIRONMENT, "no environment")
        eq(Native.markApplied(h, 999), Codes.INVALID_ARGUMENT, "bad action")
        eq(Native.destroy(h), Codes.OK, "destroy")
        eq(Native.destroy(h), Codes.INVALID_HANDLE, "double destroy")
        for (bad in listOf(h, 0L, -1L, Long.MAX_VALUE)) {
            eq(Native.networkChanged(bad), Codes.INVALID_HANDLE, "networkChanged($bad)")
            eq(Decode.evaluation(Native.evaluate(bad)).status, Codes.INVALID_HANDLE, "evaluate($bad)")
            eq(Native.submitTls(bad, Wire.encode(Record())), Codes.INVALID_HANDLE, "submitTls($bad)")
        }
        val h2 = Native.create(null)
        expect(h2 > h) { "handles must never be reused" }
        Native.destroy(h2)
    }

    test("invalid targets are rejected with the offending input") {
        DiagnosticSession(fastConfig).use { s ->
            s.setEnvironment(env("127.0.0.1:9"))
            val r = s.diagnose(listOf("ok.test", "exa mple"), emptyList())
            eq(r.status, Codes.INVALID_ARGUMENT, "status")
            eq(r.invalid, "exa mple", "invalid echo")
            eq(s.diagnose((0..8).map { "h$it.test" }, emptyList()).status, Codes.LIMIT, "target limit")
        }
    }

    test("closed session refuses use") {
        val s = DiagnosticSession(fastConfig)
        s.close()
        s.close()
        throws<IllegalStateException> { s.evaluate() }
    }

    test("TLS prober: certificate failure is reported, never bypassed") {
        val (ks, pw) = testKeystore()
        TlsServer(ks, pw).use { srv ->
            val strict = TlsProber(SSLContext.getDefault().socketFactory, loopbackConnect())
            val r = strict.probe("svc.test", srv.port, 2000)
            eq(r.status, TlsStatus.CERTIFICATE, "untrusted self-signed")
        }
    }

    test("TLS prober: trusted server negotiates TLS 1.3 + ALPN h2") {
        val (ks, pw) = testKeystore()
        TlsServer(ks, pw).use { srv ->
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
            val ctx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
            val r = TlsProber(ctx.socketFactory, loopbackConnect()).probe("svc.test", srv.port, 2000)
            eq(r.status, TlsStatus.OK, "status")
            eq(r.version, "TLSv1.3", "version")
            eq(r.alpn, "h2", "alpn")
            // Hostname verification is enforced: wrong name fails even with a trusted cert.
            val wrong = TlsProber(ctx.socketFactory, loopbackConnect()).probe("other.test", srv.port, 2000)
            eq(wrong.status, TlsStatus.CERTIFICATE, "hostname mismatch")
        }
    }

    test("TLS prober: silent server times out within bound") {
        ServerSocket(0, 4, InetAddress.getLoopbackAddress()).use { ss ->
            val start = System.nanoTime()
            val r = TlsProber(SSLContext.getDefault().socketFactory, loopbackConnect()).probe("svc.test", ss.localPort, 300)
            eq(r.status, TlsStatus.TIMEOUT, "status")
            expect((System.nanoTime() - start) / 1_000_000 < 3000) { "bounded" }
        }
    }

    test("end-to-end: native probes + platform TLS + evaluation") {
        val (ks, pw) = testKeystore()
        FakeDns().use { dns ->
            TlsServer(ks, pw).use { srv ->
                DiagnosticSession(fastConfig).use { s ->
                    eq(s.setEnvironment(env(dns.address)), Codes.OK, "env")
                    val target = listOf("svc.test:${srv.port}")
                    // 1) Default trust → certificate failure diagnosed.
                    val strict = TlsProber(SSLContext.getDefault().socketFactory, loopbackConnect())
                    val r1 = s.run(target, emptyList(), strict)
                    eq(r1.run.status, Codes.OK, "run status")
                    val t = r1.run.targets.single()
                    eq(t.dnsStatus, 1, "dns ok")
                    eq(t.addresses, listOf("127.0.0.1"), "address")
                    expect(t.tcp4Ok > 0) { "tcp" }
                    eq(r1.tls.single().status, TlsStatus.CERTIFICATE, "tls")
                    val e1 = r1.evaluation!!
                    eq(e1.diagnoses.first().category, 8, "certificate diagnosis")
                    eq(e1.decision?.state, 1, "first sighting is only pending")
                    expect(dns.queries.get() >= 2) { "resolver sampled" }
                    // 2) Trusted → healthy, decision returns to Keep after debounce.
                    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
                    val ctx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
                    val trusted = TlsProber(ctx.socketFactory, loopbackConnect())
                    val r2 = s.run(target, emptyList(), trusted)
                    eq(r2.run.targets.single().tlsVersion, "TLSv1.3", "tls version reported to native")
                    eq(r2.evaluation!!.diagnoses.first().category, 16, "healthy")
                    val text = Text.report(r2)
                    expect("Sorun tespit edilmedi" in text && "TLSv1.3" in text) { text }
                    // 3) Network change invalidates results.
                    eq(s.networkChanged(), Codes.OK, "network changed")
                    eq(s.evaluate().status, Codes.NO_DATA, "stale results discarded")
                }
            }
        }
    }

    test("wire codec Bytes kind roundtrip (Kotlin) and limits") {
        val r = Record().bytes(1, byteArrayOf(0, 1, -1, -128)).bytes(1, byteArrayOf()).text(2, "x")
        val back = Wire.decode(Wire.encode(r))
        eq(back, r, "roundtrip")
        expect(back.getBytes(1)!!.contentEquals(byteArrayOf(0, 1, -1, -128))) { "bytes" }
        eq(Record().bytes(1, ByteArray(Wire.MAX_BYTES + 10)).getBytes(1)!!.size, Wire.MAX_BYTES, "truncated")
    }

    test("DoH query is built natively (RFC 8484, ID 0) and endpoints must be https") {
        val q = Doh.query("Svc.Test")!!
        expect(q[0].toInt() == 0 && q[1].toInt() == 0) { "ID must be 0" }
        eq(Doh.query("exa mple"), null, "invalid name")
        expect(Doh.validEndpoint("https://dns.example/dns-query")) { "https ok" }
        expect(!Doh.validEndpoint("http://dns.example/dns-query")) { "cleartext rejected" }
        expect(!Doh.validEndpoint("https://")) { "no host rejected" }
    }

    test("DoH end-to-end: JDK HTTP client over local HTTPS, native validation, classification") {
        val (ks, pw) = testKeystore()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, pw) }
        val serverCtx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        var mode = "ok"
        val https = HttpsServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        https.httpsConfigurator = HttpsConfigurator(serverCtx)
        https.createContext("/dns-query") { ex ->
            val q = ex.requestBody.readAllBytes()
            val (body, type) = if (mode == "ok") dnsAnswer(q, byteArrayOf(192.toByte(), 0, 2, 1)) to "application/dns-message"
            else "<html>login</html>".toByteArray() to "text/html"
            ex.responseHeaders.add("Content-Type", type)
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        https.start()
        try {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
            val clientCtx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
            val client = JdkDohClient(clientCtx)
            val endpoint = "https://127.0.0.1:${https.address.port}/dns-query"
            FakeDns().use { dns ->
                TlsServer(ks, pw).use { srv ->
                    DiagnosticSession(fastConfig).use { s ->
                        s.setEnvironment(env(dns.address))
                        val target = listOf("svc.test:${srv.port}")
                        val r1 = s.run(target, emptyList(), null, client, listOf(endpoint, "http://cleartext.invalid/dns-query"))
                        val e1 = r1.encrypted.single()
                        eq(e1.transport, 1, "transport ok")
                        expect(e1.protocol == EncProtocol.DOH || e1.protocol == EncProtocol.DOH3) { "protocol ${e1.protocol}" }
                        val obs1 = r1.evaluation!!.diagnoses.flatMap { it.observations }.map { it.code }
                        expect(41 in obs1) { "encrypted DNS available advisory expected, got $obs1" }
                        expect("Şifreli DNS" in Text.report(r1)) { "report section" }
                        // A login page answering 200 text/html must never count as DNS.
                        mode = "html"
                        val r2 = s.run(target, emptyList(), null, client, listOf(endpoint))
                        eq(r2.encrypted.single().transport, 6, "non-DNS content")
                        val obs2 = r2.evaluation!!.diagnoses.flatMap { it.observations }.map { it.code }
                        expect(42 in obs2 && 41 !in obs2) { "failure advisory expected, got $obs2" }
                    }
                }
            }
        } finally {
            https.stop(0)
        }
    }

    test("concurrent use of one session is safe") {
        DiagnosticSession(fastConfig).use { s ->
            s.setEnvironment(env("127.0.0.1:9"))
            val errors = AtomicInteger()
            val go = CountDownLatch(1)
            val threads = (0 until 8).map {
                Thread {
                    go.await()
                    repeat(300) {
                        try {
                            s.evaluate(); s.networkChanged(); s.setEnvironment(env("127.0.0.1:9"))
                        } catch (e: Exception) {
                            errors.incrementAndGet()
                        }
                    }
                }.apply { start() }
            }
            go.countDown()
            threads.forEach { it.join() }
            eq(errors.get(), 0, "errors")
        }
    }

    test("stress: 5000 create/destroy cycles do not exhaust the registry") {
        repeat(5000) {
            val h = Native.create(null)
            expect(h > 0) { "create failed at $it: $h" }
            eq(Native.destroy(h), Codes.OK, "destroy")
        }
    }

    test("Turkish text catalogue covers every native code") {
        for (c in 1..Text.KNOWN_CATEGORIES) expect(!Text.category(c).startsWith("Kategori")) { "category $c" }
        for (a in 0..Text.KNOWN_ACTIONS) expect(!Text.actionTitle(a).startsWith("Eylem") && Text.actionDetail(a, 1400).isNotEmpty()) { "action $a" }
        for (o in 1..Text.KNOWN_OBSERVATIONS) expect(!Text.observation(Observation(o, "x", listOf(1, 2))).startsWith("Gözlem")) { "observation $o" }
        for (s in 0..7) expect(!Text.state(s).startsWith("Durum")) { "state $s" }
        for (s in 0..13) expect(!Text.status(s).startsWith("durum")) { "status $s" }
    }

    println()
    println("RESULT: $passed passed, ${failures.size} failed")
    if (failures.isNotEmpty()) {
        failures.forEach { println("  failed: $it") }
        exitProcess(1)
    }
    exitProcess(0)
}
