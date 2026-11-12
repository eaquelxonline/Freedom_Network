// Freedom Network — JVM-side tests (no third-party test framework; run by the Gradle `coreTest` task).
//
// Exercises the real JNI boundary against the host build of Native/Core.rs, the Kotlin
// wire codec, the platform TLS prober against a local TLS server, and the Turkish text
// catalogue. All network activity is loopback-only.

package com.freedom.network

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
    val path = System.getProperty("freedom.test.keystore") ?: error("freedom.test.keystore not set")
    val pw = (System.getProperty("freedom.test.keystore.password") ?: error("password not set")).toCharArray()
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
    println("Freedom Network JVM tests · java ${System.getProperty("java.version")} · ${System.getProperty("os.name")}")

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

    test("system-wide snapshot: JNI call, platform status and Turkish rendering") {
        val snap = SystemSnapshot.capture()
        val windows = System.getProperty("os.name").lowercase().contains("windows")
        eq(snap.status, if (windows) Codes.OK else Codes.UNSUPPORTED, "status")
        expect(Text.system(snap).isNotEmpty()) { "render" }
        val synthetic = SystemSnapshot(
            Codes.OK, 10, 3, 1, 4, 0, 0, 2, 1,
            listOf(ProcessInfo(1200, "app.exe", 0, 4, 0, 0, 0, 4, listOf("203.0.113.1:443"))),
            listOf(Observation(1, "app.exe", listOf(4, 1200)), Observation(4, "", listOf(1))),
        )
        val text = Text.system(synthetic)
        expect("el sıkışmada takılı" in text && "app.exe" in text && "203.0.113.1:443" in text) { text }
        for (c in 1..Text.KNOWN_SYSTEM_FINDINGS) expect(!Text.systemFinding(Observation(c, "x", listOf(1, 2))).startsWith("Bulgu")) { "finding $c" }
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
        for (m in 0..Text.KNOWN_DESYNC_MODES) expect(!Text.desyncMode(m).startsWith("Mod")) { "desyncMode $m" }
    }

    test("active DPI desync packet transformation and local proxy lifecycle over JNI") {
        DiagnosticSession(fastConfig).use { s ->
            val httpPayload = "GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n".toByteArray()
            val total = 40 + httpPayload.size
            val pkt = ByteArray(total)
            pkt[0] = 0x45.toByte()
            pkt[2] = ((total shr 8) and 0xff).toByte()
            pkt[3] = (total and 0xff).toByte()
            pkt[8] = 64
            pkt[9] = 6 // TCP
            pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1
            pkt[16] = 93.toByte(); pkt[17] = 184.toByte(); pkt[18] = 216.toByte(); pkt[19] = 34
            pkt[21] = 80
            pkt[23] = 80
            pkt[32] = 0x50.toByte()
            pkt[33] = 0x18.toByte()
            System.arraycopy(httpPayload, 0, pkt, 40, httpPayload.size)

            val res = s.desyncPacket(pkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 4))
            eq(res.status, Codes.OK, "desync status")
            eq(res.mode, DesyncMode.REALITY_VISION, "reality_vision mode")
            eq(res.sni, "blocked.example.com", "extracted host")
            expect(!res.dropped && res.packets.size >= 3) { "expected REALITY + ML-KEM-768 decoy + disordered segments, got ${res.packets.size}" }

            val started = s.startProxy(DesyncConfig(mode = DesyncMode.REALITY_VISION, port = 0))
            eq(started.status, Codes.OK, "startProxy status")
            eq(started.mode, DesyncMode.REALITY_VISION, "startProxy mode")
            expect(started.active && started.port > 0) { "proxy active on port ${started.port}" }
            expect("ENGELSİZ MOD" in Text.proxyStatus(started) && "REALITY + ML-KEM-768" in Text.proxyStatus(started)) { "proxy Turkish status" }
            eq(s.stopProxy(), Codes.OK, "stopProxy")
            expect(!s.proxyStats().active) { "proxy stopped" }
        }
    }

    test("ServerManager: multi-profile personal servers, failover, quota, key rotation, and device revocation") {
        val mgr = ServerManager()
        val s1 = ServerProfile(
            id = "srv-01",
            name = "Sunucu 01",
            primaryEndpoint = "vpn.example.com:443",
            backupEndpoint = "backup01.example.com:443",
            coverDest = "dl.google.com",
            deviceId = "android-arm64-01",
            authKeyHex = "0102030405060708",
            latencyMs = 18,
            lossPct = 0,
            quotaBytes = 10_000,
        )
        val s2 = ServerProfile(
            id = "srv-02",
            name = "Sunucu 02",
            primaryEndpoint = "backup.example.com:443",
            coverDest = "www.cloudflare.com",
            deviceId = "windows-x64-01",
            authKeyHex = "aabbccddeeff0011",
            latencyMs = 34,
            lossPct = 1,
            quotaBytes = 50_000,
        )
        mgr.upsert(s1)
        mgr.upsert(s2)
        eq(mgr.list().size, 2, "2 profiles")
        val selected = mgr.select("srv-01")!!
        eq(selected.status, ServerStatus.CONNECTED, "srv-01 connected")
        eq(selected.activeEndpoint, "vpn.example.com:443", "primary endpoint")

        // Failover switches to backupEndpoint on srv-01
        val failedOver = mgr.triggerFailover("srv-01")!!
        eq(failedOver.status, ServerStatus.FAILOVER, "failover status")
        eq(failedOver.activeEndpoint, "backup01.example.com:443", "backup endpoint active")

        // Quota enforcement
        val afterTraffic = mgr.recordTraffic("srv-01", 10_500)!!
        eq(afterTraffic.status, ServerStatus.QUOTA_EXCEEDED, "quota exceeded")
        expect(!afterTraffic.quotaAvailable) { "quota must be exhausted" }

        // Device revocation switches active profile to srv-02
        val revoked = mgr.revokeDevice("srv-01")!!
        eq(revoked.status, ServerStatus.REVOKED, "revoked status")
        eq(mgr.activeProfileId, "srv-02", "auto-promoted to srv-02")

        // Key rotation restores device access
        val rotated = mgr.rotateDeviceKey("srv-01", "9988776655443322")!!
        expect(!rotated.revoked && rotated.authKeyHex == "9988776655443322") { "key rotated" }

        val rendered = Text.serverManager(mgr)
        expect("Sunucu 01" in rendered && "Sunucu 02" in rendered && "dl.google.com" in rendered) { rendered }
    }

    test("TunBridge end-to-end: Happy Eyeballs DoH3, tracker sinkhole, STUN leak guard, UDP NAT, and universal TCP Desync") {
        DiagnosticSession(fastConfig).use { s ->
            val appToBridgeIn = java.io.PipedInputStream(65536)
            val appToBridgeOut = java.io.PipedOutputStream(appToBridgeIn)
            val bridgeToAppIn = java.io.PipedInputStream(65536)
            val bridgeToAppOut = java.io.PipedOutputStream(bridgeToAppIn)

            val protectedTcpCount = AtomicInteger(0)
            val protectedUdpCount = AtomicInteger(0)

            val mockDoh = DohClient { _, body, _ ->
                // RFC 8484 requires ID=0 in DoH wire query
                expect(body.size >= 12 && body[0].toInt() == 0 && body[1].toInt() == 0) { "DoH query ID must be 0" }
                DohResponse(1, 500, EncProtocol.DOH3, dnsAnswer(body, byteArrayOf(104.toByte(), 16.toByte(), 132.toByte(), 229.toByte())))
            }

            fun readNextIpPacket(input: java.io.InputStream): ByteArray {
                val hdr = ByteArray(20)
                var read = 0
                while (read < 20) {
                    val n = input.read(hdr, read, 20 - read)
                    if (n < 0) error("EOF reading IPv4 header")
                    read += n
                }
                val totalLen = IpPackets.u16(hdr, 2)
                val full = ByteArray(totalLen)
                System.arraycopy(hdr, 0, full, 0, 20)
                while (read < totalLen) {
                    val n = input.read(full, read, totalLen - read)
                    if (n < 0) error("EOF reading IPv4 body")
                    read += n
                }
                return full
            }

            val clientIp = IpPackets.parseIpLiteral(TunBridge.VPN_CLIENT_IP)!!
            val vpnDnsIp = IpPackets.parseIpLiteral(TunBridge.VPN_DNS_IP)!!
            val loopbackIp = IpPackets.parseIpLiteral("127.0.0.1")!!

            TunBridge(
                session = s,
                tunInput = appToBridgeIn,
                tunOutput = bridgeToAppOut,
                protectSocket = { protectedTcpCount.incrementAndGet(); true },
                protectDatagram = { protectedUdpCount.incrementAndGet(); true },
                dohClient = mockDoh,
                dohEndpoints = listOf(
                    "https://1.1.1.1/dns-query",
                    "https://8.8.8.8/dns-query",
                ),
                strictKillSwitch = true,
                blockTrackers = true,
                hardenStunLeaks = true,
            ).use { bridge ->
                bridge.start()

                // 1) DNS-over-UDP (port 53) intercepted and resolved via Happy Eyeballs Encrypted DNS (DoH3)
                val rawDnsQuery = Doh.query("cloudflare.com")!!.also {
                    it[0] = 0xCA.toByte()
                    it[1] = 0xFE.toByte()
                }
                val dnsPkt = IpPackets.buildIpv4Udp(clientIp, vpnDnsIp, 53000, 53, rawDnsQuery)
                appToBridgeOut.write(dnsPkt)
                appToBridgeOut.flush()

                val dnsReplyPkt = readNextIpPacket(bridgeToAppIn)
                val dnsReplyUdp = IpPackets.parseUdp(dnsReplyPkt)!!
                eq(dnsReplyUdp.srcPort, 53, "DNS reply srcPort")
                eq(dnsReplyUdp.dstPort, 53000, "DNS reply dstPort")
                eq(dnsReplyUdp.payload[0], 0xCA.toByte(), "restored DNS ID hi")
                eq(dnsReplyUdp.payload[1], 0xFE.toByte(), "restored DNS ID lo")
                eq(bridge.dnsQueries.get(), 1, "dnsQueries counter")
                eq(bridge.dohResolved.get(), 1, "dohResolved counter")

                // 1b) Tracker/telemetry DNS sinkhole returns local NXDOMAIN without touching upstream DoH
                val trackerQuery = Doh.query("doubleclick.net")!!.also {
                    it[0] = 0xDE.toByte()
                    it[1] = 0xAD.toByte()
                }
                val trackerPkt = IpPackets.buildIpv4Udp(clientIp, vpnDnsIp, 53001, 53, trackerQuery)
                appToBridgeOut.write(trackerPkt)
                appToBridgeOut.flush()

                val trackerReplyPkt = readNextIpPacket(bridgeToAppIn)
                val trackerReplyUdp = IpPackets.parseUdp(trackerReplyPkt)!!
                eq(trackerReplyUdp.payload[0], 0xDE.toByte(), "tracker DNS ID hi")
                eq(trackerReplyUdp.payload[3].toInt() and 0x0F, 3, "tracker DNS RCODE=3 (NXDOMAIN)")
                eq(bridge.trackersBlocked.get(), 1, "trackersBlocked counter")
                eq(bridge.dohResolved.get(), 1, "tracker must not hit DoH")

                // 1c) WebRTC STUN Binding Request IP-leak hardening returns ICMPv4 unreachable
                val stunPayload = IpPackets.buildStunIpDiscovery(0x2112A442, "", 0)
                val stunPkt = IpPackets.buildIpv4Udp(clientIp, loopbackIp, 53500, 3478, stunPayload)
                appToBridgeOut.write(stunPkt)
                appToBridgeOut.flush()

                val stunIcmp = readNextIpPacket(bridgeToAppIn)
                eq(stunIcmp[9].toInt() and 0xFF, IpPackets.PROTO_ICMP, "STUN leak blocked via ICMPv4")
                eq(stunIcmp[20].toInt() and 0xFF, 3, "ICMPv4 Type 3")
                eq(bridge.leaksBlocked.get(), 1, "leaksBlocked counter")

                // 2) Universal real-time UDP NAT relay over VpnService.protect()ed DatagramSocket
                DatagramSocket(0, InetAddress.getLoopbackAddress()).use { udpSrv ->
                    udpSrv.soTimeout = 3000
                    val srvThread = Thread {
                        val buf = ByteArray(512)
                        val dp = DatagramPacket(buf, buf.size)
                        udpSrv.receive(dp)
                        val msg = String(dp.data, 0, dp.length)
                        val reply = "UDP_PONG:$msg".toByteArray()
                        udpSrv.send(DatagramPacket(reply, reply.size, dp.socketAddress))
                    }.apply { isDaemon = true; start() }

                    val udpPayload = "FREEDOM_REALTIME_UDP_FRAME".toByteArray()
                    val udpOutPkt = IpPackets.buildIpv4Udp(clientIp, loopbackIp, 54000, udpSrv.localPort, udpPayload)
                    appToBridgeOut.write(udpOutPkt)
                    appToBridgeOut.flush()

                    val udpInPkt = readNextIpPacket(bridgeToAppIn)
                    val udpIn = IpPackets.parseUdp(udpInPkt)!!
                    eq(udpIn.srcPort, udpSrv.localPort, "UDP NAT reply srcPort")
                    eq(udpIn.dstPort, 54000, "UDP NAT reply dstPort")
                    eq(String(udpIn.payload), "UDP_PONG:FREEDOM_REALTIME_UDP_FRAME", "UDP NAT payload")
                    expect(protectedUdpCount.get() >= 1) { "protectDatagram must be called" }
                    srvThread.join(2000)
                }

                // 3) Universal TCP + Active Desync split over VpnService.protect()ed Socket
                ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { tcpSrv ->
                    tcpSrv.soTimeout = 3000
                    val httpReq = "GET / HTTP/1.1\r\nHost: cloudflare.com\r\n\r\n".toByteArray()
                    val srvThread = Thread {
                        tcpSrv.accept().use { conn ->
                            conn.soTimeout = 3000
                            val received = java.io.ByteArrayOutputStream()
                            val buf = ByteArray(256)
                            while (received.size() < httpReq.size) {
                                val n = conn.inputStream.read(buf)
                                if (n <= 0) break
                                received.write(buf, 0, n)
                            }
                            conn.outputStream.write("HTTP/1.1 200 FREEDOM_OK\r\n\r\n".toByteArray())
                            conn.outputStream.flush()
                        }
                    }.apply { isDaemon = true; start() }

                    // Send TCP SYN
                    val synPkt = IpPackets.buildIpv4Tcp(
                        srcIp = clientIp,
                        dstIp = loopbackIp,
                        srcPort = 55000,
                        dstPort = tcpSrv.localPort,
                        seq = 1000L,
                        ack = 0L,
                        flags = IpPackets.TCP_SYN,
                    )
                    appToBridgeOut.write(synPkt)
                    appToBridgeOut.flush()

                    val synAckPkt = readNextIpPacket(bridgeToAppIn)
                    val synAck = IpPackets.parseTcp(synAckPkt)!!
                    eq(synAck.flags and (IpPackets.TCP_SYN or IpPackets.TCP_ACK), IpPackets.TCP_SYN or IpPackets.TCP_ACK, "SYN+ACK flags")
                    eq(synAck.ack, 1001L, "SYN+ACK ack")

                    // Send PSH+ACK carrying HTTP request
                    val dataPkt = IpPackets.buildIpv4Tcp(
                        srcIp = clientIp,
                        dstIp = loopbackIp,
                        srcPort = 55000,
                        dstPort = tcpSrv.localPort,
                        seq = 1001L,
                        ack = (synAck.seq + 1L) and 0xFFFFFFFFL,
                        flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK,
                        payload = httpReq,
                    )
                    appToBridgeOut.write(dataPkt)
                    appToBridgeOut.flush()

                    var gotResponse = ""
                    for (attempt in 0 until 4) {
                        val pkt = readNextIpPacket(bridgeToAppIn)
                        val seg = IpPackets.parseTcp(pkt)!!
                        if (seg.payload.isNotEmpty()) {
                            gotResponse += String(seg.payload)
                            break
                        }
                    }
                    eq(gotResponse, "HTTP/1.1 200 FREEDOM_OK\r\n\r\n", "TCP response payload")
                    expect(protectedTcpCount.get() >= 1) { "protectSocket must be called" }
                    expect(bridge.desyncedFlows.get() >= 1) { "desyncedFlows must be >= 1" }
                    srvThread.join(2000)
                }

                // 4) Wi-Fi <-> Mobile Data roaming rebind refreshes active UDP/TCP sockets without dropping TUN
                bridge.rebindActiveSessions()
                expect(bridge.roamingRebinds.get() >= 1) { "roamingRebinds must be >= 1" }
            }
        }
    }

    // ------------------------------------------------------------------ 24. Restricted ISP network simulation: TLS record fragmentation, STUN 74B, realtime UDP 0x05
    test("restricted network simulation: TLS record fragmentation, STUN 74B, and realtime UDP 0x05") {
        DiagnosticSession().use { s ->
            val srcIp = IpPackets.parseIpLiteral("10.215.173.1")!!
            val dstIp = IpPackets.parseIpLiteral("104.16.132.229")!!

            // 1) STUN 74-byte IP Discovery UDP datagram (`0x00 0x01 0x00 0x46`)
            val stunPayload = IpPackets.buildStunIpDiscovery(0x11223344, "10.215.173.1", 50001)
            eq(stunPayload.size, 74, "STUN IP discovery size")
            val stunPkt = IpPackets.buildIpv4Udp(srcIp, dstIp, 50001, 50000, stunPayload)
            val stunRes = s.desyncPacket(stunPkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 3))
            eq(stunRes.status, Codes.OK, "STUN UDP desync status")
            eq(stunRes.protocol, 4, "PROTO_UDP_STUN_MEDIA (4)")
            eq(stunRes.packets.size, 2, "low-TTL decoy + real STUN UDP packet")

            // 2) Real-time UDP handshake (`0x05` + 16-byte offline magic)
            val realtimePayload = IpPackets.buildRealtimeUdpHandshake(48)
            val realtimePkt = IpPackets.buildIpv4Udp(srcIp, dstIp, 55123, 59100, realtimePayload)
            val realtimeRes = s.desyncPacket(realtimePkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 3))
            eq(realtimeRes.status, Codes.OK, "Realtime UDP desync status")
            eq(realtimeRes.protocol, 5, "PROTO_UDP_REALTIME (5)")
            eq(realtimeRes.packets.size, 2, "low-TTL decoy + real Realtime UDP packet")

            // 3) TLS 1.3 ClientHello Record-Layer Multi-Fragmentation (RFC 8446 §5.1)
            val hostBytes = "example.org".toByteArray(Charsets.US_ASCII)
            val sniExtLen = 5 + hostBytes.size
            val extsLen = 4 + sniExtLen
            val bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsLen
            val recLen = 4 + bodyLen
            val ch = java.nio.ByteBuffer.allocate(5 + recLen).apply {
                put(0x16.toByte()); put(0x03.toByte()); put(0x01.toByte())
                putShort(recLen.toShort())
                put(0x01.toByte())
                put(0x00.toByte()); putShort(bodyLen.toShort())
                put(0x03.toByte()); put(0x03.toByte())
                put(ByteArray(32))
                put(0x00.toByte())
                putShort(2); put(0x13.toByte()); put(0x01.toByte())
                put(0x01.toByte()); put(0x00.toByte())
                putShort(extsLen.toShort())
                putShort(0x0000); putShort(sniExtLen.toShort())
                putShort((3 + hostBytes.size).toShort())
                put(0x00.toByte()); putShort(hostBytes.size.toShort())
                put(hostBytes)
            }.array()
            val tcpPkt = IpPackets.buildIpv4Tcp(srcIp, dstIp, 52000, 443, 1000L, 0L, IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = ch)
            val desyncRes = s.desyncPacket(tcpPkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 4))
            val tcpChunks = IpPackets.extractOrderedStreamChunks(tcpPkt, ch, desyncRes)
            val tlsRecords = IpPackets.fragmentTlsClientHelloRecords(ch, tcpChunks)
            expect(tlsRecords.size >= 2) { "must fragment into multiple TLS 0x16 records" }
            for (rec in tlsRecords) {
                eq(rec[0].toInt() and 0xFF, 0x16, "each fragment is a valid TLS 0x16 record")
                expect(!String(rec, Charsets.ISO_8859_1).contains("example.org")) {
                    "no single TLS record may contain full SNI"
                }
            }
        }
    }

    // ------------------------------------------------------------------ 25. DNS Poisoning Detection, ICMP synthesis & Stream First-Flight Evasion
    test("DNS poison detection, ICMP unreachable synthesis, and stream planFirstPayload") {
        val q = Doh.query("example.org")!!

        // 1) ISP Poison detection: 195.175.254.2 / loopback / clean IP
        val poisonedIsp = dnsAnswer(q, byteArrayOf(195.toByte(), 175.toByte(), 254.toByte(), 2))
        expect(IpPackets.containsPoisonedDns(poisonedIsp)) { "must detect 195.175.254.2 as poisoned" }

        val poisonedLoopback = dnsAnswer(q, byteArrayOf(127, 0, 0, 1))
        expect(IpPackets.containsPoisonedDns(poisonedLoopback)) { "must detect 127.0.0.1 as poisoned" }

        val cleanAnswer = dnsAnswer(q, byteArrayOf(104.toByte(), 16.toByte(), 132.toByte(), 229.toByte()))
        expect(!IpPackets.containsPoisonedDns(cleanAnswer)) { "clean IP must not be flagged" }

        val minTtl = IpPackets.dnsMinTtl(cleanAnswer)
        eq(minTtl, 300L, "parsed DNS answer min TTL")

        // 2) ICMPv6 unreachable synthesis (RFC 4443 Type 1 Code 3) for immediate IPv4 fallback
        val mockIpv6 = ByteArray(40).apply {
            this[0] = 0x60 // IPv6 version 6
            this[6] = 6 // TCP
            this[7] = 64 // Hop limit
            // src: 2001:db8::1, dst: 2001:db8::2
            this[8] = 0x20; this[9] = 0x01; this[10] = 0x0d; this[11] = 0xb8.toByte(); this[23] = 1
            this[24] = 0x20; this[25] = 0x01; this[26] = 0x0d; this[27] = 0xb8.toByte(); this[39] = 2
        }
        val icmpv6 = IpPackets.buildIcmpv6Unreachable(mockIpv6)
        expect(icmpv6 != null) { "ICMPv6 packet must be synthesized" }
        eq(((icmpv6!![0].toInt() ushr 4) and 0x0F), 6, "ICMPv6 version")
        eq(icmpv6[6].toInt() and 0xFF, 58, "IPv6 Next Header = ICMPv6 (58)")
        eq(icmpv6[40].toInt() and 0xFF, 1, "ICMPv6 Type 1 (Destination Unreachable)")
        eq(icmpv6[41].toInt() and 0xFF, 3, "ICMPv6 Code 3 (Address Unreachable)")

        // 3) ICMPv4 unreachable synthesis for QUIC -> TCP fallback
        val clientIp = IpPackets.parseIpLiteral("10.215.173.1")!!
        val quicIp = IpPackets.parseIpLiteral("104.16.132.229")!!
        val quicPkt = IpPackets.buildIpv4Udp(clientIp, quicIp, 50000, 443, byteArrayOf(1, 2, 3, 4))
        val icmpv4 = IpPackets.buildIcmpv4Unreachable(quicPkt)
        expect(icmpv4 != null) { "ICMPv4 packet must be synthesized" }
        eq(icmpv4!![9].toInt() and 0xFF, 1, "IPv4 Proto = ICMP (1)")
        eq(icmpv4[20].toInt() and 0xFF, 3, "ICMPv4 Type 3 (Destination Unreachable)")
        eq(icmpv4[21].toInt() and 0xFF, 3, "ICMPv4 Code 3 (Port Unreachable)")

        // 4) SNI locator and planFirstPayload
        val hostBytes = "wikipedia.org".toByteArray(Charsets.US_ASCII)
        val sniExtLen = 5 + hostBytes.size
        val extsLen = 4 + sniExtLen
        val bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsLen
        val recLen = 4 + bodyLen
        val ch = java.nio.ByteBuffer.allocate(5 + recLen).apply {
            put(0x16.toByte()); put(0x03.toByte()); put(0x01.toByte())
            putShort(recLen.toShort())
            put(0x01.toByte())
            put(0x00.toByte()); putShort(bodyLen.toShort())
            put(0x03.toByte()); put(0x03.toByte())
            put(ByteArray(32))
            put(0x00.toByte())
            putShort(2); put(0x13.toByte()); put(0x01.toByte())
            put(0x01.toByte()); put(0x00.toByte())
            putShort(extsLen.toShort())
            putShort(0x0000); putShort(sniExtLen.toShort())
            putShort((3 + hostBytes.size).toShort())
            put(0x00.toByte()); putShort(hostBytes.size.toShort())
            put(hostBytes)
        }.array()

        val sniPos = IpPackets.findClientHelloSni(ch)
        expect(sniPos != null) { "must locate SNI offset in ClientHello" }
        eq(String(ch, sniPos!!.first, sniPos.second, Charsets.US_ASCII), "wikipedia.org", "extracted SNI string")

        val planned = IpPackets.planFirstPayload(ch, listOf(ch))
        expect(planned.size >= 2) { "planFirstPayload must fragment ClientHello" }
        for (f in planned) {
            eq(f[0].toInt() and 0xFF, 0x16, "each planned fragment is a valid TLS 0x16 record")
            expect(!String(f, Charsets.ISO_8859_1).contains("wikipedia.org")) {
                "no single planned fragment contains full wikipedia.org SNI"
            }
        }
    }

    println()
    println("RESULT: $passed passed, ${failures.size} failed")
    if (failures.isNotEmpty()) {
        failures.forEach { println("  failed: $it") }
        exitProcess(1)
    }
    exitProcess(0)
}

