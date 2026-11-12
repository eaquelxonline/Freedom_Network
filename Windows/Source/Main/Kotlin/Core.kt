// THE DPI — Windows 10/11 x64 application (Kotlin/JVM, JDK Swing, Rust DLL via JNI).
//
// Self-contained: the JNI boundary (class thedpi.Native), the wire codec mirrored from
// Native/Core.rs, typed models, the platform-TLS prober, the diagnostic session
// orchestrator, the Turkish text catalogue, and this platform's integration.
// The shared section below is kept byte-identical with the other platform module.

package thedpi

import java.time.Duration
import java.net.http.HttpTimeoutException
import java.net.http.HttpResponse
import java.net.http.HttpRequest
import java.net.http.HttpClient
import java.net.URI
import java.net.ProxySelector
import java.net.ConnectException
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.KeyStore
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.UIManager
import javax.swing.WindowConstants
import kotlin.system.exitProcess

// ==================================================================================
// SHARED SECTION — identical in Android/Core.kt and Windows/Core.kt. Edit both together.
// ==================================================================================

// ------------------------------------------------------------------ JNI

/** The single JNI boundary. Symbols: Java_thedpi_Native_* in Native/Core.rs. */
object Native {
    const val EXPECTED_API = 1
    const val LIBRARY = "the_dpi"

    /** Null when the native library loaded; otherwise the reason it did not. */
    val loadError: Throwable? = try {
        System.loadLibrary(LIBRARY)
        null
    } catch (e: UnsatisfiedLinkError) {
        e
    } catch (e: SecurityException) {
        e
    }

    val available: Boolean get() = loadError == null

    @JvmStatic external fun apiVersion(): Int
    @JvmStatic external fun engineVersion(): String?
    @JvmStatic external fun create(config: ByteArray?): Long
    @JvmStatic external fun destroy(handle: Long): Int
    @JvmStatic external fun detectEnvironment(): ByteArray?
    @JvmStatic external fun setEnvironment(handle: Long, env: ByteArray): Int
    @JvmStatic external fun diagnose(handle: Long, request: ByteArray): ByteArray?
    @JvmStatic external fun submitTls(handle: Long, observations: ByteArray): Int
    @JvmStatic external fun evaluate(handle: Long): ByteArray?
    @JvmStatic external fun networkChanged(handle: Long): Int
    @JvmStatic external fun markApplied(handle: Long, action: Int): Int
    @JvmStatic external fun dohQuery(request: ByteArray): ByteArray?
    @JvmStatic external fun systemConnections(): ByteArray?
    @JvmStatic external fun submitEncrypted(handle: Long, results: ByteArray): Int
}

object Codes {
    const val OK = 0
    const val INVALID_ARGUMENT = -1
    const val INVALID_HANDLE = -2
    const val WIRE = -3
    const val BUSY = -4
    const val LIMIT = -5
    const val PANIC = -6
    const val NO_ENVIRONMENT = -7
    const val NO_DATA = -8
    const val UNSUPPORTED = -9
    const val JNI = -10
    const val INTERNAL = -11
}

class NativeException(val code: Int, message: String) : Exception(message)

// ------------------------------------------------------------------ wire codec

/** Mirror of `wire` in Native/Core.rs: "DP", version 1, fields (tag u8, kind u8, len u32 BE, payload). */
class Record {
    sealed interface Value
    data class IntValue(val v: Long) : Value
    data class TextValue(val v: String) : Value
    data class RecordValue(val v: Record) : Value
    class BytesValue(val v: ByteArray) : Value {
        override fun equals(other: Any?) = other is BytesValue && other.v.contentEquals(v)
        override fun hashCode() = v.contentHashCode()
    }

    val fields = ArrayList<Pair<Int, Value>>()

    fun int(tag: Int, v: Long) = apply { fields += tag to IntValue(v) }
    fun int(tag: Int, v: Int) = int(tag, v.toLong())
    fun text(tag: Int, v: String) = apply { fields += tag to TextValue(Wire.truncateUtf8(v, Wire.MAX_TEXT)) }
    fun record(tag: Int, r: Record) = apply { fields += tag to RecordValue(r) }
    fun bytes(tag: Int, v: ByteArray) = apply { fields += tag to BytesValue(v.copyOf(minOf(v.size, Wire.MAX_BYTES))) }
    fun getBytes(tag: Int): ByteArray? = fields.firstOrNull { it.first == tag && it.second is BytesValue }?.let { (it.second as BytesValue).v }

    fun ints(tag: Int): List<Long> = fields.filter { it.first == tag }.mapNotNull { (it.second as? IntValue)?.v }
    fun texts(tag: Int): List<String> = fields.filter { it.first == tag }.mapNotNull { (it.second as? TextValue)?.v }
    fun records(tag: Int): List<Record> = fields.filter { it.first == tag }.mapNotNull { (it.second as? RecordValue)?.v }
    fun getInt(tag: Int): Long? = ints(tag).firstOrNull()
    fun getText(tag: Int): String? = texts(tag).firstOrNull()
    val status: Long? get() = getInt(Tags.STATUS)

    override fun equals(other: Any?) = other is Record && other.fields == fields
    override fun hashCode() = fields.hashCode()
}

class WireException(message: String) : Exception(message)

object Wire {
    const val VERSION = 1
    const val MAX_MESSAGE = 256 * 1024
    const val MAX_DEPTH = 4
    const val MAX_FIELDS = 8192
    const val MAX_TEXT = 4096
    private const val KIND_INT = 1
    private const val KIND_TEXT = 2
    private const val KIND_RECORD = 3
    private const val KIND_BYTES = 4
    const val MAX_BYTES = 16 * 1024

    fun truncateUtf8(s: String, max: Int): String {
        val bytes = s.toByteArray(Charsets.UTF_8)
        if (bytes.size <= max) return s
        var end = max
        while (end > 0 && (bytes[end].toInt() and 0xC0) == 0x80) end-- // never split a code point
        return String(bytes, 0, end, Charsets.UTF_8)
    }

    fun encode(r: Record): ByteArray {
        val out = ByteArrayOutputStream(256)
        out.write('D'.code); out.write('P'.code); out.write(VERSION)
        val count = IntArray(1)
        encodeFields(r, out, 0, count)
        if (out.size() > MAX_MESSAGE) throw WireException("message too large")
        return out.toByteArray()
    }

    private fun header(out: ByteArrayOutputStream, tag: Int, kind: Int, len: Int) {
        require(tag in 0..255) { "tag out of range" }
        out.write(tag); out.write(kind)
        out.write(ByteBuffer.allocate(4).putInt(len).array())
    }

    private fun encodeFields(r: Record, out: ByteArrayOutputStream, depth: Int, count: IntArray) {
        if (depth >= MAX_DEPTH) throw WireException("too deep")
        for ((tag, v) in r.fields) {
            if (++count[0] > MAX_FIELDS) throw WireException("too many fields")
            when (v) {
                is Record.IntValue -> {
                    header(out, tag, KIND_INT, 8)
                    out.write(ByteBuffer.allocate(8).putLong(v.v).array())
                }
                is Record.TextValue -> {
                    val b = v.v.toByteArray(Charsets.UTF_8)
                    header(out, tag, KIND_TEXT, b.size)
                    out.write(b)
                }
                is Record.BytesValue -> {
                    header(out, tag, KIND_BYTES, v.v.size)
                    out.write(v.v)
                }
                is Record.RecordValue -> {
                    val inner = ByteArrayOutputStream()
                    encodeFields(v.v, inner, depth + 1, count)
                    header(out, tag, KIND_RECORD, inner.size())
                    inner.writeTo(out)
                }
            }
            if (out.size() > MAX_MESSAGE) throw WireException("message too large")
        }
    }

    fun decode(b: ByteArray): Record {
        if (b.size > MAX_MESSAGE) throw WireException("message too large")
        if (b.size < 3) throw WireException("truncated")
        if (b[0] != 'D'.code.toByte() || b[1] != 'P'.code.toByte()) throw WireException("bad magic")
        if (b[2].toInt() != VERSION) throw WireException("bad version")
        return decodeFields(ByteBuffer.wrap(b, 3, b.size - 3).slice(), 0, IntArray(1))
    }

    private fun decodeFields(buf: ByteBuffer, depth: Int, count: IntArray): Record {
        if (depth >= MAX_DEPTH) throw WireException("too deep")
        val rec = Record()
        while (buf.hasRemaining()) {
            if (buf.remaining() < 6) throw WireException("truncated header")
            val tag = buf.get().toInt() and 0xFF
            val kind = buf.get().toInt() and 0xFF
            val len = buf.int.toLong() and 0xFFFFFFFFL
            if (len > buf.remaining()) throw WireException("truncated payload")
            if (++count[0] > MAX_FIELDS) throw WireException("too many fields")
            val payload = buf.slice().limit(len.toInt()) as ByteBuffer
            buf.position(buf.position() + len.toInt())
            val value: Record.Value = when (kind) {
                KIND_INT -> {
                    if (len != 8L) throw WireException("bad int length")
                    Record.IntValue(payload.long)
                }
                KIND_TEXT -> {
                    if (len > MAX_TEXT) throw WireException("text too long")
                    val decoder = Charsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                    try {
                        Record.TextValue(decoder.decode(payload).toString())
                    } catch (e: CharacterCodingException) {
                        throw WireException("bad utf-8")
                    }
                }
                KIND_RECORD -> Record.RecordValue(decodeFields(payload, depth + 1, count))
                KIND_BYTES -> {
                    if (len > MAX_BYTES) throw WireException("bytes too long")
                    Record.BytesValue(ByteArray(len.toInt()).also { payload.get(it) })
                }
                else -> throw WireException("bad kind $kind")
            }
            rec.fields += tag to value
        }
        return rec
    }
}

/** Field tags; mirror of `tags` in Native/Core.rs. */
object Tags {
    const val STATUS = 0

    object Config {
        const val TIMEOUT_MS = 1; const val DNS_SAMPLES = 2; const val MAX_PARALLEL = 3; const val COOLDOWN_MS = 4
        const val HYSTERESIS_PCT = 5; const val QUIC = 6; const val MTU = 7; const val TCP_SAMPLES = 8; const val BUDGET_MS = 9
    }

    object Env {
        const val OS_NAME = 1; const val OS_VERSION = 2; const val ARCH = 3; const val NETWORK_TYPE = 4; const val INTERFACE = 5
        const val DNS_SERVER = 6; const val GATEWAY = 7; const val MTU = 8; const val HAS_IPV4 = 9; const val HAS_IPV6 = 10
        const val CAPTIVE = 11; const val METERED = 12; const val VALIDATED = 13; const val PRIVATE_DNS = 14
        const val PRIVATE_DNS_NAME = 15; const val OS_BUILD = 16; const val CONNECTED = 17; const val RESTRICT_BACKGROUND = 18
    }

    object Request { const val TARGET = 1; const val ALT_DNS = 2 }

    object Run { const val GENERATION = 1; const val DURATION_US = 2; const val RESOLVER = 3; const val TARGET = 4; const val INVALID = 5; const val ENCRYPTED = 6 }

    object Resolver {
        const val SERVER = 1; const val ALTERNATE = 2; const val SENT = 3; const val RECEIVED = 4
        const val AVG_US = 5; const val JITTER_US = 6; const val STATUS = 7; const val TCP_STATUS = 8
    }

    object Target {
        const val HOST = 1; const val PORT = 2; const val DNS_STATUS = 3; const val DNS_US = 4; const val ADDRESS = 5
        const val HTTPS_RR = 6; const val ALPN = 7; const val ECH = 8; const val TCP4_STATUS = 9; const val TCP4_US = 10
        const val TCP6_STATUS = 11; const val TCP6_US = 12; const val QUIC_STATUS = 13; const val QUIC_US = 14
        const val QUIC_VERSION = 15; const val PMTU = 16; const val MTU_STATUS = 17; const val TLS_STATUS = 18
        const val TLS_US = 19; const val TLS_VERSION = 20; const val TLS_ALPN = 21; const val TLS_CIPHER = 22
        const val TCP4_ATTEMPTS = 23; const val TCP4_OK = 24; const val TCP6_ATTEMPTS = 25; const val TCP6_OK = 26
        const val MTU_PROBES = 27; const val DNS_SERVER = 28; const val DNS_TCP = 29; const val DNS_RCODE = 30
        const val LITERAL = 31; const val MTU_CEILING = 32
    }

    object TlsSubmit { const val RESULT = 1 }
    object EncSubmit { const val RESULT = 1 }
    object Enc {
        const val ENDPOINT = 1; const val PROTOCOL = 2; const val TRANSPORT = 3; const val RTT_US = 4
        const val QUERY_NAME = 5; const val QTYPE = 6; const val RESPONSE = 7; const val STATUS = 8; const val ANSWERS = 9
    }
    object DohQuery { const val NAME = 1; const val QTYPE = 2; const val QUERY = 1 }
    object Sysnet {
        const val TOTAL = 1; const val ESTABLISHED = 2; const val LISTEN = 3; const val SYN_SENT = 4; const val TIME_WAIT = 5
        const val CLOSE_WAIT = 6; const val UDP = 7; const val PROCESS = 8; const val FINDING = 9; const val EXPOSED = 10; const val OS_ERROR = 11
    }
    object Process {
        const val PID = 1; const val NAME = 2; const val ESTABLISHED = 3; const val SYN_SENT = 4; const val LISTEN = 5
        const val UDP = 6; const val REMOTES = 7; const val CLOSE_WAIT = 8; const val SAMPLE = 9
    }
    object Finding { const val CODE = 1; const val SUBJECT = 2; const val ARG = 3 }

    object Tls {
        const val HOST = 1; const val PORT = 2; const val STATUS = 3; const val HANDSHAKE_US = 4
        const val VERSION = 5; const val ALPN = 6; const val CIPHER = 7
    }

    object Eval { const val SCORE = 1; const val EWMA = 2; const val GENERATION = 3; const val DIAGNOSIS = 4; const val DECISION = 5; const val STABILITY = 6; const val EVALUATIONS = 7 }
    object Diagnosis { const val CATEGORY = 1; const val CONFIDENCE = 2; const val OBSERVATION = 3 }
    object Observation { const val CODE = 1; const val SUBJECT = 2; const val ARG = 3 }
    object Decision { const val STATE = 1; const val ACTION = 2; const val CONFIDENCE = 3; const val CATEGORY = 4; const val COOLDOWN_MS = 5; const val PARAM = 6; const val HIGH_IMPACT = 7 }
}

// ------------------------------------------------------------------ models

const val NO = 0
const val YES = 1
const val UNKNOWN = 2

object NetworkType { const val UNKNOWN = 0; const val WIFI = 1; const val CELLULAR = 2; const val ETHERNET = 3; const val VPN = 4; const val OTHER = 5 }

data class EngineConfig(
    val timeoutMs: Int = 1500,
    val dnsSamples: Int = 5,
    val tcpSamples: Int = 3,
    val maxParallel: Int = 4,
    val cooldownMs: Int = 60_000,
    val hysteresisPct: Int = 10,
    val quic: Boolean = true,
    val mtu: Boolean = true,
    val budgetMs: Int = 20_000,
) {
    fun toRecord(): Record = Record()
        .int(Tags.Config.TIMEOUT_MS, timeoutMs).int(Tags.Config.DNS_SAMPLES, dnsSamples)
        .int(Tags.Config.TCP_SAMPLES, tcpSamples).int(Tags.Config.MAX_PARALLEL, maxParallel)
        .int(Tags.Config.COOLDOWN_MS, cooldownMs).int(Tags.Config.HYSTERESIS_PCT, hysteresisPct)
        .int(Tags.Config.QUIC, if (quic) 1 else 0).int(Tags.Config.MTU, if (mtu) 1 else 0)
        .int(Tags.Config.BUDGET_MS, budgetMs)
}

data class EnvironmentInfo(
    val osName: String = "",
    val osVersion: String = "",
    val osBuild: Long = 0,
    val arch: String = "",
    val networkType: Int = NetworkType.UNKNOWN,
    val interfaceName: String = "",
    val dnsServers: List<String> = emptyList(),
    val gateways: List<String> = emptyList(),
    val mtu: Int = 0,
    val hasIpv4: Int = UNKNOWN,
    val hasIpv6: Int = UNKNOWN,
    val captive: Int = UNKNOWN,
    val metered: Int = UNKNOWN,
    val validated: Int = UNKNOWN,
    val privateDns: Int = UNKNOWN,
    val privateDnsName: String = "",
    val connected: Int = UNKNOWN,
    val restrictBackground: Int = UNKNOWN,
) {
    fun toRecord(): Record {
        val r = Record()
            .text(Tags.Env.OS_NAME, osName).text(Tags.Env.OS_VERSION, osVersion).int(Tags.Env.OS_BUILD, osBuild)
            .text(Tags.Env.ARCH, arch).int(Tags.Env.NETWORK_TYPE, networkType).text(Tags.Env.INTERFACE, interfaceName)
            .int(Tags.Env.MTU, mtu).int(Tags.Env.HAS_IPV4, hasIpv4).int(Tags.Env.HAS_IPV6, hasIpv6)
            .int(Tags.Env.CAPTIVE, captive).int(Tags.Env.METERED, metered).int(Tags.Env.VALIDATED, validated)
            .int(Tags.Env.PRIVATE_DNS, privateDns).text(Tags.Env.PRIVATE_DNS_NAME, privateDnsName)
            .int(Tags.Env.CONNECTED, connected).int(Tags.Env.RESTRICT_BACKGROUND, restrictBackground)
        dnsServers.take(8).forEach { r.text(Tags.Env.DNS_SERVER, it) }
        gateways.take(8).forEach { r.text(Tags.Env.GATEWAY, it) }
        return r
    }

    /** Stable fingerprint used to detect network changes without storing history. */
    fun fingerprint(): String = listOf(networkType, interfaceName, dnsServers, gateways, connected, hasIpv6).joinToString("|")

    companion object {
        fun fromRecord(r: Record) = EnvironmentInfo(
            osName = r.getText(Tags.Env.OS_NAME) ?: "",
            osVersion = r.getText(Tags.Env.OS_VERSION) ?: "",
            osBuild = r.getInt(Tags.Env.OS_BUILD) ?: 0,
            arch = r.getText(Tags.Env.ARCH) ?: "",
            networkType = (r.getInt(Tags.Env.NETWORK_TYPE) ?: 0).toInt(),
            interfaceName = r.getText(Tags.Env.INTERFACE) ?: "",
            dnsServers = r.texts(Tags.Env.DNS_SERVER),
            gateways = r.texts(Tags.Env.GATEWAY),
            mtu = (r.getInt(Tags.Env.MTU) ?: 0).toInt(),
            hasIpv4 = (r.getInt(Tags.Env.HAS_IPV4) ?: 2).toInt(),
            hasIpv6 = (r.getInt(Tags.Env.HAS_IPV6) ?: 2).toInt(),
            captive = (r.getInt(Tags.Env.CAPTIVE) ?: 2).toInt(),
            metered = (r.getInt(Tags.Env.METERED) ?: 2).toInt(),
            validated = (r.getInt(Tags.Env.VALIDATED) ?: 2).toInt(),
            privateDns = (r.getInt(Tags.Env.PRIVATE_DNS) ?: 2).toInt(),
            privateDnsName = r.getText(Tags.Env.PRIVATE_DNS_NAME) ?: "",
            connected = (r.getInt(Tags.Env.CONNECTED) ?: 2).toInt(),
            restrictBackground = (r.getInt(Tags.Env.RESTRICT_BACKGROUND) ?: 2).toInt(),
        )
    }
}

data class ResolverResult(
    val server: String, val alternate: Boolean, val sent: Int, val received: Int,
    val avgUs: Long, val jitterUs: Long, val status: Int, val tcpStatus: Int,
)

data class TargetResult(
    val host: String, val port: Int, val literal: Boolean,
    val dnsStatus: Int, val dnsUs: Long, val dnsServer: String, val dnsViaTcp: Boolean, val addresses: List<String>,
    val httpsRecord: Boolean, val alpn: List<String>, val ech: Boolean,
    val tcp4Status: Int, val tcp4Us: Long, val tcp4Attempts: Int, val tcp4Ok: Int,
    val tcp6Status: Int, val tcp6Us: Long, val tcp6Attempts: Int, val tcp6Ok: Int,
    val quicStatus: Int, val quicUs: Long, val quicVersions: List<Long>,
    val mtuStatus: Int, val pathMtu: Int, val mtuCeiling: Int, val mtuProbes: Int,
    val tlsStatus: Int, val tlsUs: Long, val tlsVersion: String, val tlsAlpn: String, val tlsCipher: String,
) {
    val tcpOk: Boolean get() = tcp4Ok > 0 || tcp6Ok > 0
}

data class RunResult(
    val status: Int, val generation: Long, val durationUs: Long,
    val resolvers: List<ResolverResult>, val targets: List<TargetResult>, val invalid: String?,
)

data class Observation(val code: Int, val subject: String, val args: List<Long>)
data class Diagnosis(val category: Int, val confidence: Int, val observations: List<Observation>)
data class Decision(val state: Int, val action: Int, val confidence: Int, val category: Int, val cooldownMs: Long, val param: Long, val highImpact: Boolean)

data class Evaluation(
    val status: Int, val score: Long, val ewma: Long, val generation: Long, val stability: Long,
    val evaluations: Long, val diagnoses: List<Diagnosis>, val decision: Decision?,
)

object TlsStatus { const val NOT_RUN = 0; const val OK = 1; const val CERTIFICATE = 2; const val HANDSHAKE = 3; const val TIMEOUT = 4; const val IO = 5; const val UNSUPPORTED = 6 }

data class TlsResult(val host: String, val port: Int, val status: Int, val handshakeUs: Long, val version: String, val alpn: String, val cipher: String) {
    fun toRecord(): Record = Record()
        .text(Tags.Tls.HOST, host).int(Tags.Tls.PORT, port).int(Tags.Tls.STATUS, status)
        .int(Tags.Tls.HANDSHAKE_US, handshakeUs).text(Tags.Tls.VERSION, version)
        .text(Tags.Tls.ALPN, alpn).text(Tags.Tls.CIPHER, cipher)
}

object Decode {
    private fun Record.i(tag: Int) = (getInt(tag) ?: 0L).toInt()
    private fun Record.l(tag: Int) = getInt(tag) ?: 0L

    fun run(bytes: ByteArray?): RunResult {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        return RunResult(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            generation = r.l(Tags.Run.GENERATION),
            durationUs = r.l(Tags.Run.DURATION_US),
            resolvers = r.records(Tags.Run.RESOLVER).map {
                ResolverResult(
                    it.getText(Tags.Resolver.SERVER) ?: "", it.l(Tags.Resolver.ALTERNATE) == 1L,
                    it.i(Tags.Resolver.SENT), it.i(Tags.Resolver.RECEIVED), it.l(Tags.Resolver.AVG_US),
                    it.l(Tags.Resolver.JITTER_US), it.i(Tags.Resolver.STATUS), it.i(Tags.Resolver.TCP_STATUS),
                )
            },
            targets = r.records(Tags.Run.TARGET).map { t ->
                TargetResult(
                    host = t.getText(Tags.Target.HOST) ?: "", port = t.i(Tags.Target.PORT), literal = t.l(Tags.Target.LITERAL) == 1L,
                    dnsStatus = t.i(Tags.Target.DNS_STATUS), dnsUs = t.l(Tags.Target.DNS_US), dnsServer = t.getText(Tags.Target.DNS_SERVER) ?: "",
                    dnsViaTcp = t.l(Tags.Target.DNS_TCP) == 1L, addresses = t.texts(Tags.Target.ADDRESS),
                    httpsRecord = t.l(Tags.Target.HTTPS_RR) == 1L, alpn = t.texts(Tags.Target.ALPN), ech = t.l(Tags.Target.ECH) == 1L,
                    tcp4Status = t.i(Tags.Target.TCP4_STATUS), tcp4Us = t.l(Tags.Target.TCP4_US), tcp4Attempts = t.i(Tags.Target.TCP4_ATTEMPTS), tcp4Ok = t.i(Tags.Target.TCP4_OK),
                    tcp6Status = t.i(Tags.Target.TCP6_STATUS), tcp6Us = t.l(Tags.Target.TCP6_US), tcp6Attempts = t.i(Tags.Target.TCP6_ATTEMPTS), tcp6Ok = t.i(Tags.Target.TCP6_OK),
                    quicStatus = t.i(Tags.Target.QUIC_STATUS), quicUs = t.l(Tags.Target.QUIC_US), quicVersions = t.ints(Tags.Target.QUIC_VERSION),
                    mtuStatus = t.i(Tags.Target.MTU_STATUS), pathMtu = t.i(Tags.Target.PMTU), mtuCeiling = t.i(Tags.Target.MTU_CEILING), mtuProbes = t.i(Tags.Target.MTU_PROBES),
                    tlsStatus = t.i(Tags.Target.TLS_STATUS), tlsUs = t.l(Tags.Target.TLS_US), tlsVersion = t.getText(Tags.Target.TLS_VERSION) ?: "",
                    tlsAlpn = t.getText(Tags.Target.TLS_ALPN) ?: "", tlsCipher = t.getText(Tags.Target.TLS_CIPHER) ?: "",
                )
            },
            invalid = r.getText(Tags.Run.INVALID),
        )
    }

    fun evaluation(bytes: ByteArray?): Evaluation {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        return Evaluation(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            score = r.getInt(Tags.Eval.SCORE) ?: -1, ewma = r.getInt(Tags.Eval.EWMA) ?: -1,
            generation = r.l(Tags.Eval.GENERATION), stability = r.l(Tags.Eval.STABILITY), evaluations = r.l(Tags.Eval.EVALUATIONS),
            diagnoses = r.records(Tags.Eval.DIAGNOSIS).map { d ->
                Diagnosis(
                    d.i(Tags.Diagnosis.CATEGORY), d.i(Tags.Diagnosis.CONFIDENCE),
                    d.records(Tags.Diagnosis.OBSERVATION).map { o -> Observation(o.i(Tags.Observation.CODE), o.getText(Tags.Observation.SUBJECT) ?: "", o.ints(Tags.Observation.ARG)) },
                )
            },
            decision = r.records(Tags.Eval.DECISION).firstOrNull()?.let { d ->
                Decision(
                    d.i(Tags.Decision.STATE), d.i(Tags.Decision.ACTION), d.i(Tags.Decision.CONFIDENCE), d.i(Tags.Decision.CATEGORY),
                    d.l(Tags.Decision.COOLDOWN_MS), d.l(Tags.Decision.PARAM), d.l(Tags.Decision.HIGH_IMPACT) == 1L,
                )
            },
        )
    }
}

// ------------------------------------------------------------------ platform TLS

/**
 * TLS observation through the platform's validated TLS stack (Android Conscrypt /
 * JDK JSSE). Certificate validation is never disabled; failures are reported.
 */
class TlsProber(
    private val factory: SSLSocketFactory,
    private val connect: (host: String, port: Int, timeoutMs: Int) -> Socket,
    private val extraHostnameCheck: ((host: String, session: SSLSession) -> Boolean)? = null,
) {
    fun probe(host: String, port: Int, timeoutMs: Int): TlsResult {
        val start = System.nanoTime()
        fun result(status: Int, version: String = "", alpn: String = "", cipher: String = "") =
            TlsResult(host, port, status, (System.nanoTime() - start) / 1000, version, alpn, cipher)
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        try {
            raw = connect(host, port, timeoutMs)
            raw.soTimeout = timeoutMs
            ssl = factory.createSocket(raw, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            params.applicationProtocols = arrayOf("h2", "http/1.1")
            val allowed = ssl.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }
            if (allowed.isEmpty()) return result(TlsStatus.UNSUPPORTED)
            params.protocols = allowed.toTypedArray()
            ssl.sslParameters = params
            ssl.startHandshake()
            val session = ssl.session
            if (extraHostnameCheck != null && !extraHostnameCheck.invoke(host, session)) return result(TlsStatus.CERTIFICATE)
            return result(TlsStatus.OK, session.protocol ?: "", ssl.applicationProtocol ?: "", session.cipherSuite ?: "")
        } catch (e: SSLPeerUnverifiedException) {
            return result(TlsStatus.CERTIFICATE)
        } catch (e: SSLHandshakeException) {
            return result(if (isCertificateProblem(e)) TlsStatus.CERTIFICATE else TlsStatus.HANDSHAKE)
        } catch (e: SocketTimeoutException) {
            return result(TlsStatus.TIMEOUT)
        } catch (e: IOException) {
            return result(if (isCertificateProblem(e)) TlsStatus.CERTIFICATE else TlsStatus.IO)
        } catch (e: RuntimeException) {
            return result(TlsStatus.IO)
        } finally {
            try { ssl?.close() ?: raw?.close() } catch (_: IOException) { }
        }
    }

    private fun isCertificateProblem(e: Throwable): Boolean {
        var c: Throwable? = e
        var depth = 0
        while (c != null && depth++ < 8) {
            if (c is CertificateException || c is CertPathValidatorException || c is SSLPeerUnverifiedException) return true
            c = c.cause
        }
        return false
    }
}

// ------------------------------------------------------------------ session

/** Encrypted-DNS protocol identifiers (mirror of probe::ENC_* in Native/Core.rs). */
object EncProtocol {
    const val UNKNOWN = 0
    const val DOH = 1 // DNS over HTTPS, HTTP/2 (RFC 8484)
    const val DOH3 = 2 // DNS over HTTPS, HTTP/3 over QUIC (RFC 8484 + RFC 9114)
    const val DOT = 3 // DNS over TLS (RFC 7858)
    const val DOQ = 4 // DNS over dedicated QUIC (RFC 9250)
}

/** Result of one HTTPS exchange performed by the platform's own TLS/QUIC stack. */
data class DohResponse(val transport: Int, val rttUs: Long, val protocol: Int, val body: ByteArray?)

/**
 * Platform transport for RFC 8484 DoH: POST application/dns-message over the platform's
 * HTTPS client (HTTP/3 where the platform offers it, HTTP/2 otherwise). Certificate
 * validation is the platform's and is never relaxed.
 */
fun interface DohClient {
    fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse
}

data class EncryptedResult(val endpoint: String, val name: String, val protocol: Int, val transport: Int, val rttUs: Long, val status: Int = 0)

object Doh {
    const val MAX_ENDPOINTS = 4

    /** Only absolute https:// URLs are accepted: DoH is never sent in clear text. */
    fun validEndpoint(url: String): Boolean =
        url.length <= 256 && url.startsWith("https://") && runCatching { java.net.URI(url).host?.isNotEmpty() == true }.getOrDefault(false)

    /** RFC 8484 query bytes built by the native DNS codec (ID 0). */
    fun query(name: String, qtype: Int = 1): ByteArray? {
        val r = Wire.decode(Native.dohQuery(Wire.encode(Record().text(Tags.DohQuery.NAME, name).int(Tags.DohQuery.QTYPE, qtype))) ?: return null)
        return if (r.status?.toInt() == Codes.OK) r.getBytes(Tags.DohQuery.QUERY) else null
    }
}

data class ProcessInfo(
    val pid: Long, val name: String, val established: Int, val synSent: Int, val listen: Int,
    val closeWait: Int, val udp: Int, val remotes: Int, val sample: List<String>,
)

data class SystemSnapshot(
    val status: Int, val total: Int, val established: Int, val listen: Int, val synSent: Int, val timeWait: Int,
    val closeWait: Int, val udp: Int, val exposed: Int, val processes: List<ProcessInfo>, val findings: List<Observation>,
) {
    companion object {
        /** Machine-wide connections per process (Windows user mode; other platforms: UNSUPPORTED). */
        fun capture(): SystemSnapshot {
            val r = Wire.decode(Native.systemConnections() ?: throw WireException("null result"))
            fun i(rec: Record, tag: Int) = (rec.getInt(tag) ?: 0L).toInt()
            return SystemSnapshot(
                status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
                total = i(r, Tags.Sysnet.TOTAL), established = i(r, Tags.Sysnet.ESTABLISHED), listen = i(r, Tags.Sysnet.LISTEN),
                synSent = i(r, Tags.Sysnet.SYN_SENT), timeWait = i(r, Tags.Sysnet.TIME_WAIT), closeWait = i(r, Tags.Sysnet.CLOSE_WAIT),
                udp = i(r, Tags.Sysnet.UDP), exposed = i(r, Tags.Sysnet.EXPOSED),
                processes = r.records(Tags.Sysnet.PROCESS).map { p ->
                    ProcessInfo(
                        p.getInt(Tags.Process.PID) ?: 0, p.getText(Tags.Process.NAME) ?: "", i(p, Tags.Process.ESTABLISHED),
                        i(p, Tags.Process.SYN_SENT), i(p, Tags.Process.LISTEN), i(p, Tags.Process.CLOSE_WAIT), i(p, Tags.Process.UDP),
                        i(p, Tags.Process.REMOTES), p.texts(Tags.Process.SAMPLE),
                    )
                },
                findings = r.records(Tags.Sysnet.FINDING).map { f ->
                    Observation(i(f, Tags.Finding.CODE), f.getText(Tags.Finding.SUBJECT) ?: "", f.ints(Tags.Finding.ARG))
                },
            )
        }
    }
}

data class Report(val run: RunResult, val evaluation: Evaluation?, val tls: List<TlsResult>, val encrypted: List<EncryptedResult> = emptyList())

/** Owns one native engine handle; all calls are thread-safe and the handle is never reused. */
class DiagnosticSession(val config: EngineConfig = EngineConfig()) : AutoCloseable {
    private val handle: Long
    @Volatile private var closed = false

    init {
        Native.loadError?.let { throw NativeException(Codes.JNI, "Yerel kütüphane yüklenemedi: ${it.message}") }
        val api = Native.apiVersion()
        if (api != Native.EXPECTED_API) throw NativeException(Codes.UNSUPPORTED, "Yerel API sürümü uyumsuz: $api")
        handle = Native.create(Wire.encode(config.toRecord()))
        if (handle <= 0) throw NativeException(handle.toInt(), "Motor oluşturulamadı (${Text.code(handle.toInt())})")
    }

    private fun live(): Long {
        check(!closed) { "session closed" }
        return handle
    }

    fun setEnvironment(env: EnvironmentInfo): Int = Native.setEnvironment(live(), Wire.encode(env.toRecord()))

    fun diagnose(targets: List<String>, alternateDns: List<String>): RunResult {
        val req = Record()
        targets.forEach { req.text(Tags.Request.TARGET, it) }
        alternateDns.forEach { req.text(Tags.Request.ALT_DNS, it) }
        return Decode.run(Native.diagnose(live(), Wire.encode(req)))
    }

    fun submitTls(results: List<TlsResult>): Int {
        val r = Record()
        results.forEach { r.record(Tags.TlsSubmit.RESULT, it.toRecord()) }
        return Native.submitTls(live(), Wire.encode(r))
    }

    fun evaluate(): Evaluation = Decode.evaluation(Native.evaluate(live()))
    fun networkChanged(): Int = Native.networkChanged(live())
    fun markApplied(action: Int): Int = Native.markApplied(live(), action)

    /** Full pipeline: native probes → platform TLS on reachable targets → evaluation. */
    /** Measures user-authorized encrypted resolvers and submits them for validation. */
    fun measureEncrypted(run: RunResult, endpoints: List<String>, client: DohClient): List<EncryptedResult> {
        val name = run.targets.firstOrNull { !it.literal }?.host ?: return emptyList()
        val query = Doh.query(name) ?: return emptyList()
        val results = ArrayList<EncryptedResult>()
        val submission = Record()
        for (url in endpoints.filter(Doh::validEndpoint).distinct().take(Doh.MAX_ENDPOINTS)) {
            val r = client.post(url, query, config.timeoutMs)
            val rec = Record().text(Tags.Enc.ENDPOINT, url).int(Tags.Enc.PROTOCOL, r.protocol).int(Tags.Enc.TRANSPORT, r.transport)
                .int(Tags.Enc.RTT_US, r.rttUs).text(Tags.Enc.QUERY_NAME, name).int(Tags.Enc.QTYPE, 1)
            r.body?.let { rec.bytes(Tags.Enc.RESPONSE, it) }
            submission.record(Tags.EncSubmit.RESULT, rec)
            results += EncryptedResult(url, name, r.protocol, r.transport, r.rttUs)
        }
        if (results.isNotEmpty()) Native.submitEncrypted(live(), Wire.encode(submission))
        return results
    }

    fun run(targets: List<String>, alternateDns: List<String>, tls: TlsProber?, doh: DohClient? = null, dohEndpoints: List<String> = emptyList()): Report {
        val run = diagnose(targets, alternateDns)
        if (run.status != Codes.OK) return Report(run, null, emptyList())
        val tlsResults = if (tls == null) emptyList() else run.targets.filter { it.tcpOk }.map { tls.probe(it.host, it.port, config.timeoutMs) }
        if (tlsResults.isNotEmpty()) submitTls(tlsResults)
        // The native run record predates the TLS probes; merge them so the report shows one view.
        val merged = run.copy(
            targets = run.targets.map { t ->
                tlsResults.firstOrNull { it.host == t.host && it.port == t.port }?.let {
                    t.copy(tlsStatus = it.status, tlsUs = it.handshakeUs, tlsVersion = it.version, tlsAlpn = it.alpn, tlsCipher = it.cipher)
                } ?: t
            },
        )
        val encrypted = if (doh != null && dohEndpoints.isNotEmpty()) measureEncrypted(run, dohEndpoints, doh) else emptyList()
        val evaluation = evaluate()
        // Status of each encrypted resolver as validated natively (parser verdict), for display.
        return Report(merged, evaluation, tlsResults, encrypted)
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            Native.destroy(handle)
        }
    }
}

// ------------------------------------------------------------------ text (Turkish UI catalogue)

object Text {
    fun code(c: Int): String = when (c) {
        Codes.OK -> "tamam"
        Codes.INVALID_ARGUMENT -> "geçersiz girdi"
        Codes.INVALID_HANDLE -> "geçersiz motor tanıtıcısı"
        Codes.WIRE -> "veri biçimi hatası"
        Codes.BUSY -> "başka bir tanılama sürüyor"
        Codes.LIMIT -> "sınır aşıldı"
        Codes.PANIC -> "yerel motor iç hatası (yakalandı)"
        Codes.NO_ENVIRONMENT -> "ağ ortamı bilgisi yok"
        Codes.NO_DATA -> "veri yok (ağ değişmiş olabilir; tekrar tanılayın)"
        Codes.UNSUPPORTED -> "bu platformda desteklenmiyor"
        Codes.JNI -> "JNI hatası"
        Codes.INTERNAL -> "iç hata"
        else -> "kod $c"
    }

    fun status(s: Int): String = when (s) {
        0 -> "çalışmadı"; 1 -> "başarılı"; 2 -> "zaman aşımı"; 3 -> "reddedildi"; 4 -> "erişilemez"
        5 -> "hata"; 6 -> "geçersiz yanıt"; 7 -> "kayıt yok"; 8 -> "alan adı yok"; 9 -> "sunucu hatası"
        10 -> "desteklenmiyor"; 11 -> "atlandı"; 12 -> "yerel MTU sınırı"; 13 -> "platform izin vermedi"; else -> "durum $s"
    }

    fun tls(s: Int): String = when (s) {
        TlsStatus.NOT_RUN -> "çalışmadı"; TlsStatus.OK -> "başarılı"; TlsStatus.CERTIFICATE -> "sertifika doğrulanamadı"
        TlsStatus.HANDSHAKE -> "el sıkışma başarısız"; TlsStatus.TIMEOUT -> "zaman aşımı"; TlsStatus.IO -> "bağlantı kesildi"
        TlsStatus.UNSUPPORTED -> "desteklenmiyor"; else -> "durum $s"
    }

    fun category(c: Int): String = when (c) {
        0 -> "—"
        1 -> "DNS çözümleme hatası"
        2 -> "DNS zaman aşımı"
        3 -> "IPv4 bağlantı hatası"
        4 -> "IPv6 bağlantı hatası"
        5 -> "TCP bağlantı hatası"
        6 -> "UDP erişilebilirlik sorunu"
        7 -> "TLS anlaşma hatası"
        8 -> "Sertifika doğrulama hatası"
        9 -> "QUIC uyumsuzluğu"
        10 -> "HTTP/3 uyumsuzluğu"
        11 -> "MTU kaynaklı bağlantı sorunu"
        12 -> "Captive portal (ağ giriş sayfası)"
        13 -> "Yerel ağ kesintisi"
        14 -> "Uzak servis hatası"
        15 -> "Yetersiz kanıt"
        16 -> "Sorun tespit edilmedi"
        17 -> "Bilgilendirme"
        else -> "Kategori $c"
    }

    fun state(s: Int): String = when (s) {
        0 -> "Kararlı"
        1 -> "Ön gözlem — tekrar doğrulanması bekleniyor"
        2 -> "Öneri"
        3 -> "Bekleme süresi (gereksiz değişikliği önlemek için)"
        4 -> "Daha fazla kanıt gerekli"
        5 -> "Uygulanan değişiklik doğrulanıyor"
        6 -> "Değişiklik doğrulandı"
        7 -> "Değişiklik iyileştirme sağlamadı"
        else -> "Durum $s"
    }

    fun actionTitle(a: Int): String = when (a) {
        0 -> "Mevcut yapılandırmayı koru"
        1 -> "IPv4'ü tercih et"
        2 -> "IPv6'yı tercih et"
        3 -> "Alternatif (şifreli) DNS kullan"
        4 -> "TCP (HTTP/2) yoluna güven"
        5 -> "MTU değerini düşür"
        6 -> "Ağ giriş sayfasını aç"
        7 -> "Bekle ve tekrar dene"
        8 -> "Daha fazla ölçüm topla"
        9 -> "Saat ve ağ aracını kontrol et"
        10 -> "Servis sağlayıcı / ağ yöneticisiyle iletişime geç"
        11 -> "Son değişikliği geri al"
        12 -> "Yerel bağlantıyı kontrol et"
        13 -> "Hedef adını kontrol et"
        else -> "Eylem $a"
    }

    fun actionDetail(a: Int, param: Long): String = when (a) {
        0 -> "İşlem gerekmiyor."
        1 -> "IPv6 yolu çalışmıyor, IPv4 çalışıyor. Modem/yönlendirici IPv6 ayarlarını kontrol edin; gerekirse ağ bağdaştırıcısında IPv4'ü önceliklendirin (yönetici izni gerekir)."
        2 -> "IPv4 yolu çalışmıyor, IPv6 çalışıyor. Modem/yönlendirici IPv4 (NAT/DHCP) ayarlarını kontrol edin."
        3 -> "Sistem DNS'i sorunlu görünüyor. Güvendiğiniz bir şifreli DNS hizmetini kendiniz seçip ayarlayabilirsiniz (Android: Ayarlar › Ağ › Özel DNS; Windows: Ayarlar › Ağ › DNS sunucusu ataması › Şifreli DNS). THE DPI sistem DNS'ini sessizce değiştirmez. Gizlilik notu: seçtiğiniz DNS sağlayıcısı sorgularınızı görür."
        4 -> "UDP/443 (QUIC) yolu yanıt vermiyor; uygulamalar normalde HTTP/2 (TCP) ile otomatik devam eder. Sorun yaşarsanız tarayıcıda QUIC/HTTP3'ü kapatabilirsiniz."
        5 -> "Ölçülen yol MTU'su ${param} bayt. Büyük paketler yolda düşüyor olabilir; bağdaştırıcı MTU değerini bu değere düşürmeyi değerlendirin (yönetici izni gerekir)."
        6 -> "Ağ bir giriş sayfası (captive portal) istiyor. Tarayıcıda giriş yapın; ardından tekrar tanılayın."
        7 -> "TLS anlaşması geçici olarak başarısız oldu. Bir süre sonra tekrar deneyin; sorun sürerse ağ yöneticisine bildirin."
        8 -> "Güvenilir bir sonuç için yeterli ölçüm yok. Tanılamayı tekrar çalıştırın veya başka bir test hedefi ekleyin."
        9 -> "Sertifika doğrulanamadı. Cihaz tarih/saatini, araya giren proxy veya güvenlik yazılımını ve captive portal olasılığını kontrol edin. Sertifika doğrulaması asla devre dışı bırakılmaz."
        10 -> "Sorun bu hedefe özgü görünüyor (diğer hedefler çalışıyor). Hizmet sağlayıcısıyla veya ağ yöneticisiyle iletişime geçin."
        11 -> "Uygulanan değişiklik (${actionTitle(param.toInt())}) bağlantıyı iyileştirmedi. Önceki ayara geri dönün."
        12 -> "Wi-Fi/kablo/mobil veri bağlantısını ve modemi kontrol edin."
        13 -> "Alan adı DNS'te bulunamadı (NXDOMAIN) ve diğer adlar çözülüyor: büyük olasılıkla yazım hatası veya kaldırılmış bir ad. DNS ayarlarını değiştirmek bu sorunu çözmez."
        else -> ""
    }

    fun observation(o: Observation): String {
        val s = o.subject
        fun a(i: Int) = o.args.getOrNull(i)?.toString() ?: "?"
        return when (o.code) {
            1 -> "Aktif ağ bağlantısı yok"
            2 -> "Platform captive portal bildirdi"
            3 -> "Platform internet erişimini doğrulamadı ($s)"
            4 -> "DNS sunucusu $s yanıt vermedi (${a(0)} sorgu, ${a(1)} yanıt)"
            5 -> "DNS sunucusu $s: %${a(0)} paket kaybı"
            6 -> "DNS sunucusu $s UDP'de yanıtsız, TCP'de yanıt veriyor"
            7 -> "$s: alan adı bulunamadı (NXDOMAIN) — yazım hatası olabilir"
            8 -> "$s: DNS sunucu hatası (RCODE ${a(0)})"
            9 -> "$s: DNS zaman aşımı"
            10 -> "$s: IPv4 TCP bağlantısı başarısız (${a(0)} deneme)"
            11 -> "$s: IPv6 TCP bağlantısı başarısız (${a(0)} deneme)"
            12 -> "$s: IPv4 TCP başarılı (${a(0)} ms)"
            13 -> "$s: IPv6 TCP başarılı (${a(0)} ms)"
            14 -> "$s: tüm TCP denemeleri başarısız (${a(0)} deneme)"
            15 -> "$s: TLS sertifikası doğrulanamadı"
            16 -> "$s: TLS anlaşması başarısız"
            17 -> "$s: TLS başarılı"
            18 -> "$s: DNS HTTPS kaydı HTTP/3 (h3) ilan ediyor"
            19 -> "$s: QUIC sürüm anlaşması yanıtı alınamadı (UDP)"
            20 -> "$s: QUIC v1 destekleniyor"
            21 -> "$s: sunucu QUIC v1 listelemiyor"
            22 -> "$s: yol MTU ${a(0)} bayt, beklenen ${a(1)} bayt"
            23 -> "$s: ECH yapılandırması DNS'te yayımlanmış"
            24 -> "$s: cihazda genel IPv6 adresi yok (IPv6 denemesi beklenen şekilde başarısız)"
            25 -> "$s: yüksek gecikme (${a(0)} ms)"
            26 -> "Windows 10 (build ${a(0)}): standart Microsoft desteği 14 Ekim 2025'te sona erdi; güvenlik güncellemeleri için Windows 11'e geçiş veya ESU önerilir"
            27 -> "Diğer hedeflere bağlantı başarılı (${a(0)} hedef)"
            28 -> "Test hedefi belirtilmedi"
            29 -> "$s: DNS sunucusu sorguyu reddetti (REFUSED)"
            30 -> "Ölçülü (kotalı) bağlantı"
            31 -> "DNS sunucusu $s: yüksek jitter (${a(0)} ms)"
            32 -> "Kullanıcı tanımlı DNS $s daha iyi ölçüldü (${a(0)} ms; sistem: ${a(1)} ms)"
            33 -> "$s: adres kaydı yok"
            34 -> "$s: sağlıklı (${a(0)} ms)"
            35 -> "Sonuç çıkarmak için yeterli ölçüm yok"
            36 -> "Arka plan veri kısıtlaması (Veri Tasarrufu) etkin"
            37 -> "Özel DNS (DNS over TLS) etkin${if (s.isNotEmpty()) ": $s" else ""}"
            38 -> "Sistem DNS sunucusu bilgisi alınamadı"
            40 -> "Şifreli DNS ${Text.encProtocol(o.args.getOrNull(1)?.toInt() ?: 0)} ($s) yanıtladı (${a(0)} ms)"
            41 -> "Şifreli DNS kullanılabilir: ${Text.encProtocol(o.args.getOrNull(1)?.toInt() ?: 0)} $s ${a(0)} ms (sistem DNS: ${a(2)} ms). Gizlilik için sistemde şifreli DNS'i etkinleştirmeyi değerlendirin"
            42 -> "Şifreli DNS $s yanıt vermedi (${status(o.args.getOrNull(0)?.toInt() ?: 5)}); uç nokta veya ağ politikası olabilir"
            43 -> "$s: sistem DNS'i alan adı yok diyor, bağımsız şifreli DNS (${Text.encProtocol(o.args.getOrNull(0)?.toInt() ?: 0)}) çözüyor — çözümleyici düzeyinde tutarsızlık"
            44 -> "$s: şifreli DNS de alan adının olmadığını doğruluyor"
            39 -> "$s: işletim sistemi bağlantıya izin vermedi (Android 17+: yerel ağ adresleri ACCESS_LOCAL_NETWORK izni gerektirir; THE DPI bu izni istemez). Bu bir ağ arızası değildir."
            else -> "Gözlem ${o.code} $s ${o.args}"
        }
    }

    const val KNOWN_OBSERVATIONS = 44

    fun encProtocol(p: Int): String = when (p) {
        EncProtocol.DOH -> "DoH (HTTP/2)"
        EncProtocol.DOH3 -> "DoH3 (HTTP/3)"
        EncProtocol.DOT -> "DoT"
        EncProtocol.DOQ -> "DoQ"
        else -> "şifreli DNS"
    }
    const val KNOWN_CATEGORIES = 17
    const val KNOWN_ACTIONS = 13

    private fun ms(us: Long) = "${us / 1000} ms"

    fun networkType(t: Int) = when (t) {
        NetworkType.WIFI -> "Wi-Fi"; NetworkType.CELLULAR -> "Mobil veri"; NetworkType.ETHERNET -> "Ethernet"
        NetworkType.VPN -> "VPN/tünel"; NetworkType.OTHER -> "Diğer"; else -> "Bilinmiyor"
    }

    private fun tri(v: Int) = when (v) { YES -> "evet"; NO -> "hayır"; else -> "bilinmiyor" }

    fun systemFinding(o: Observation): String {
        fun a(i: Int) = o.args.getOrNull(i)?.toString() ?: "?"
        return when (o.code) {
            1 -> "${o.subject} (PID ${a(1)}): ${a(0)} bağlantı el sıkışmada takılı (SYN_SENT) — uzak uç erişilemez veya yol filtreleniyor olabilir"
            2 -> "${o.subject} (PID ${a(1)}): ${a(0)} bağlantı kapatılmayı bekliyor (CLOSE_WAIT) — uygulama soketleri kapatmıyor olabilir"
            3 -> "Sistemde ${a(0)} TIME_WAIT bağlantısı: kısa ömürlü bağlantı yoğunluğu, kaynak port tükenmesi riski"
            4 -> "${a(0)} servis tüm arayüzlerde dinliyor (0.0.0.0/::): güvenlik duvarı izin verirse ağdan erişilebilir"
            5 -> "Etkin TCP bağlantısı yok"
            else -> "Bulgu ${o.code} ${o.subject} ${o.args}"
        }
    }

    const val KNOWN_SYSTEM_FINDINGS = 5

    fun system(s: SystemSnapshot): String = buildString {
        if (s.status != Codes.OK) {
            appendLine("Sistem geneli bağlantı görünümü: ${code(s.status)}")
            return@buildString
        }
        appendLine("SİSTEM GENELİ BAĞLANTILAR (yalnızca bu cihazda gösterilir, kaydedilmez)")
        appendLine("  Toplam ${s.total} · kurulu ${s.established} · dinleyen ${s.listen} · el sıkışmada ${s.synSent} · TIME_WAIT ${s.timeWait} · CLOSE_WAIT ${s.closeWait} · UDP ${s.udp}")
        if (s.findings.isNotEmpty()) {
            appendLine()
            appendLine("BULGULAR")
            s.findings.forEach { appendLine("  • ${systemFinding(it)}") }
        }
        appendLine()
        appendLine("İŞLEMLER (en fazla 64)")
        for (p in s.processes) {
            val parts = buildList {
                if (p.established > 0) add("kurulu ${p.established}")
                if (p.synSent > 0) add("el sıkışmada ${p.synSent}")
                if (p.listen > 0) add("dinleyen ${p.listen}")
                if (p.closeWait > 0) add("CLOSE_WAIT ${p.closeWait}")
                if (p.udp > 0) add("UDP ${p.udp}")
                if (p.remotes > 0) add("uzak uç ${p.remotes}")
            }
            appendLine("  ${p.name} (PID ${p.pid}): ${parts.joinToString(", ")}")
            if (p.sample.isNotEmpty()) appendLine("      → ${p.sample.joinToString(", ")}")
        }
    }

    fun environment(e: EnvironmentInfo): String = buildString {
        appendLine("ORTAM")
        appendLine("  Sistem      : ${e.osName} ${e.osVersion}${if (e.osBuild > 0) " (build ${e.osBuild})" else ""} · ${e.arch}")
        appendLine("  Ağ          : ${networkType(e.networkType)} · ${e.interfaceName.ifEmpty { "?" }} · bağlı: ${tri(e.connected)}")
        appendLine("  DNS         : ${e.dnsServers.ifEmpty { listOf("?") }.joinToString(", ")}")
        appendLine("  Ağ geçidi   : ${e.gateways.ifEmpty { listOf("?") }.joinToString(", ")}")
        appendLine("  MTU         : ${if (e.mtu > 0) e.mtu else "?"} · IPv4: ${tri(e.hasIpv4)} · IPv6: ${tri(e.hasIpv6)}")
        appendLine("  Captive     : ${tri(e.captive)} · doğrulanmış: ${tri(e.validated)} · ölçülü: ${tri(e.metered)}")
    }

    fun report(r: Report): String = buildString {
        val run = r.run
        if (run.status != Codes.OK) {
            appendLine("Tanılama yapılamadı: ${code(run.status)}${run.invalid?.let { " — '$it'" } ?: ""}")
            return@buildString
        }
        appendLine("ÖLÇÜMLER (${run.durationUs / 1000} ms)")
        for (s in run.resolvers) {
            appendLine("  DNS ${s.server}${if (s.alternate) " [kullanıcı tanımlı]" else ""}: ${s.received}/${s.sent} yanıt, ort. ${ms(s.avgUs)}, jitter ${ms(s.jitterUs)}${if (s.tcpStatus != 0) ", TCP: ${status(s.tcpStatus)}" else ""}")
        }
        for (t in run.targets) {
            appendLine("  ${t.host}:${t.port}")
            if (!t.literal) appendLine("    DNS   : ${status(t.dnsStatus)} ${ms(t.dnsUs)}${if (t.dnsViaTcp) " (TCP)" else ""} → ${t.addresses.take(4).joinToString(", ").ifEmpty { "—" }}")
            if (t.httpsRecord) appendLine("    HTTPS : ALPN ${t.alpn.joinToString(",")}${if (t.ech) ", ECH yayımlanmış" else ""}")
            if (t.tcp4Attempts > 0) appendLine("    TCP4  : ${status(t.tcp4Status)} ${t.tcp4Ok}/${t.tcp4Attempts}, medyan ${ms(t.tcp4Us)}")
            if (t.tcp6Attempts > 0) appendLine("    TCP6  : ${status(t.tcp6Status)} ${t.tcp6Ok}/${t.tcp6Attempts}, medyan ${ms(t.tcp6Us)}")
            if (t.tlsStatus != 0) appendLine("    TLS   : ${tls(t.tlsStatus)} ${ms(t.tlsUs)} ${t.tlsVersion} ${t.tlsAlpn} ${t.tlsCipher}".trimEnd())
            if (t.quicStatus != 11) appendLine("    QUIC  : ${status(t.quicStatus)}${if (t.quicVersions.isNotEmpty()) " sürümler " + t.quicVersions.joinToString(",") { "0x" + it.toString(16) } else ""}")
            if (t.mtuStatus == 1) appendLine("    MTU   : yol ${t.pathMtu}/${t.mtuCeiling} bayt (${t.mtuProbes} prob)")
        }
        if (r.encrypted.isNotEmpty()) {
            appendLine("  Şifreli DNS (sorgu: ${r.encrypted.first().name})")
            for (x in r.encrypted) {
                appendLine("    ${x.endpoint}: ${encProtocol(x.protocol)}, aktarım ${status(x.transport)}, ${ms(x.rttUs)}")
            }
        }
        val e = r.evaluation ?: return@buildString
        appendLine()
        val stability = if (e.evaluations >= 2) ", kararlılık ${e.stability}/1000" else ""
        appendLine("TEŞHİS (puan ${e.score}/1000, ortalama ${e.ewma}$stability)")
        for (d in e.diagnoses) {
            appendLine("  • ${category(d.category)} — güven %${d.confidence}")
            d.observations.forEach { appendLine("      - ${observation(it)}") }
        }
        e.decision?.let { d ->
            appendLine()
            appendLine("KARAR: ${state(d.state)}")
            appendLine("  ${actionTitle(d.action)}${if (d.highImpact) " (sistem ayarı — yalnızca sizin onayınızla)" else ""}")
            actionDetail(d.action, d.param).takeIf { it.isNotEmpty() }?.let { appendLine("  $it") }
            if ((d.state == 1 || d.state == 3) && d.param > 0) {
                appendLine("  Değerlendirilen öneri: ${actionTitle(d.param.toInt())} (tek ölçümle sistem değişikliği önerilmez)")
            }
            if (d.cooldownMs > 0) appendLine("  Yeni değişiklik önerisi için kalan süre: ${d.cooldownMs / 1000} sn")
        }
    }
}

// ==================================================================================
// WINDOWS PLATFORM SECTION
// ==================================================================================

/** Windows platform services: native IP Helper detection and the Windows certificate store. */
object WindowsPlatform {
    /**
     * TLS trust anchors from the Windows certificate store via the JDK SunMSCAPI provider
     * ("Windows-ROOT"). Falls back to the JDK trust store when unavailable (non-Windows test host).
     */
    val trustContext: Pair<SSLContext, String> by lazy {
        try {
            val ks = KeyStore.getInstance("Windows-ROOT")
            ks.load(null, null)
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(ks)
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, tmf.trustManagers, null)
            ctx to "Windows sertifika deposu"
        } catch (e: Exception) {
            SSLContext.getDefault() to "JDK güven deposu"
        }
    }

    val trust: Pair<SSLSocketFactory, String> get() = trustContext.first.socketFactory to trustContext.second

    fun dohClient(): DohClient = JdkDohClient(trustContext.first)

    fun prober(): TlsProber = TlsProber(trust.first, { host, port, timeout ->
        Socket().apply { connect(InetSocketAddress(host, port), timeout) }
    })

    /** Native detection (GetAdaptersAddresses + registry); JDK fallback keeps unknowns unknown. */
    fun environment(dnsOverride: List<String> = emptyList()): EnvironmentInfo {
        val rec = Native.detectEnvironment()?.let { runCatching { Wire.decode(it) }.getOrNull() }
        var env = rec?.let { EnvironmentInfo.fromRecord(it) } ?: EnvironmentInfo()
        if (rec?.status?.toInt() != Codes.OK) env = jdkFallback(env)
        if (env.osVersion.isEmpty()) env = env.copy(osVersion = System.getProperty("os.version") ?: "")
        if (dnsOverride.isNotEmpty()) env = env.copy(dnsServers = dnsOverride)
        return env
    }

    private fun jdkFallback(base: EnvironmentInfo): EnvironmentInfo {
        val candidates = runCatching {
            NetworkInterface.networkInterfaces().toList().filter { it.isUp && !it.isLoopback && !it.isVirtual }
        }.getOrDefault(emptyList())
        val ni = candidates.firstOrNull { n -> n.inetAddresses.toList().any { !it.isLinkLocalAddress } }
            ?: return base.copy(osName = System.getProperty("os.name") ?: base.osName)
        val addrs = ni.inetAddresses.toList()
        return base.copy(
            osName = System.getProperty("os.name") ?: base.osName,
            interfaceName = ni.name,
            mtu = runCatching { ni.mtu }.getOrDefault(0),
            hasIpv4 = if (addrs.any { it is Inet4Address && !it.isLinkLocalAddress }) YES else NO,
            hasIpv6 = if (addrs.any { it is Inet6Address && !it.isLinkLocalAddress && !it.isSiteLocalAddress && (it.address[0].toInt() and 0xE0) == 0x20 }) YES else NO,
        )
    }
}

private fun splitList(s: String): List<String> =
    s.split('\n', ',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }

/**
 * RFC 8484 DoH over the JDK HTTP client with the Windows trust store. HTTP/3 is requested
 * when the running JDK provides it (JEP 517); the protocol actually negotiated is reported,
 * so DoH3 is never claimed when HTTP/2 was used. Redirects are refused (a DoH endpoint
 * that redirects is treated as a failure, never followed into a login page).
 */
class JdkDohClient(private val ssl: SSLContext) : DohClient {
    private val client: HttpClient by lazy {
        HttpClient.newBuilder()
            .sslContext(ssl)
            .version(PREFERRED)
            .followRedirects(HttpClient.Redirect.NEVER)
            .proxy(ProxySelector.getDefault())
            .connectTimeout(Duration.ofSeconds(5))
            .build()
    }

    override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
        val attempted = if (PREFERRED.name == "HTTP_3") EncProtocol.DOH3 else EncProtocol.DOH
        val start = System.nanoTime()
        fun rtt() = (System.nanoTime() - start) / 1000
        return try {
            val req = HttpRequest.newBuilder(URI(url))
                .timeout(Duration.ofMillis(timeoutMs.toLong()))
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build()
            val resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray())
            val proto = if (resp.version().name == "HTTP_3") EncProtocol.DOH3 else EncProtocol.DOH
            val type = resp.headers().firstValue("content-type").orElse("")
            if (resp.statusCode() == 200 && type.startsWith("application/dns-message")) {
                val b = resp.body()
                DohResponse(1, rtt(), proto, if (b.size > Wire.MAX_BYTES) b.copyOf(Wire.MAX_BYTES) else b)
            } else {
                DohResponse(6, rtt(), proto, null) // not a DNS answer (e.g. login page or error)
            }
        } catch (e: HttpTimeoutException) {
            DohResponse(2, rtt(), attempted, null)
        } catch (e: ConnectException) {
            DohResponse(4, rtt(), attempted, null)
        } catch (e: IOException) {
            DohResponse(5, rtt(), attempted, null)
        } catch (e: IllegalArgumentException) {
            DohResponse(6, rtt(), attempted, null)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            DohResponse(5, rtt(), attempted, null)
        }
    }

    companion object {
        /** HTTP/3 when the running JDK supports it, otherwise HTTP/2 (feature detection, no reflection on internals). */
        val PREFERRED: HttpClient.Version =
            runCatching { HttpClient.Version.valueOf("HTTP_3") }.getOrDefault(HttpClient.Version.HTTP_2)
    }
}

/** Headless mode: `TheDPI --cli example.com [--dns 1.1.1.1] [--alt 9.9.9.9]`. */
fun runCli(args: List<String>): Int {
    val targets = ArrayList<String>()
    val dns = ArrayList<String>()
    val alt = ArrayList<String>()
    val doh = ArrayList<String>()
    var system = false
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--cli" -> {}
            "--dns" -> dns += args.getOrNull(++i) ?: ""
            "--alt" -> alt += args.getOrNull(++i) ?: ""
            "--doh" -> doh += args.getOrNull(++i) ?: ""
            "--system" -> system = true
            else -> targets += args[i]
        }
        i++
    }
    return try {
        DiagnosticSession().use { session ->
            val env = WindowsPlatform.environment(dns.filter { it.isNotEmpty() })
            session.setEnvironment(env)
            println("THE DPI ${Native.engineVersion()} · TLS güveni: ${WindowsPlatform.trust.second}")
            print(Text.environment(env))
            println()
            val report = session.run(
                targets, alt.filter { it.isNotEmpty() }, WindowsPlatform.prober(),
                WindowsPlatform.dohClient(), doh.filter { it.isNotEmpty() },
            )
            print(Text.report(report))
            if (system) {
                println()
                print(Text.system(SystemSnapshot.capture()))
            }
            0
        }
    } catch (e: NativeException) {
        System.err.println(e.message)
        2
    }
}

class MainWindow {
    private val frame = JFrame("THE DPI")
    private val targets = JTextArea("example.com", 3, 40)
    private val altDns = JTextField(30)
    private val dohEndpoints = JTextField(30).apply {
        toolTipText = "Örnek: https://dns.example/dns-query — yalnızca https:// adresleri; DoH3 (HTTP/3) desteklenirse kullanılır"
    }
    private val runButton = JButton("Tanıla")
    private val systemButton = JButton("Sistem geneli bağlantılar")
    private val appliedButton = JButton("Öneriyi uyguladım — doğrula").apply { isEnabled = false }
    private val auto = JCheckBox("Ağ değişince yeniden tanıla", false)
    private val output = JTextArea().apply {
        isEditable = false
        font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        lineWrap = true
        wrapStyleWord = true
    }
    private val status = JLabel(" ")
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "thedpi-worker").apply { isDaemon = true } }
    private val busy = AtomicBoolean(false)
    private var session: DiagnosticSession? = null
    @Volatile private var lastEnv: EnvironmentInfo? = null
    @Volatile private var lastDecision: Decision? = null
    private val watcher = Timer(15_000) { worker.execute { checkNetwork() } }

    fun show() {
        val form = JPanel(GridBagLayout())
        form.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        val c = GridBagConstraints().apply { insets = Insets(3, 3, 3, 3); anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL }
        fun row(y: Int, label: String, comp: java.awt.Component) {
            c.gridx = 0; c.gridy = y; c.weightx = 0.0; form.add(JLabel(label), c)
            c.gridx = 1; c.weightx = 1.0; form.add(comp, c)
        }
        val disclosure = JLabel(
            "<html>Tanılama yalnızca yazdığınız test hedeflerine ve sistem DNS sunucularınıza düşük hacimli " +
                "bağlantılar kurar. Veriler cihazda kalır, kaydedilmez; sistem ayarları değiştirilmez.</html>",
        )
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2; form.add(disclosure, c); c.gridwidth = 1
        row(1, "Test hedefleri:", JScrollPane(targets))
        row(2, "Karşılaştırılacak DNS (isteğe bağlı):", altDns)
        row(3, "Şifreli DNS — DoH3/DoH adresleri (isteğe bağlı):", dohEndpoints)
        val buttons = JPanel().apply { add(runButton); add(systemButton); add(appliedButton); add(auto) }
        c.gridx = 0; c.gridy = 4; c.gridwidth = 2; form.add(buttons, c)

        frame.layout = BorderLayout()
        frame.add(form, BorderLayout.NORTH)
        frame.add(JScrollPane(output), BorderLayout.CENTER)
        frame.add(status.apply { border = BorderFactory.createEmptyBorder(4, 8, 4, 8) }, BorderLayout.SOUTH)
        frame.defaultCloseOperation = WindowConstants.DISPOSE_ON_CLOSE
        frame.addWindowListener(object : WindowAdapter() {
            override fun windowClosed(e: WindowEvent) = shutdown()
        })
        frame.minimumSize = Dimension(640, 520)
        frame.setLocationRelativeTo(null)

        runButton.addActionListener { startRun(verifyRuns = 0) }
        appliedButton.addActionListener { applied() }
        systemButton.addActionListener { showSystem() }

        try {
            session = DiagnosticSession()
            status.text = "Motor ${Native.engineVersion()} hazır · TLS güveni: ${WindowsPlatform.trust.second}"
            watcher.start()
        } catch (e: NativeException) {
            runButton.isEnabled = false
            output.text = "Yerel motor başlatılamadı: ${e.message}"
        }
        frame.isVisible = true
    }

    private fun ui(block: () -> Unit) = SwingUtilities.invokeLater(block)

    private fun startRun(verifyRuns: Int) {
        val s = session ?: return
        if (!busy.compareAndSet(false, true)) return
        val targetList = splitList(targets.text)
        val altList = splitList(altDns.text)
        val dohList = splitList(dohEndpoints.text)
        runButton.isEnabled = false
        appliedButton.isEnabled = false
        status.text = "Tanılanıyor…"
        worker.execute {
            try {
                var remaining = verifyRuns + 1
                var text = ""
                while (remaining-- > 0) {
                    val env = refreshEnvironment(s)
                    val report = s.run(targetList, altList, WindowsPlatform.prober(), WindowsPlatform.dohClient(), dohList)
                    lastDecision = report.evaluation?.decision
                    text = Text.environment(env) + "\n" + Text.report(report)
                }
                ui {
                    output.text = text
                    output.caretPosition = 0
                    val d = lastDecision
                    appliedButton.isEnabled = d != null && d.state == 2 && d.action !in setOf(0, 8)
                    status.text = "Tamamlandı"
                }
            } catch (e: Exception) {
                ui { status.text = "Hata: ${e.message}" }
            } finally {
                busy.set(false)
                ui { runButton.isEnabled = true }
            }
        }
    }

    /** Machine-wide connections per process (user mode, IP Helper; nothing is stored). */
    private fun showSystem() {
        systemButton.isEnabled = false
        status.text = "Sistem bağlantıları okunuyor…"
        worker.execute {
            val text = try {
                Text.system(SystemSnapshot.capture())
            } catch (e: Exception) {
                "Sistem bağlantıları okunamadı: ${e.message}"
            }
            ui {
                output.text = text
                output.caretPosition = 0
                status.text = "Sistem geneli görünüm güncellendi"
                systemButton.isEnabled = true
            }
        }
    }

    /** User reports applying the recommendation; the engine verifies it over two evaluations. */
    private fun applied() {
        val s = session ?: return
        val d = lastDecision ?: return
        worker.execute {
            val rc = s.markApplied(d.action)
            ui {
                if (rc == Codes.OK) {
                    status.text = "Doğrulama başlatıldı: iki ölçüm yapılacak"
                    startRun(verifyRuns = 1)
                } else {
                    status.text = "Doğrulama başlatılamadı: ${Text.code(rc)}"
                }
            }
        }
    }

    private fun refreshEnvironment(s: DiagnosticSession): EnvironmentInfo {
        val env = WindowsPlatform.environment()
        val prev = lastEnv
        if (prev != null && prev.fingerprint() != env.fingerprint()) s.networkChanged()
        lastEnv = env
        s.setEnvironment(env)
        return env
    }

    private fun checkNetwork() {
        val s = session ?: return
        val prev = lastEnv ?: return
        if (busy.get()) return
        val env = WindowsPlatform.environment()
        if (prev.fingerprint() == env.fingerprint()) return
        s.networkChanged()
        lastEnv = env
        s.setEnvironment(env)
        ui {
            status.text = "Ağ değişti (${Text.networkType(env.networkType)} · ${env.interfaceName}); önceki sonuçlar geçersiz."
            appliedButton.isEnabled = false
            if (auto.isSelected) startRun(verifyRuns = 0)
        }
    }

    private fun shutdown() {
        watcher.stop()
        worker.shutdownNow()
        runCatching { worker.awaitTermination(2, TimeUnit.SECONDS) }
        session?.close()
        session = null
    }
}

fun main(args: Array<String>) {
    if (args.isNotEmpty()) exitProcess(runCli(args.toList()))
    runCatching { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()) }
    SwingUtilities.invokeLater { MainWindow().show() }
}
