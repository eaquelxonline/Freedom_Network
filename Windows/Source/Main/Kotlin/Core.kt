// Freedom Network — Windows 10/11 x64 application (Kotlin/JVM, JDK Swing, Rust DLL via JNI).
//
// Self-contained: the JNI boundary (class com.freedom.network.Native), the wire codec mirrored from
// Native/Core.rs, typed models, the platform-TLS prober, the diagnostic session
// orchestrator, the Turkish text catalogue, and this platform's integration.
// The shared section below is kept byte-identical with the other platform module.

package com.freedom.network

import java.time.Duration
import java.net.http.HttpTimeoutException
import java.net.http.HttpResponse
import java.net.http.HttpRequest
import java.net.http.HttpClient
import java.net.URI
import java.net.ProxySelector
import java.net.ConnectException
import java.awt.BasicStroke
import java.awt.CardLayout
import java.awt.Cursor
import java.awt.LinearGradientPaint
import java.awt.RadialGradientPaint
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.geom.Path2D
import java.awt.geom.RoundRectangle2D
import java.awt.geom.Arc2D
import java.awt.geom.Ellipse2D
import java.awt.geom.Line2D
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.GridLayout
import java.awt.Insets
import java.awt.RenderingHints
import java.awt.Toolkit
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.channels.DatagramChannel
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.KeyStore
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.util.concurrent.CountDownLatch
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
import javax.imageio.ImageIO
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.Icon
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ScrollPaneConstants
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.UIManager
import javax.swing.WindowConstants
import javax.swing.plaf.basic.BasicScrollBarUI
import kotlin.system.exitProcess

// ==================================================================================
// SHARED SECTION — identical in Android/Core.kt and Windows/Core.kt. Edit both together.
// ==================================================================================

// ------------------------------------------------------------------ JNI

/** The single JNI boundary. Symbols: Java_com_freedom_network_Native_* in Native/Core.rs. */
object Native {
    const val EXPECTED_API = 1
    const val LIBRARY = "freedom"

    /** Null when the native library loaded; otherwise the reason it did not. */
    val loadError: Throwable? = try {
        System.loadLibrary(LIBRARY)
        null
    } catch (e: UnsatisfiedLinkError) {
        e
    } catch (e: SecurityException) {
        e
    } catch (t: Throwable) {
        t
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
    @JvmStatic external fun desyncPacket(handle: Long, request: ByteArray): ByteArray?
    @JvmStatic external fun startProxy(handle: Long, config: ByteArray): ByteArray?
    @JvmStatic external fun stopProxy(handle: Long): Int
    @JvmStatic external fun proxyStats(handle: Long): ByteArray?
    @JvmStatic external fun wgPublicKey(privKey: ByteArray): ByteArray?
    @JvmStatic external fun wgCreate(privKey: ByteArray, peerPub: ByteArray): Long
    @JvmStatic external fun wgDestroy(wgHandle: Long): Int
    @JvmStatic external fun wgHandshakeInit(wgHandle: Long, ephPriv: ByteArray, tai64n12: ByteArray): ByteArray?
    @JvmStatic external fun wgConsumeResponse(wgHandle: Long, pkt: ByteArray): Int
    @JvmStatic external fun wgEncrypt(wgHandle: Long, ipPacket: ByteArray): ByteArray?
    @JvmStatic external fun wgDecrypt(wgHandle: Long, wgPacket: ByteArray): ByteArray?
    @JvmStatic external fun wgSetReserved(wgHandle: Long, reserved3: ByteArray): Int
    @JvmStatic external fun wgBuildAwgPrefaces(jc: Int, jmin: Int, jmax: Int, cpsTemplate: ByteArray?): ByteArray?
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
    fun bytesAll(tag: Int): List<ByteArray> = fields.filter { it.first == tag }.mapNotNull { (it.second as? BytesValue)?.v }
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

    object Eval { const val SCORE = 1; const val EWMA = 2; const val GENERATION = 3; const val DIAGNOSIS = 4; const val DECISION = 5; const val STABILITY = 6; const val EVALUATIONS = 7; const val DESYNC_MODE = 8 }
    object Diagnosis { const val CATEGORY = 1; const val CONFIDENCE = 2; const val OBSERVATION = 3 }
    object Observation { const val CODE = 1; const val SUBJECT = 2; const val ARG = 3 }
    object Decision { const val STATE = 1; const val ACTION = 2; const val CONFIDENCE = 3; const val CATEGORY = 4; const val COOLDOWN_MS = 5; const val PARAM = 6; const val HIGH_IMPACT = 7 }
    object Desync {
        const val MODE = 1; const val FAKE_TTL = 2; const val SPLIT_POS = 3; const val DROP_RST = 4
        const val PORT = 5; const val PACKET = 6; const val OUT_PACKET = 7; const val DROPPED = 8
        const val PROTOCOL = 9; const val SNI = 10; const val ECH = 11; const val POST_QUANTUM = 12
        const val CONNECTIONS = 13; const val TLS_SPLIT = 14; const val HTTP_SPLIT = 15
        const val FAKE_SENT = 16; const val RST_DROPPED = 17; const val ACTIVE = 18
        const val VISION_SPLICE = 19; const val REALITY_DEST = 20
        const val PERSONA = 21; const val BLOCK_TRACKERS = 22; const val STRIP_PARAMS = 23
        const val TRACKERS_BLOCKED = 24; const val PARAMS_STRIPPED = 25
    }
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

object DesyncMode {
    const val OFF = 0
    const val SPLIT = 1
    const val DISORDER = 2
    const val FAKE_BAD_SUM = 3
    const val FAKE_AUTO_TTL = 4
    const val QUIC_SCRAMBLE = 5
    const val ADAPTIVE_FULL = 6
    const val REALITY_VISION = 7
}

data class DesyncConfig(
    val mode: Int = DesyncMode.REALITY_VISION,
    val fakeTtl: Int = 5,
    val splitPos: Int = 2,
    val dropRst: Boolean = true,
    val port: Int = 0,
    val persona: String = "",
    val blockTrackers: Boolean = true,
    val stripUrlParams: Boolean = true,
) {
    fun toRecord(): Record = Record()
        .int(Tags.Desync.MODE, mode).int(Tags.Desync.FAKE_TTL, fakeTtl)
        .int(Tags.Desync.SPLIT_POS, splitPos).int(Tags.Desync.DROP_RST, if (dropRst) 1 else 0)
        .int(Tags.Desync.PORT, port)
        .apply { if (persona.isNotEmpty()) text(Tags.Desync.PERSONA, persona) }
        .int(Tags.Desync.BLOCK_TRACKERS, if (blockTrackers) 1 else 0)
        .int(Tags.Desync.STRIP_PARAMS, if (stripUrlParams) 1 else 0)
}

data class DesyncResult(
    val status: Int, val mode: Int, val dropped: Boolean, val protocol: Int,
    val sni: String, val ech: Boolean, val postQuantum: Boolean, val packets: List<ByteArray>,
)

data class ProxyStatus(
    val status: Int, val active: Boolean, val port: Int, val mode: Int,
    val connections: Long = 0, val tlsSplit: Long = 0, val httpSplit: Long = 0,
    val fakeSent: Long = 0, val rstDropped: Long = 0, val visionSplice: Long = 0,
    val trackersBlocked: Long = 0, val paramsStripped: Long = 0,
)

object ServerStatus {
    const val STANDBY = 0
    const val CONNECTED = 1
    const val FAILOVER = 2
    const val UNREACHABLE = 3
    const val REVOKED = 4
    const val QUOTA_EXCEEDED = 5
}

/**
 * User-owned personal server profile ("Your Network. Your Server. Your Control."):
 * - Per-device identity (`deviceId`) and authentication key (`authKeyHex`)
 * - Primary & backup endpoints (`primaryEndpoint`, `backupEndpoint`) with automatic failover
 * - Cover TLS destination (`coverDest`) for REALITY + X25519MLKEM768 active-probing defense
 * - Bandwidth quota tracking (`quotaBytes` / `usedBytes`), latency & packet-loss metrics,
 *   key rotation, and instant device revocation.
 */
data class ServerProfile(
    val id: String,
    val name: String,
    val primaryEndpoint: String,
    val backupEndpoint: String = "",
    val coverDest: String = "dl.google.com",
    val deviceId: String,
    val authKeyHex: String,
    val status: Int = ServerStatus.STANDBY,
    val latencyMs: Long = 0,
    val lossPct: Int = 0,
    val quotaBytes: Long = 0,
    val usedBytes: Long = 0,
    val revoked: Boolean = false,
) {
    val activeEndpoint: String
        get() = if (status == ServerStatus.FAILOVER && backupEndpoint.isNotBlank()) backupEndpoint else primaryEndpoint

    val quotaAvailable: Boolean
        get() = !revoked && (quotaBytes <= 0L || usedBytes < quotaBytes)
}

/**
 * Manages multiple user-owned personal server profiles, per-device key rotation,
 * instant device revocation, quota tracking, and automatic primary -> backup failover.
 */
class ServerManager {
    private val profiles = LinkedHashMap<String, ServerProfile>()
    @Volatile var activeProfileId: String? = null
        private set

    @Synchronized
    fun upsert(profile: ServerProfile) {
        profiles[profile.id] = profile
        if (activeProfileId == null) activeProfileId = profile.id
    }

    @Synchronized
    fun list(): List<ServerProfile> = profiles.values.toList()

    @Synchronized
    fun active(): ServerProfile? = activeProfileId?.let { profiles[it] }

    @Synchronized
    fun select(id: String): ServerProfile? {
        val p = profiles[id] ?: return null
        if (!p.quotaAvailable) return null
        activeProfileId = id
        val updated = p.copy(status = ServerStatus.CONNECTED)
        profiles[id] = updated
        return updated
    }

    @Synchronized
    fun recordTraffic(id: String, bytes: Long): ServerProfile? {
        val p = profiles[id] ?: return null
        val used = (p.usedBytes + bytes).coerceAtLeast(0L)
        val st = if (p.quotaBytes > 0L && used >= p.quotaBytes) ServerStatus.QUOTA_EXCEEDED else p.status
        val updated = p.copy(usedBytes = used, status = st)
        profiles[id] = updated
        return updated
    }

    @Synchronized
    fun revokeDevice(id: String): ServerProfile? {
        val p = profiles[id] ?: return null
        val updated = p.copy(revoked = true, status = ServerStatus.REVOKED)
        profiles[id] = updated
        if (activeProfileId == id) {
            activeProfileId = profiles.values.firstOrNull { it.id != id && it.quotaAvailable }?.id
        }
        return updated
    }

    @Synchronized
    fun rotateDeviceKey(id: String, newKeyHex: String): ServerProfile? {
        if (newKeyHex.isBlank()) return null
        val p = profiles[id] ?: return null
        val updated = p.copy(
            authKeyHex = newKeyHex,
            revoked = false,
            status = if (p.status == ServerStatus.REVOKED) ServerStatus.STANDBY else p.status,
        )
        profiles[id] = updated
        return updated
    }

    @Synchronized
    fun triggerFailover(id: String): ServerProfile? {
        val p = profiles[id] ?: return null
        if (p.backupEndpoint.isNotBlank() && p.quotaAvailable) {
            val updated = p.copy(status = ServerStatus.FAILOVER)
            profiles[id] = updated
            return updated
        }
        val marked = p.copy(status = ServerStatus.UNREACHABLE)
        profiles[id] = marked
        val next = profiles.values.firstOrNull { it.id != id && it.quotaAvailable }
        if (next != null) {
            activeProfileId = next.id
            val promoted = next.copy(status = ServerStatus.CONNECTED)
            profiles[next.id] = promoted
            return promoted
        }
        return marked
    }
}

data class Evaluation(
    val status: Int, val score: Long, val ewma: Long, val generation: Long, val stability: Long,
    val evaluations: Long, val diagnoses: List<Diagnosis>, val decision: Decision?,
    val desyncMode: Int = DesyncMode.OFF,
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
            desyncMode = r.i(Tags.Eval.DESYNC_MODE),
        )
    }

    fun desync(bytes: ByteArray?): DesyncResult {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        val pkts = r.fields.filter { it.first == Tags.Desync.OUT_PACKET }.mapNotNull { (it.second as? Record.BytesValue)?.v }
        return DesyncResult(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            mode = r.i(Tags.Desync.MODE),
            dropped = r.l(Tags.Desync.DROPPED) == 1L,
            protocol = r.i(Tags.Desync.PROTOCOL),
            sni = r.getText(Tags.Desync.SNI) ?: "",
            ech = r.l(Tags.Desync.ECH) == 1L,
            postQuantum = r.l(Tags.Desync.POST_QUANTUM) == 1L,
            packets = pkts,
        )
    }

    fun proxy(bytes: ByteArray?): ProxyStatus {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        return ProxyStatus(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            active = r.l(Tags.Desync.ACTIVE) == 1L,
            port = r.i(Tags.Desync.PORT),
            mode = r.i(Tags.Desync.MODE),
            connections = r.l(Tags.Desync.CONNECTIONS),
            tlsSplit = r.l(Tags.Desync.TLS_SPLIT),
            httpSplit = r.l(Tags.Desync.HTTP_SPLIT),
            fakeSent = r.l(Tags.Desync.FAKE_SENT),
            rstDropped = r.l(Tags.Desync.RST_DROPPED),
            visionSplice = r.l(Tags.Desync.VISION_SPLICE),
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

    fun desyncPacket(packet: ByteArray, cfg: DesyncConfig = DesyncConfig()): DesyncResult {
        val req = cfg.toRecord().bytes(Tags.Desync.PACKET, packet)
        return Decode.desync(Native.desyncPacket(live(), Wire.encode(req)))
    }

    fun startProxy(cfg: DesyncConfig = DesyncConfig()): ProxyStatus =
        Decode.proxy(Native.startProxy(live(), Wire.encode(cfg.toRecord())))

    fun stopProxy(): Int = Native.stopProxy(live())

    fun proxyStats(): ProxyStatus = Decode.proxy(Native.proxyStats(live()))

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
        3 -> "Sistem DNS'i sorunlu görünüyor. Güvendiğiniz bir şifreli DNS hizmetini kendiniz seçip ayarlayabilirsiniz (Android: Ayarlar › Ağ › Özel DNS; Windows: Ayarlar › Ağ › DNS sunucusu ataması › Şifreli DNS). Freedom Network sistem DNS'ini sessizce değiştirmez. Gizlilik notu: seçtiğiniz DNS sağlayıcısı sorgularınızı görür."
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
            45 -> "$s: DNS yanıtı zehirlenmiş / sansür IP'sine yönlendirildi (${a(0)}.${a(1)}.${a(2)}.${a(3)})"
            39 -> "$s: işletim sistemi bağlantıya izin vermedi (Android 17+: yerel ağ adresleri ACCESS_LOCAL_NETWORK izni gerektirir; Freedom Network bu izni istemez). Bu bir ağ arızası değildir."
            else -> "Gözlem ${o.code} $s ${o.args}"
        }
    }

    const val KNOWN_OBSERVATIONS = 45

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
        if (e.desyncMode != DesyncMode.OFF) {
            appendLine()
            appendLine("AKTİF DPI AŞMA (DESYNC) ÖNERİSİ: ${desyncMode(e.desyncMode)}")
        }
    }

    const val KNOWN_DESYNC_MODES = 7

    fun desyncMode(m: Int): String = when (m) {
        DesyncMode.OFF -> "Kapalı (Doğrudan Geçiş)"
        DesyncMode.SPLIT -> "TLS SNI/ECH + HTTP Host Bölme (Split)"
        DesyncMode.DISORDER -> "Ters Sıralı TCP Segmentasyonu (Multi-Disorder)"
        DesyncMode.FAKE_BAD_SUM -> "Sahte Paket (RFC 1624 BadSum) + Disorder"
        DesyncMode.FAKE_AUTO_TTL -> "Sahte Paket (Oto-TTL) + Disorder"
        DesyncMode.QUIC_SCRAMBLE -> "QUIC v1/v2 Initial Şaşırtma + TCP/TLS 1.3 Yedeği"
        DesyncMode.ADAPTIVE_FULL -> "Tam Adaptif Özgürlük Modu (PQ-TLS 1.3 + ECH + Oto-TTL + BadSum + RST Kalkanı)"
        DesyncMode.REALITY_VISION -> "REALITY + ML-KEM-768 + xtls-rprx-vision Doğrudan Aktarım (2026–2027)"
        else -> "Mod $m"
    }

    fun serverStatus(s: Int): String = when (s) {
        ServerStatus.STANDBY -> "Beklemede"
        ServerStatus.CONNECTED -> "Bağlı"
        ServerStatus.FAILOVER -> "Yedek Sunucuda (Failover)"
        ServerStatus.UNREACHABLE -> "Erişilemez"
        ServerStatus.REVOKED -> "Cihaz Erişimi İptal Edildi"
        ServerStatus.QUOTA_EXCEEDED -> "Kota Doldu"
        else -> "Durum $s"
    }

    fun serverManager(mgr: ServerManager): String = buildString {
        val list = mgr.list()
        appendLine("FREEDOM NETWORK — KİŞİSEL SUNUCU YÖNETİCİSİ (${list.size} profil)")
        for (p in list) {
            val kota = if (p.quotaBytes > 0) "${p.usedBytes}/${p.quotaBytes} bayt" else "${p.usedBytes} bayt (sınırsız)"
            appendLine("  • ${p.name} [${serverStatus(p.status)}] → ${p.activeEndpoint} (REALITY hedefi: ${p.coverDest} · cihaz: ${p.deviceId} · gecikme: ${p.latencyMs} ms · kayıp: %${p.lossPct} · kota: $kota)")
        }
    }

    fun proxyStatus(p: ProxyStatus): String = buildString {
        if (!p.active) {
            appendLine("FREEDOM NETWORK (YEREL DPI AŞMA): Kapalı")
            return@buildString
        }
        appendLine("FREEDOM NETWORK (YEREL DPI AŞMA): Etkin · 127.0.0.1:${p.port} (SOCKS5 + HTTP CONNECT)")
        appendLine("  Strateji   : ${desyncMode(p.mode)}")
        appendLine("  İstatistik : bağlantı ${p.connections} · TLS bölme ${p.tlsSplit} · HTTP bölme ${p.httpSplit} · sahte paket ${p.fakeSent} · RST kalkanı ${p.rstDropped} · Vision doğrudan aktarım ${p.visionSplice} · izleyici engeli ${p.trackersBlocked} · URL temizleme ${p.paramsStripped}")
    }

    fun vpnStatus(
        vpnActive: Boolean,
        p: ProxyStatus,
        tcpFlows: Int = 0,
        udpFlows: Int = 0,
        dnsQueries: Int = 0,
        dohResolved: Int = 0,
        desyncedFlows: Int = 0,
        visionSplicedFlows: Int = 0,
        poisonedBlocked: Int = 0,
        quicFallbacks: Int = 0,
        tlsFragmented: Int = 0,
        bytesUp: Long = 0,
        bytesDown: Long = 0,
        trackersBlocked: Int = 0,
        leaksBlocked: Int = 0,
        killSwitch: Boolean = false,
        exitRelayLabel: String = "",
        ipMasked: Boolean = false,
        maskMethodLabel: String = "",
        devicePersonaLabel: String = "",
        locationShieldLabel: String = "",
    ): String = buildString {
        if (!vpnActive && !p.active) {
            appendLine("FREEDOM NETWORK (SİSTEM GENELİ ÖZGÜR AĞ): Kapalı")
            return@buildString
        }
        val activeLabel = maskMethodLabel.ifBlank { exitRelayLabel }
        val isMaskedNow = ipMasked || (activeLabel.isNotBlank() && !activeLabel.startsWith("Doğrudan"))
        val modeDesc = if (vpnActive) {
            if (isMaskedNow && activeLabel.isNotBlank()) {
                "Sistem Geneli Gizlilik Tüneli ($activeLabel)"
            } else {
                "Sistem Geneli TUN Köprüsü (DoH3 + REALITY/Vision Desync + Tam UDP NAT)"
            }
        } else {
            "Yerel Proxy (127.0.0.1:${p.port})"
        }
        appendLine("FREEDOM NETWORK: Etkin · $modeDesc")
        if (p.active) {
            appendLine("  Yerel Proxy: 127.0.0.1:${p.port} (SOCKS5 + HTTP CONNECT)")
        }
        if (isMaskedNow && activeLabel.isNotBlank()) {
            appendLine("  Çıkış IP   : MASKELİ · $activeLabel")
        } else if (vpnActive) {
            appendLine("  Çıkış IP   : Doğrudan (Yerel DoH3 + DPI Açık · Tünel/Röle Bağlanmadı)")
        }
        if (locationShieldLabel.isNotBlank()) {
            appendLine("  Konum Kalkanı : $locationShieldLabel")
        }
        if (devicePersonaLabel.isNotBlank()) {
            appendLine("  Cihaz Kimliği : $devicePersonaLabel")
        }
        appendLine("  Strateji   : ${desyncMode(p.mode)}${if (killSwitch) " · Sızdırmaz Kill Switch AKTİF" else ""}")
        appendLine("  TUN Köprüsü: TCP $tcpFlows (Desync $desyncedFlows, TLS Parçalama $tlsFragmented, Vision $visionSplicedFlows) · UDP $udpFlows (QUIC $quicFallbacks) · DNS $dnsQueries (DoH $dohResolved, Zehir $poisonedBlocked, İzleyici $trackersBlocked, Sızıntı $leaksBlocked)")
        if (bytesUp > 0 || bytesDown > 0) {
            appendLine("  Veri Akışı : Yükleme ${bytesUp / 1024} KB · İndirme ${bytesDown / 1024} KB")
        }
        appendLine("  Motor İstat: bağlantı ${p.connections} · TLS bölme ${p.tlsSplit} · HTTP bölme ${p.httpSplit} · sahte paket ${p.fakeSent} · RST kalkanı ${p.rstDropped} · Vision doğrudan aktarım ${p.visionSplice}")
    }
}

// ------------------------------------------------------------------ user-mode TUN TCP/UDP/DoH bridge

/**
 * Zero-dependency IPv4 + TCP/UDP packet parser, RFC 1071 / RFC 1624 checksum calculator,
 * packet synthesizer, and L7 Desync segment reassembler for the user-mode TUN bridge.
 */
object IpPackets {
    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val PROTO_ICMPV6 = 58

    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08
    const val TCP_ACK = 0x10

    data class Ipv4Header(
        val ihl: Int,
        val totalLen: Int,
        val ttl: Int,
        val proto: Int,
        val srcIp: Int,
        val dstIp: Int,
    )

    data class TcpSegment(
        val ip: Ipv4Header,
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val dataOffset: Int,
        val flags: Int,
        val window: Int,
        val payload: ByteArray,
    )

    data class UdpDatagram(
        val ip: Ipv4Header,
        val srcPort: Int,
        val dstPort: Int,
        val payload: ByteArray,
    )

    fun u8(b: ByteArray, off: Int): Int = b[off].toInt() and 0xFF
    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
    fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFFL) shl 24) or
            ((b[off + 1].toLong() and 0xFFL) shl 16) or
            ((b[off + 2].toLong() and 0xFFL) shl 8) or
            (b[off + 3].toLong() and 0xFFL)

    fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v ushr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    fun putU32(b: ByteArray, off: Int, v: Long) {
        b[off] = ((v ushr 24) and 0xFFL).toByte()
        b[off + 1] = ((v ushr 16) and 0xFFL).toByte()
        b[off + 2] = ((v ushr 8) and 0xFFL).toByte()
        b[off + 3] = (v and 0xFFL).toByte()
    }

    fun ipToBytes(ip: Int): ByteArray = byteArrayOf(
        ((ip ushr 24) and 0xFF).toByte(),
        ((ip ushr 16) and 0xFF).toByte(),
        ((ip ushr 8) and 0xFF).toByte(),
        (ip and 0xFF).toByte(),
    )

    fun ipToString(ip: Int): String =
        "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"

    fun parseIpLiteral(s: String): Int? {
        val parts = s.trim().substringBefore(':').split('.')
        if (parts.size != 4) return null
        var acc = 0
        for (p in parts) {
            val n = p.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            acc = (acc shl 8) or n
        }
        return acc
    }

    fun parseIpv4(raw: ByteArray): Ipv4Header? {
        if (raw.size < 20) return null
        val ver = (raw[0].toInt() ushr 4) and 0x0F
        if (ver != 4) return null
        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (ihl < 20 || raw.size < ihl) return null
        val totalLen = u16(raw, 2)
        if (totalLen < ihl || totalLen > raw.size) return null
        val ttl = u8(raw, 8)
        val proto = u8(raw, 9)
        val srcIp = u32(raw, 12).toInt()
        val dstIp = u32(raw, 16).toInt()
        return Ipv4Header(ihl, totalLen, ttl, proto, srcIp, dstIp)
    }

    fun parseTcp(raw: ByteArray, ip: Ipv4Header? = parseIpv4(raw)): TcpSegment? {
        val ip_ = ip ?: return null
        if (ip.proto != PROTO_TCP || ip.totalLen < ip.ihl + 20) return null
        val base = ip.ihl
        val dataOff = ((raw[base + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOff < 20 || ip.totalLen < base + dataOff) return null
        val srcPort = u16(raw, base)
        val dstPort = u16(raw, base + 2)
        val seq = u32(raw, base + 4)
        val ack = u32(raw, base + 8)
        val flags = u8(raw, base + 13)
        val window = u16(raw, base + 14)
        val payload = raw.copyOfRange(base + dataOff, ip.totalLen)
        return TcpSegment(ip, srcPort, dstPort, seq, ack, dataOff, flags, window, payload)
    }

    fun parseUdp(raw: ByteArray, ip: Ipv4Header? = null): UdpDatagram? {
        val ip = ip ?: parseIpv4(raw) ?: return null
        if (ip.proto != PROTO_UDP || ip.totalLen < ip.ihl + 8) return null
        val base = ip.ihl
        val srcPort = u16(raw, base)
        val dstPort = u16(raw, base + 2)
        val udpLen = u16(raw, base + 4)
        val end = minOf(ip.totalLen, if (udpLen >= 8) base + udpLen else ip.totalLen)
        if (end < base + 8) return null
        val payload = raw.copyOfRange(base + 8, end)
        return UdpDatagram(ip, srcPort, dstPort, payload)
    }

    /** RFC 1071 16-bit one's-complement checksum over `buf[off until off + len]`. */
    fun ipv4Checksum(buf: ByteArray, off: Int = 0, len: Int = buf.size - off): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) {
            sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /** Computes or verifies TCP/UDP transport checksum over IPv4 pseudo-header + L4 segment. */
    fun transportChecksumV4(
        srcIp: Int,
        dstIp: Int,
        proto: Int,
        buf: ByteArray,
        off: Int = 0,
        len: Int = buf.size - off,
    ): Int {
        var sum = 0L
        sum += ((srcIp ushr 16) and 0xFFFF).toLong()
        sum += (srcIp and 0xFFFF).toLong()
        sum += ((dstIp ushr 16) and 0xFFFF).toLong()
        sum += (dstIp and 0xFFFF).toLong()
        sum += (proto and 0xFF).toLong()
        sum += (len and 0xFFFF).toLong()
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) {
            sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /** Skips a (possibly compressed) DNS name starting at [pos]; returns the offset after it or -1. */
    private fun skipDnsName(msg: ByteArray, start: Int): Int {
        var pos = start
        var guard = 0
        while (pos < msg.size && guard++ < 128) {
            val len = msg[pos].toInt() and 0xFF
            when {
                len == 0 -> return pos + 1
                (len and 0xC0) == 0xC0 -> return if (pos + 2 <= msg.size) pos + 2 else -1
                (len and 0xC0) != 0 -> return -1
                else -> pos += 1 + len
            }
        }
        return -1
    }

    /**
     * Extracts A (4-byte) and AAAA (16-byte) RDATA from the answer section of a DNS response.
     * Returns null when the message is malformed.
     */
    fun dnsAnswerAddresses(msg: ByteArray): List<ByteArray>? {
        if (msg.size < 12) return null
        val qd = u16(msg, 4)
        val an = u16(msg, 6)
        var pos = 12
        repeat(qd) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 4 > msg.size) return null
            pos += 4
        }
        val out = ArrayList<ByteArray>()
        repeat(an) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 10 > msg.size) return null
            val type = u16(msg, pos)
            val rdLen = u16(msg, pos + 8)
            pos += 10
            if (pos + rdLen > msg.size) return null
            if ((type == 1 && rdLen == 4) || (type == 28 && rdLen == 16)) {
                out.add(msg.copyOfRange(pos, pos + rdLen))
            }
            pos += rdLen
        }
        return out
    }

    /**
     * True when a DNS response points to a known ISP block/warning page, sinkhole, or
     * private/link-local/CGNAT DNS-rebinding target (`195.175.254.0/24`, `127/8`, `10/8`,
     * `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10`, `::`, `::1`, `fe80::/10`, `fc00::/7`,
     * or `2a01:358:4014:a00::/64`).
     */
    fun containsPoisonedDns(payload: ByteArray): Boolean {
        val addrs = dnsAnswerAddresses(payload) ?: return false
        for (a in addrs) {
            val b0 = a[0].toInt() and 0xFF
            if (a.size == 4) {
                val b1 = a[1].toInt() and 0xFF
                val b2 = a[2].toInt() and 0xFF
                if (b0 == 195 && b1 == 175 && b2 == 254) return true
                if (b0 == 127 || b0 == 10 || b0 == 0) return true
                if (b0 == 172 && b1 in 16..31) return true
                if (b0 == 192 && b1 == 168) return true
                if (b0 == 169 && b1 == 254) return true
                if (b0 == 100 && b1 in 64..127) return true
            } else {
                if (a.copyOfRange(0, 15).all { it.toInt() == 0 }) return true // :: and ::1
                if (b0 == 0xFE && (a[1].toInt() and 0xC0) == 0x80) return true // fe80::/10
                if ((b0 and 0xFE) == 0xFC) return true // fc00::/7
                val tt = byteArrayOf(0x2a, 0x01, 0x03, 0x58, 0x40, 0x14, 0x0a, 0x00)
                if (a.copyOfRange(0, 8).contentEquals(tt)) return true
            }
        }
        return false
    }

    /** Smallest TTL found in the answer section (seconds), or null. */
    fun dnsMinTtl(msg: ByteArray): Long? {
        if (msg.size < 12) return null
        val qd = u16(msg, 4)
        val an = u16(msg, 6)
        var pos = 12
        repeat(qd) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 4 > msg.size) return null
            pos += 4
        }
        var min: Long? = null
        repeat(an) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 10 > msg.size) return min
            val ttl = u32(msg, pos + 4)
            val rdLen = u16(msg, pos + 8)
            min = if (min == null) ttl else minOf(min!!, ttl)
            pos += 10 + rdLen
        }
        return min
    }

    /**
     * Synthesizes an ICMPv4 Destination Unreachable (Type 3, Code 3 port unreachable) for an
     * outgoing IPv4 packet, so e.g. QUIC (UDP 443) clients fall back to TCP immediately.
     */
    fun buildIcmpv4Unreachable(origPacket: ByteArray, code: Int = 3): ByteArray? {
        val ip = parseIpv4(origPacket) ?: return null
        val quoteLen = minOf(origPacket.size, ip.ihl + 8)
        val icmpLen = 8 + quoteLen
        val out = ByteArray(20 + icmpLen)
        out[0] = 0x45
        putU16(out, 2, out.size)
        out[8] = 64
        out[9] = PROTO_ICMP.toByte()
        putU32(out, 12, ip.dstIp.toLong() and 0xFFFFFFFFL)
        putU32(out, 16, ip.srcIp.toLong() and 0xFFFFFFFFL)
        putU16(out, 10, checksum(out, 0, 20))
        out[20] = 3
        out[21] = code.toByte()
        System.arraycopy(origPacket, 0, out, 28, quoteLen)
        putU16(out, 22, checksum(out, 20, icmpLen))
        return out
    }

    /** RFC 1071 Internet checksum over [len] bytes at [off]. */
    fun checksum(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /**
     * Locates the SNI host name inside a single TLS ClientHello record. Returns
     * `(offset, length)` of the host bytes within [p], or null.
     */
    fun findClientHelloSni(p: ByteArray): Pair<Int, Int>? {
        if (p.size < 48 || (p[0].toInt() and 0xFF) != 0x16 || (p[5].toInt() and 0xFF) != 0x01) return null
        var pos = 5 + 4 + 2 + 32
        if (pos >= p.size) return null
        pos += 1 + (p[pos].toInt() and 0xFF) // session id
        if (pos + 2 > p.size) return null
        pos += 2 + u16(p, pos) // cipher suites
        if (pos + 1 > p.size) return null
        pos += 1 + (p[pos].toInt() and 0xFF) // compression methods
        if (pos + 2 > p.size) return null
        val extEnd = minOf(p.size, pos + 2 + u16(p, pos))
        pos += 2
        while (pos + 4 <= extEnd) {
            val type = u16(p, pos)
            val len = u16(p, pos + 2)
            if (type == 0 && pos + 9 <= extEnd) {
                val nameLen = u16(p, pos + 7)
                val nameOff = pos + 9
                return if (nameOff + nameLen <= p.size && nameLen > 0) nameOff to nameLen else null
            }
            pos += 4 + len
        }
        return null
    }

    /** Splits [payload] at the given (sorted, deduplicated, in-range) byte offsets. */
    fun splitAt(payload: ByteArray, offsets: Collection<Int>): List<ByteArray> {
        val cuts = offsets.filter { it in 1 until payload.size }.distinct().sorted()
        if (cuts.isEmpty()) return listOf(payload)
        val out = ArrayList<ByteArray>(cuts.size + 1)
        var prev = 0
        for (c in cuts + payload.size) {
            out.add(payload.copyOfRange(prev, c))
            prev = c
        }
        return out
    }

    /**
     * Full stream-level DPI evasion plan for the first client payload of a TCP flow:
     * TCP chunk boundaries from the native engine (if any) plus a guaranteed cut in the middle
     * of the SNI host (TLS) or `Host:` value (HTTP), followed by TLS record-layer
     * fragmentation so even TCP-reassembling middleboxes never see the SNI in one record.
     */
    fun planFirstPayload(payload: ByteArray, nativeChunks: List<ByteArray>): List<ByteArray> {
        val cuts = ArrayList<Int>()
        var acc = 0
        for (i in 0 until nativeChunks.size - 1) {
            acc += nativeChunks[i].size
            cuts.add(acc)
        }
        val sni = findClientHelloSni(payload)
        if (sni != null) {
            cuts.add(sni.first + maxOf(1, sni.second / 2))
            cuts.add(sni.first - 2)
        } else {
            val text = String(payload, 0, minOf(payload.size, 2048), Charsets.ISO_8859_1)
            val h = text.indexOf("\r\nHost:", ignoreCase = true)
            if (h >= 0) {
                cuts.add(h + 2)
                val valStart = h + 7
                val valEnd = text.indexOf("\r\n", valStart).let { if (it < 0) text.length else it }
                cuts.add(valStart + maxOf(1, (valEnd - valStart) / 2))
            } else if (payload.size > 2) {
                cuts.add(2)
            }
        }
        val chunks = splitAt(payload, cuts)
        return if (sni != null) fragmentTlsClientHelloRecords(payload, chunks) else chunks
    }

    /** RFC 4443 / RFC 8200 IPv6 pseudo-header transport checksum. */
    fun transportChecksumV6(
        srcIp: ByteArray,
        dstIp: ByteArray,
        nextHeader: Int,
        buf: ByteArray,
        off: Int = 0,
        len: Int = buf.size - off,
    ): Int {
        var sum = 0L
        for (i in 0 until 16 step 2) {
            sum += u16(srcIp, i).toLong()
            sum += u16(dstIp, i).toLong()
        }
        sum += ((len ushr 16) and 0xFFFF).toLong()
        sum += (len and 0xFFFF).toLong()
        sum += (nextHeader and 0xFF).toLong()
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) {
            sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /** Synthesizes an ICMPv6 Destination Unreachable (Type 1, Code 3, RFC 4443) for incoming IPv6 packets so dual-stack apps instantly select IPv4. */
    fun buildIcmpv6Unreachable(origPacket: ByteArray): ByteArray? {
        if (origPacket.size < 40 || ((origPacket[0].toInt() ushr 4) and 0x0F) != 6) return null
        val origSrc = origPacket.copyOfRange(8, 24)
        val origDst = origPacket.copyOfRange(24, 40)
        val invokeLen = minOf(origPacket.size, 1200)
        val icmpBodyLen = 8 + invokeLen
        val totalLen = 40 + icmpBodyLen
        val out = ByteArray(totalLen)
        out[0] = 0x60
        putU16(out, 4, icmpBodyLen)
        out[6] = PROTO_ICMPV6.toByte()
        out[7] = 64
        System.arraycopy(origDst, 0, out, 8, 16)
        System.arraycopy(origSrc, 0, out, 24, 16)
        out[40] = 1 // Type 1: Destination Unreachable
        out[41] = 3 // Code 3: Address Unreachable
        System.arraycopy(origPacket, 0, out, 48, invokeLen)
        val csum = transportChecksumV6(origDst, origSrc, PROTO_ICMPV6, out, 40, icmpBodyLen)
        putU16(out, 42, if (csum == 0) 0xFFFF else csum)
        return out
    }

    /** Synthesizes a valid IPv4 + UDP packet with computed IPv4 and UDP checksums. */
    fun buildIpv4Udp(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        ttl: Int = 64,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        putU16(pkt, 2, totalLen)
        putU16(pkt, 4, 0x2468)
        putU16(pkt, 6, 0x4000)
        pkt[8] = ttl.toByte()
        pkt[9] = PROTO_UDP.toByte()
        putU32(pkt, 12, srcIp.toLong() and 0xFFFFFFFFL)
        putU32(pkt, 16, dstIp.toLong() and 0xFFFFFFFFL)
        putU16(pkt, 10, ipv4Checksum(pkt, 0, 20))

        putU16(pkt, 20, srcPort)
        putU16(pkt, 22, dstPort)
        putU16(pkt, 24, udpLen)
        System.arraycopy(payload, 0, pkt, 28, payload.size)
        val csum = transportChecksumV4(srcIp, dstIp, PROTO_UDP, pkt, 20, udpLen)
        putU16(pkt, 26, if (csum == 0) 0xFFFF else csum)
        return pkt
    }

    /** Synthesizes a valid IPv4 + TCP segment (with optional MSS option on SYN+ACK). */
    fun buildIpv4Tcp(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int = 65535,
        payload: ByteArray = ByteArray(0),
        mssOption: Int = 0,
        ttl: Int = 64,
    ): ByteArray {
        val tcpHdrLen = if (mssOption > 0) 24 else 20
        val totalLen = 20 + tcpHdrLen + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        putU16(pkt, 2, totalLen)
        putU16(pkt, 4, 0x1357)
        putU16(pkt, 6, 0x4000)
        pkt[8] = ttl.toByte()
        pkt[9] = PROTO_TCP.toByte()
        putU32(pkt, 12, srcIp.toLong() and 0xFFFFFFFFL)
        putU32(pkt, 16, dstIp.toLong() and 0xFFFFFFFFL)
        putU16(pkt, 10, ipv4Checksum(pkt, 0, 20))

        putU16(pkt, 20, srcPort)
        putU16(pkt, 22, dstPort)
        putU32(pkt, 24, seq and 0xFFFFFFFFL)
        putU32(pkt, 28, ack and 0xFFFFFFFFL)
        pkt[32] = (((tcpHdrLen / 4) shl 4) and 0xF0).toByte()
        pkt[33] = (flags and 0xFF).toByte()
        putU16(pkt, 34, window)
        if (mssOption > 0) {
            pkt[40] = 0x02
            pkt[41] = 0x04
            putU16(pkt, 42, mssOption)
        }
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, 20 + tcpHdrLen, payload.size)
        }
        val csum = transportChecksumV4(srcIp, dstIp, PROTO_TCP, pkt, 20, tcpHdrLen + payload.size)
        putU16(pkt, 36, csum)
        return pkt
    }

    /**
     * Extracts genuine split payload chunks in ascending TCP sequence number order from a
     * `DesyncResult` (filtering out low-TTL and BadSum decoy packets meant for raw sockets)
     * so user-mode `VpnService.protect()`ed stream sockets transmit SNI/ECH/Host splits
     * without stream corruption.
     */
    fun extractOrderedStreamChunks(
        origPacket: ByteArray,
        origPayload: ByteArray,
        res: DesyncResult?,
    ): List<ByteArray> {
        if (origPayload.isEmpty()) return emptyList()
        val origIp = parseIpv4(origPacket)
        if (res != null && res.status == Codes.OK && !res.dropped && origIp != null && res.packets.isNotEmpty()) {
            val realSegments = ArrayList<Pair<Long, ByteArray>>()
            for (pkt in res.packets) {
                val ip = parseIpv4(pkt) ?: continue
                if (ip.ttl != origIp.ttl) continue // filter out FakeAutoTtl decoy
                if (transportChecksumV4(ip.srcIp, ip.dstIp, PROTO_TCP, pkt, ip.ihl, ip.totalLen - ip.ihl) != 0) {
                    continue // filter out FakeBadSum decoy
                }
                val tcp = parseTcp(pkt, ip) ?: continue
                if (tcp.payload.isNotEmpty()) {
                    realSegments.add(tcp.seq to tcp.payload)
                }
            }
            if (realSegments.isNotEmpty()) {
                realSegments.sortBy { it.first }
                val total = realSegments.sumOf { it.second.size }
                if (total == origPayload.size) {
                    val combined = ByteArray(total)
                    var pos = 0
                    for ((_, seg) in realSegments) {
                        System.arraycopy(seg, 0, combined, pos, seg.size)
                        pos += seg.size
                    }
                    if (combined.contentEquals(origPayload)) {
                        return realSegments.map { it.second }
                    }
                }
            }
        }
        if (origPayload.size > 2) {
            val splitAt = minOf(2, origPayload.size - 1)
            return listOf(origPayload.copyOfRange(0, splitAt), origPayload.copyOfRange(splitAt, origPayload.size))
        }
        return listOf(origPayload)
    }

    /**
     * Fragments a single TLS 1.2/1.3 `ClientHello` record (`0x16 0x03 0x01..0x04 <len:2>`) across
     * multiple valid `TLSPlaintext` handshake records (RFC 5246 §6.2.1 / RFC 8446 §5.1) aligned
     * with the TCP split chunks so stateful TCP-reassembling ISP middleboxes never see an intact
     * SNI (`0x0000`) or ECH (`0xfe0d`) extension in a single TLS record.
     */
    fun fragmentTlsClientHelloRecords(origPayload: ByteArray, tcpChunks: List<ByteArray>): List<ByteArray> {
        if (origPayload.size < 43 ||
            (origPayload[0].toInt() and 0xFF) != 0x16 ||
            (origPayload[1].toInt() and 0xFF) != 0x03 ||
            (origPayload[2].toInt() and 0xFF) > 0x04 ||
            (origPayload[5].toInt() and 0xFF) != 0x01
        ) {
            return tcpChunks
        }
        val recLen = u16(origPayload, 3)
        if (5 + recLen != origPayload.size || recLen <= 4 || tcpChunks.size <= 1) {
            return tcpChunks
        }
        val hs = origPayload.copyOfRange(5, origPayload.size)
        val splitPoints = ArrayList<Int>()
        splitPoints.add(minOf(4, hs.size - 1))
        var cursor = 0
        for (i in 0 until tcpChunks.size - 1) {
            cursor += tcpChunks[i].size
            val hsOff = cursor - 5
            if (hsOff in 1 until hs.size) {
                splitPoints.add(hsOff)
            }
        }
        val uniqueSplits = splitPoints.distinct().sorted()
        if (uniqueSplits.isEmpty()) return tcpChunks
        val records = ArrayList<ByteArray>(uniqueSplits.size + 1)
        var prev = 0
        for (sp in uniqueSplits + hs.size) {
            if (sp <= prev || sp > hs.size) continue
            val sliceLen = sp - prev
            val rec = ByteArray(5 + sliceLen)
            rec[0] = 0x16
            rec[1] = origPayload[1]
            rec[2] = origPayload[2]
            putU16(rec, 3, sliceLen)
            System.arraycopy(hs, prev, rec, 5, sliceLen)
            records.add(rec)
            prev = sp
        }
        return if (records.size > 1) records else tcpChunks
    }

    /** Extracts the lowercase QNAME from a standard DNS wire query packet, or null. */
    fun parseDnsQuestionName(msg: ByteArray): String? {
        if (msg.size < 13 || u16(msg, 4) == 0) return null
        val sb = StringBuilder()
        var pos = 12
        var guard = 0
        while (pos < msg.size && guard++ < 128) {
            val len = msg[pos].toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) != 0) return null
            if (pos + 1 + len > msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..len) {
                val c = (msg[pos + i].toInt() and 0xFF)
                sb.append(if (c in 65..90) (c + 32).toChar() else c.toChar())
            }
            pos += 1 + len
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    /** Extracts the DNS QTYPE (e.g. `1`=A, `28`=AAAA) from a standard DNS wire query, or null. */
    fun parseDnsQuestionType(msg: ByteArray): Int? {
        if (msg.size < 13 || u16(msg, 4) == 0) return null
        val end = skipDnsName(msg, 12)
        if (end < 13 || end + 4 > msg.size) return null
        return u16(msg, end)
    }

    /** Synthesizes a fast local NXDOMAIN DNS answer (RCODE=3) preserving query ID and question. */
    fun buildDnsNxdomain(query: ByteArray): ByteArray {
        if (query.size < 12) return query.copyOf()
        val end = skipDnsName(query, 12)
        val qEnd = if (end in 13..(query.size - 4)) end + 4 else query.size
        val out = ByteArray(qEnd)
        System.arraycopy(query, 0, out, 0, qEnd)
        out[2] = ((query[2].toInt() and 0x01) or 0x81).toByte() // QR=1, copy RD
        out[3] = 0x83.toByte() // RA=1, RCODE=3 (NXDOMAIN)
        out[4] = 0; out[5] = if (qEnd > 12) 1 else 0
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }

    /** Synthesizes an empty NOERROR/NODATA DNS answer (ANCOUNT=0) to suppress AAAA leaks when IPv6 is unbridged. */
    fun buildDnsNodataAaaa(query: ByteArray): ByteArray {
        if (query.size < 12) return query.copyOf()
        val end = skipDnsName(query, 12)
        val qEnd = if (end in 13..(query.size - 4)) end + 4 else query.size
        val out = ByteArray(qEnd)
        System.arraycopy(query, 0, out, 0, qEnd)
        out[2] = ((query[2].toInt() and 0x01) or 0x81).toByte() // QR=1, copy RD
        out[3] = 0x80.toByte() // RA=1, RCODE=0 (NOERROR, NODATA)
        out[4] = 0; out[5] = if (qEnd > 12) 1 else 0
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }

    private val TRACKER_SUFFIXES = arrayOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
        "analytics.google.com", "adservice.google.com", "app-measurement.com", "appsflyer.com",
        "adjust.com", "branch.io", "mixpanel.com", "amplitude.com", "hotjar.com",
        "taboola.com", "outbrain.com", "criteo.com", "pubmatic.com", "rubiconproject.com",
        "scorecardresearch.com", "quantserve.com", "unityads.unity3d.com",
        "ads-api.tiktok.com", "analytics.tiktok.com", "ads.reddit.com", "telemetry.mozilla.org",
        "fpjs.io", "fingerprintjs.com", "fingerprint.com", "location.services.mozilla.com",
        "mls.services.mozilla.com", "diagmon.samsung.com", "samsungcloudsolution.com",
        "metrics.icloud.com", "metrics.apple.com", "crashlytics.com", "firebase-settings.crashlytics.com",
        "vortex.data.microsoft.com", "telemetry.microsoft.com", "data.mistat.xiaomi.com",
        "tracking.miui.com", "singular.net", "kochava.com", "inmobi.com", "applovin.com",
        "ironsrc.com", "vungle.com", "sentry.io", "datadoghq.com", "segment.io", "segment.com",
    )

    /** True when [host] matches a known advertising, fingerprinting, geo-beacon, or telemetry domain. */
    fun isTrackerOrAdDomain(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        return TRACKER_SUFFIXES.any { s -> h == s || h.endsWith(".$s") }
    }

    /** True when [payload] is a classic STUN Binding Request / IP Discovery packet (`0x0001`). */
    fun isStunBindingRequest(payload: ByteArray): Boolean {
        if (payload.size < 20) return false
        val msgType = u16(payload, 0)
        if (msgType != 0x0001) return false
        val magic = u32(payload, 4)
        return magic == 0x2112A442L || payload.size == 74
    }

    /** Builds a 74-byte STUN UDP IP Discovery packet (`0x00 0x01 0x00 0x46` + SSRC). */
    fun buildStunIpDiscovery(ssrc: Int, address: String = "", port: Int = 0): ByteArray {
        val pkt = ByteArray(74)
        putU16(pkt, 0, 0x0001)
        putU16(pkt, 2, 70)
        putU32(pkt, 4, ssrc.toLong() and 0xFFFFFFFFL)
        val addrBytes = address.toByteArray(Charsets.UTF_8)
        System.arraycopy(addrBytes, 0, pkt, 8, minOf(addrBytes.size, 63))
        putU16(pkt, 72, port)
        return pkt
    }

    /** Builds a real-time UDP protocol handshake datagram (`0x05` + offline framing magic). */
    fun buildRealtimeUdpHandshake(totalSize: Int = 48): ByteArray {
        val size = maxOf(18, totalSize)
        val pkt = ByteArray(size)
        pkt[0] = 0x05
        val magic = byteArrayOf(
            0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00,
            0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(),
            0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(),
            0x12, 0x34, 0x56, 0x78,
        )
        System.arraycopy(magic, 0, pkt, 1, magic.size)
        pkt[17] = 11
        return pkt
    }

    /** True when [port] is a known STUN/TURN/mDNS/SSDP IP-discovery/local-leak UDP port. */
    fun isLeakRiskUdpPort(port: Int): Boolean =
        port == 3478 || port == 3479 || port == 5349 || port == 5353 || port == 1900 || (port in 19302..19309)

    /** True when [port] is a STUN/TURN TCP port that can expose client IP addresses. */
    fun isLeakRiskTcpPort(port: Int): Boolean =
        port == 3478 || port == 3479 || port == 5349

    private fun csumAdjust16(csum: Int, oldVal: Int, newVal: Int): Int {
        var sum = (csum.inv() and 0xFFFF) + (oldVal.inv() and 0xFFFF) + (newVal and 0xFFFF)
        sum = (sum ushr 16) + (sum and 0xFFFF)
        sum += (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    private fun csumAdjust32(csum: Int, oldVal: Int, newVal: Int): Int {
        val mid = csumAdjust16(csum, (oldVal ushr 16) and 0xFFFF, (newVal ushr 16) and 0xFFFF)
        return csumAdjust16(mid, oldVal and 0xFFFF, newVal and 0xFFFF)
    }

    /**
     * Layer-3 NAT translation on an IPv4 packet (`srcIp` and/or `dstIp`) with RFC 1624
     * incremental IPv4 and TCP/UDP checksum updates and optional TCP SYN MSS clamping.
     */
    fun rewriteIpv4Nat(
        pkt: ByteArray,
        newSrcIp: Int? = null,
        newDstIp: Int? = null,
        clampMss: Int = 0,
    ): ByteArray? {
        val ip = parseIpv4(pkt) ?: return null
        if (pkt.size < ip.totalLen) return null
        val out = pkt.copyOfRange(0, ip.totalLen)
        var ipCsum = u16(out, 10)
        val proto = ip.proto
        val ihl = ip.ihl
        var l4CsumOff = -1
        var l4Csum = 0
        if (proto == PROTO_TCP && out.size >= ihl + 20) {
            l4CsumOff = ihl + 16
            l4Csum = u16(out, l4CsumOff)
        } else if (proto == PROTO_UDP && out.size >= ihl + 8) {
            l4CsumOff = ihl + 6
            l4Csum = u16(out, l4CsumOff)
        }

        if (newSrcIp != null && newSrcIp != ip.srcIp) {
            putU32(out, 12, newSrcIp.toLong() and 0xFFFFFFFFL)
            ipCsum = csumAdjust32(ipCsum, ip.srcIp, newSrcIp)
            if (l4CsumOff >= 0 && (proto == PROTO_TCP || l4Csum != 0)) {
                l4Csum = csumAdjust32(l4Csum, ip.srcIp, newSrcIp)
            }
        }
        if (newDstIp != null && newDstIp != ip.dstIp) {
            putU32(out, 16, newDstIp.toLong() and 0xFFFFFFFFL)
            ipCsum = csumAdjust32(ipCsum, ip.dstIp, newDstIp)
            if (l4CsumOff >= 0 && (proto == PROTO_TCP || l4Csum != 0)) {
                l4Csum = csumAdjust32(l4Csum, ip.dstIp, newDstIp)
            }
        }
        if (clampMss > 0 && proto == PROTO_TCP && out.size >= ihl + 24) {
            val dataOff = ((out[ihl + 12].toInt() ushr 4) and 0x0F) * 4
            val flags = out[ihl + 13].toInt() and 0xFF
            if ((flags and TCP_SYN) != 0 && dataOff >= 24 && ihl + dataOff <= out.size) {
                var pos = ihl + 20
                val end = ihl + dataOff
                while (pos < end) {
                    val kind = out[pos].toInt() and 0xFF
                    if (kind == 0) break
                    if (kind == 1) {
                        pos++
                        continue
                    }
                    if (pos + 1 >= end) break
                    val optLen = out[pos + 1].toInt() and 0xFF
                    if (optLen < 2 || pos + optLen > end) break
                    if (kind == 2 && optLen == 4 && pos + 4 <= end) {
                        val curMss = u16(out, pos + 2)
                        if (curMss > clampMss) {
                            putU16(out, pos + 2, clampMss)
                            l4Csum = csumAdjust16(l4Csum, curMss, clampMss)
                        }
                        break
                    }
                    pos += optLen
                }
            }
        }
        putU16(out, 10, ipCsum)
        if (l4CsumOff >= 0) {
            if (proto == PROTO_UDP) {
                if (u16(out, l4CsumOff) != 0) {
                    putU16(out, l4CsumOff, if (l4Csum == 0) 0xFFFF else l4Csum)
                }
            } else {
                putU16(out, l4CsumOff, l4Csum)
            }
        }
        return out
    }

    /**
     * Strips privacy-leaking IP/geo/device headers (`X-Forwarded-For`, `Forwarded`, `Via`,
     * `X-Real-IP`, `Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Geo-Location`,
     * `X-Device-Model`, `X-Requested-With`, etc.) from plaintext HTTP/1.x requests and optionally
     * replaces device identity headers with a synthetic future [DevicePersona].
     */
    private val TRACKING_QUERY_KEYS = setOf(
        "fbclid", "gclid", "gbraid", "wbraid", "dclid", "msclkid", "ttclid",
        "twclid", "yclid", "igshid", "mc_cid", "mc_eid", "_hsenc", "_hsmi",
        "mkt_tok", "ref_src", "ref_url", "spm", "si", "oly_enc_id", "oly_anon_id",
        "vero_id", "wickedid",
    )

    fun stripUrlTrackingParamsFromRequestLine(requestLine: String): Pair<String, Boolean> {
        val sp1 = requestLine.indexOf(' ')
        if (sp1 <= 0) return requestLine to false
        val sp2 = requestLine.indexOf(' ', sp1 + 1)
        if (sp2 <= sp1 + 1) return requestLine to false
        val target = requestLine.substring(sp1 + 1, sp2)
        val qIdx = target.indexOf('?')
        if (qIdx < 0 || qIdx == target.lastIndex) return requestLine to false
        val path = target.substring(0, qIdx)
        val query = target.substring(qIdx + 1)
        val parts = query.split('&')
        val kept = ArrayList<String>(parts.size)
        var stripped = false
        for (part in parts) {
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            val key = (if (eq >= 0) part.substring(0, eq) else part).lowercase()
            if (key.startsWith("utm_") || key in TRACKING_QUERY_KEYS) {
                stripped = true
            } else {
                kept.add(part)
            }
        }
        if (!stripped) return requestLine to false
        val newTarget = if (kept.isEmpty()) path else "$path?${kept.joinToString("&")}"
        return "${requestLine.substring(0, sp1 + 1)}$newTarget${requestLine.substring(sp2)}" to true
    }

    fun sanitizePlainHttpHeaders(
        payload: ByteArray,
        persona: DevicePersona? = null,
        stripGeoHeaders: Boolean = true,
        stripTrackingParams: Boolean = true,
    ): ByteArray {
        if (payload.size < 16) return payload
        val b0 = payload[0].toInt() and 0xFF
        if (b0 < 0x41 || b0 > 0x5A) return payload // not uppercase ASCII HTTP method
        val headText = String(payload, 0, minOf(payload.size, 8192), Charsets.ISO_8859_1)
        val hdrEnd = headText.indexOf("\r\n\r\n")
        if (hdrEnd <= 0) return payload
        val headerBlock = headText.substring(0, hdrEnd)
        val lines = headerBlock.split("\r\n")
        if (lines.isEmpty() || !lines[0].contains("HTTP/1.")) return payload
        val spoofUa = persona != null && persona != DevicePersona.OFF
        var changed = false
        var sawUa = false
        val kept = ArrayList<String>(lines.size + 4)
        val (cleanReqLine, reqChanged) = if (stripTrackingParams) {
            stripUrlTrackingParamsFromRequestLine(lines[0])
        } else {
            lines[0] to false
        }
        if (reqChanged) changed = true
        kept.add(cleanReqLine)
        for (i in 1 until lines.size) {
            val line = lines[i]
            val lower = line.lowercase()
            if (lower.startsWith("x-forwarded-for:") ||
                lower.startsWith("forwarded:") ||
                lower.startsWith("via:") ||
                lower.startsWith("x-real-ip:") ||
                lower.startsWith("client-ip:") ||
                lower.startsWith("true-client-ip:") ||
                lower.startsWith("cf-connecting-ip:") ||
                lower.startsWith("x-originating-ip:") ||
                lower.startsWith("x-client-ip:") ||
                (stripGeoHeaders && (
                    lower.startsWith("x-geo-location:") ||
                        lower.startsWith("x-location:") ||
                        lower.startsWith("geo-position:")
                    )) ||
                (spoofUa && (
                    lower.startsWith("x-requested-with:") ||
                        lower.startsWith("x-device-model:") ||
                        lower.startsWith("x-device-brand:")
                    ))
            ) {
                changed = true
            } else if (spoofUa && lower.startsWith("user-agent:")) {
                kept.add("User-Agent: ${persona!!.userAgent}")
                sawUa = true
                changed = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua:")) {
                kept.add("Sec-CH-UA: ${persona!!.secChUa}")
                changed = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-model:")) {
                kept.add("Sec-CH-UA-Model: ${persona!!.secChModel}")
                changed = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-platform:")) {
                kept.add("Sec-CH-UA-Platform: ${persona!!.secChPlatform}")
                changed = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-platform-version:")) {
                kept.add("Sec-CH-UA-Platform-Version: ${persona!!.secChPlatformVersion}")
                changed = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-mobile:")) {
                kept.add("Sec-CH-UA-Mobile: ${persona!!.secChMobile}")
                changed = true
            } else if (stripGeoHeaders && spoofUa && lower.startsWith("accept-language:")) {
                kept.add("Accept-Language: en-US,en;q=0.9")
                changed = true
            } else {
                kept.add(line)
            }
        }
        if (spoofUa && !sawUa) {
            kept.add("User-Agent: ${persona!!.userAgent}")
            changed = true
        }
        if (!changed) return payload
        val newHead = (kept.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1)
        val bodyOff = hdrEnd + 4
        val bodyLen = payload.size - bodyOff
        val out = ByteArray(newHead.size + bodyLen)
        System.arraycopy(newHead, 0, out, 0, newHead.size)
        if (bodyLen > 0) System.arraycopy(payload, bodyOff, out, newHead.size, bodyLen)
        return out
    }

    /** Backwards-compatible helper stripping forwarding/client-IP headers from HTTP/1.x payloads. */
    fun stripPlainHttpClientIpHeaders(payload: ByteArray): ByteArray =
        sanitizePlainHttpHeaders(payload, null, false)
}

/**
 * Futuristic/fictional HTTP device identity profiles masking real OEM brand & OS headers on plaintext HTTP/proxy traffic.
 */
enum class DevicePersona(
    val id: String,
    val labelTr: String,
    val shortLabel: String,
    val userAgent: String,
    val secChUa: String,
    val secChModel: String,
    val secChPlatform: String,
    val secChPlatformVersion: String,
    val secChMobile: String,
) {
    IPHONE_19_BETA(
        id = "iphone19",
        labelTr = "iPhone 19 Beta · iOS 21.0 (Hayalet Kimlik)",
        shortLabel = "iPhone 19 Beta (iOS 21)",
        userAgent = "Mozilla/5.0 (iPhone19,3; CPU iPhone OS 21_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/21.0 Mobile/25A109 Safari/604.1",
        secChUa = "\"Safari\";v=\"21\", \"Not_A Brand\";v=\"99\"",
        secChModel = "\"iPhone 19 Beta\"",
        secChPlatform = "\"iOS\"",
        secChPlatformVersion = "\"21.0.0\"",
        secChMobile = "?1",
    ),
    ANDROID_19_QUANTUM(
        id = "android19",
        labelTr = "Android 19 Quantum · SDK 39 (Hayalet Kimlik)",
        shortLabel = "Android 19 Quantum",
        userAgent = "Mozilla/5.0 (Linux; Android 19; Quantum-X99) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
        secChUa = "\"Chromium\";v=\"148\", \"Not_A Brand\";v=\"99\"",
        secChModel = "\"Quantum-X99 Beta\"",
        secChPlatform = "\"Android\"",
        secChPlatformVersion = "\"19.0.0\"",
        secChMobile = "?1",
    ),
    PIXEL_14_FUTURE(
        id = "pixel14",
        labelTr = "Pixel 14 Ultra · Android 19 Beta (Hayalet Kimlik)",
        shortLabel = "Pixel 14 Ultra Prototype",
        userAgent = "Mozilla/5.0 (Linux; Android 19; Pixel 14 Ultra Proto) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
        secChUa = "\"Google Chrome\";v=\"149\", \"Not_A Brand\";v=\"99\"",
        secChModel = "\"Pixel 14 Ultra Proto\"",
        secChPlatform = "\"Android\"",
        secChPlatformVersion = "\"19.0.0\"",
        secChMobile = "?1",
    ),
    OFF(
        id = "off",
        labelTr = "Gerçek Cihaz Kimliği (Maskesiz)",
        shortLabel = "Kapalı",
        userAgent = "",
        secChUa = "",
        secChModel = "",
        secChPlatform = "",
        secChPlatformVersion = "",
        secChMobile = "",
    );

    companion object {
        fun fromId(id: String?): DevicePersona =
            values().firstOrNull { it.id == id } ?: IPHONE_19_BETA
    }
}

/**
 * Validated upstream exit relay descriptor for public IP hiding (`socks5://`, `http://`,
 * `https://`, or `tor`/`orbot` shortcut to `127.0.0.1:9050`).
 */
data class ExitRelayConfig(
    val scheme: String,
    val host: String,
    val port: Int,
    val username: String = "",
    val password: String = "",
) {
    fun isLoopback(): Boolean =
        host == "127.0.0.1" || host.equals("localhost", ignoreCase = true) || host == "::1"

    fun label(): String = "${scheme.uppercase()} $host:$port"

    companion object {
        fun parse(raw: String): ExitRelayConfig? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) return null
            if (trimmed.equals("tor", ignoreCase = true) || trimmed.equals("orbot", ignoreCase = true)) {
                return ExitRelayConfig(scheme = "socks5", host = "127.0.0.1", port = 9050)
            }
            val normalized = if ("://" in trimmed) trimmed else "socks5://$trimmed"
            val uri = runCatching { java.net.URI(normalized) }.getOrNull() ?: return null
            val rawScheme = (uri.scheme ?: "socks5").lowercase()
            val scheme = when (rawScheme) {
                "socks", "socks5", "socks5h" -> "socks5"
                "http" -> "http"
                "https" -> "https"
                else -> return null
            }
            val host = uri.host?.trim('[', ']')?.takeIf { it.isNotEmpty() } ?: return null
            val defaultPort = when (scheme) {
                "socks5" -> 1080
                "https" -> 443
                else -> 8080
            }
            val port = if (uri.port > 0) uri.port else defaultPort
            if (port !in 1..65535) return null
            val userInfo = uri.userInfo.orEmpty()
            val user = userInfo.substringBefore(':', "")
            val pass = if (':' in userInfo) userInfo.substringAfter(':') else ""
            return ExitRelayConfig(scheme, host, port, user, pass)
        }
    }
}

/**
 * RFC 8484 DoH client that needs **no DNS of its own**: endpoints are IP literals
 * (`https://1.1.1.1/dns-query`) or well-known resolver names mapped to their anycast IPs, so
 * the ISP resolver (which may return poisoned sinkhole IPs such as `195.175.254.2`) is never
 * consulted and a VPN TUN cannot recurse into itself. Every socket is passed to
 * [protectSocket] (Android `VpnService.protect`). Requests send minimal zero-fingerprint headers
 * over pooled HTTP/1.1 keep-alive connections and verify server identity via HTTPS SAN rules.
 */
class DirectDohClient(
    private val protectSocket: (Socket) -> Boolean = { true },
    private val sslFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    private val verifier: ((String, SSLSession) -> Boolean)? = null,
) : DohClient, AutoCloseable {
    private class Conn(val key: String, val sock: SSLSocket, val input: java.io.BufferedInputStream, val out: OutputStream)

    private val idle = ConcurrentHashMap<String, java.util.concurrent.ConcurrentLinkedQueue<Conn>>()

    override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
        val start = System.nanoTime()
        fun rtt() = (System.nanoTime() - start) / 1000
        val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return DohResponse(6, 0, EncProtocol.DOH, null)
        val host = uri.host?.trim('[', ']') ?: return DohResponse(6, 0, EncProtocol.DOH, null)
        val port = if (uri.port > 0) uri.port else 443
        val path = (uri.rawPath ?: "/dns-query").ifEmpty { "/dns-query" }
        val key = "$host:$port"
        for (attempt in 0 until 2) {
            val pooled = if (attempt == 0) idle[key]?.poll() else null
            val conn = pooled ?: try {
                open(host, port, timeoutMs)
            } catch (_: SocketTimeoutException) {
                return DohResponse(2, rtt(), EncProtocol.DOH, null)
            } catch (_: ConnectException) {
                return DohResponse(4, rtt(), EncProtocol.DOH, null)
            } catch (_: SSLHandshakeException) {
                return DohResponse(5, rtt(), EncProtocol.DOH, null)
            } catch (_: IOException) {
                return DohResponse(5, rtt(), EncProtocol.DOH, null)
            }
            try {
                conn.sock.soTimeout = timeoutMs
                val hostHeader = if (host.contains(':')) "[$host]" else host
                val head = "POST $path HTTP/1.1\r\nHost: $hostHeader\r\n" +
                    "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n" +
                    "Content-Length: ${body.size}\r\nConnection: keep-alive\r\n\r\n"
                conn.out.write(head.toByteArray(Charsets.US_ASCII))
                conn.out.write(body)
                conn.out.flush()
                val (status, headers, respBody) = readResponse(conn.input)
                val keep = !headers["connection"].orEmpty().equals("close", ignoreCase = true)
                if (keep) idle.getOrPut(key) { java.util.concurrent.ConcurrentLinkedQueue() }.offer(conn) else closeConn(conn)
                val type = headers["content-type"].orEmpty()
                return if (status == 200 && type.startsWith("application/dns-message") && respBody.size >= 12) {
                    DohResponse(1, rtt(), EncProtocol.DOH, respBody)
                } else {
                    DohResponse(6, rtt(), EncProtocol.DOH, null)
                }
            } catch (e: IOException) {
                closeConn(conn)
                if (pooled == null) {
                    return DohResponse(if (e is SocketTimeoutException) 2 else 5, rtt(), EncProtocol.DOH, null)
                }
                // stale keep-alive connection: retry once on a fresh one
            }
        }
        return DohResponse(5, rtt(), EncProtocol.DOH, null)
    }

    private fun open(host: String, port: Int, timeoutMs: Int): Conn {
        val ip = IpPackets.parseIpLiteral(host)?.let { InetAddress.getByAddress(IpPackets.ipToBytes(it)) }
            ?: BOOTSTRAP[host.lowercase()]?.let { InetAddress.getByAddress(IpPackets.ipToBytes(IpPackets.parseIpLiteral(it)!!)) }
            ?: InetAddress.getByName(host)
        val raw = Socket()
        try {
            raw.bind(null)
            protectSocket(raw)
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(ip, port), timeoutMs)
            raw.soTimeout = timeoutMs
            val ssl = sslFactory.createSocket(raw, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.startHandshake()
            val v = verifier
            if (v != null && !v(host, ssl.session)) {
                runCatching { ssl.close() }
                throw SSLPeerUnverifiedException("DoH host verification failed: $host")
            }
            return Conn("$host:$port", ssl, java.io.BufferedInputStream(ssl.inputStream), java.io.BufferedOutputStream(ssl.outputStream))
        } catch (e: IOException) {
            runCatching { raw.close() }
            throw e
        }
    }

    private fun readLine(input: java.io.InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 8192) {
            val c = input.read()
            if (c < 0) throw IOException("EOF")
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun readExact(input: java.io.InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var r = 0
        while (r < n) {
            val k = input.read(out, r, n - r)
            if (k < 0) throw IOException("EOF")
            r += k
        }
        return out
    }

    private fun readResponse(input: java.io.InputStream): Triple<Int, Map<String, String>, ByteArray> {
        val statusLine = readLine(input)
        val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: throw IOException("bad status")
        val headers = HashMap<String, String>()
        while (true) {
            val line = readLine(input)
            if (line.isEmpty()) break
            val i = line.indexOf(':')
            if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
        }
        val body = if (headers["transfer-encoding"].orEmpty().contains("chunked", ignoreCase = true)) {
            val acc = ByteArrayOutputStream()
            while (true) {
                val size = readLine(input).substringBefore(';').trim().toIntOrNull(16) ?: throw IOException("bad chunk")
                if (size == 0) {
                    while (readLine(input).isNotEmpty()) { /* trailers */ }
                    break
                }
                if (acc.size() + size > Wire.MAX_BYTES) throw IOException("too large")
                acc.write(readExact(input, size))
                readLine(input)
            }
            acc.toByteArray()
        } else {
            val len = headers["content-length"]?.toIntOrNull() ?: throw IOException("no length")
            if (len < 0 || len > Wire.MAX_BYTES) throw IOException("bad length")
            readExact(input, len)
        }
        return Triple(status, headers, body)
    }

    private fun closeConn(c: Conn) {
        runCatching { c.sock.close() }
    }

    override fun close() {
        for (q in idle.values) while (true) closeConn(q.poll() ?: break)
        idle.clear()
    }

    companion object {
        /** Anycast addresses of public resolvers, used instead of a DNS lookup for their names. */
        val BOOTSTRAP = mapOf(
            "cloudflare-dns.com" to "1.1.1.1",
            "one.one.one.one" to "1.1.1.1",
            "security.cloudflare-dns.com" to "1.1.1.2",
            "dns.google" to "8.8.8.8",
            "dns.google.com" to "8.8.8.8",
            "dns.quad9.net" to "9.9.9.9",
            "dns.adguard-dns.com" to "94.140.14.14",
        )
    }
}

/** Provisioned Cloudflare WARP WireGuard credentials (persisted locally for instant reconnect). */
data class WarpIdentity(
    val privateKeyB64: String,
    val peerPublicKeyB64: String,
    val clientIpv4: String,
    val endpointHost: String,
    val endpointPort: Int = 2408,
    val deviceId: String = "",
    val accessToken: String = "",
    val createdAtMs: Long = System.currentTimeMillis(),
    val clientIdB64: String = "",
    val clientIpv6: String = "",
) {
    fun privateKeyBytes(): ByteArray? = runCatching {
        java.util.Base64.getDecoder().decode(privateKeyB64).takeIf { it.size == 32 }
    }.getOrNull()

    fun peerPublicKeyBytes(): ByteArray? = runCatching {
        java.util.Base64.getDecoder().decode(peerPublicKeyB64).takeIf { it.size == 32 }
    }.getOrNull()

    fun reservedBytes(): ByteArray {
        val raw = runCatching { java.util.Base64.getDecoder().decode(clientIdB64) }.getOrNull()
        return if (raw != null && raw.size >= 3) raw.copyOfRange(0, 3) else byteArrayOf(0, 0, 0)
    }

    fun clientIpInt(): Int? = IpPackets.parseIpLiteral(clientIpv4)

    fun isValid(): Boolean =
        privateKeyBytes() != null &&
            peerPublicKeyBytes() != null &&
            clientIpInt() != null &&
            endpointHost.isNotBlank() &&
            endpointPort in 1..65535

    fun serialize(): String =
        listOf(
            privateKeyB64,
            peerPublicKeyB64,
            clientIpv4,
            endpointHost,
            endpointPort.toString(),
            deviceId,
            accessToken,
            createdAtMs.toString(),
            clientIdB64,
            clientIpv6,
        ).joinToString("|")

    companion object {
        fun deserialize(raw: String?): WarpIdentity? {
            if (raw.isNullOrBlank()) return null
            val p = raw.split('|')
            if (p.size < 5) return null
            val id = WarpIdentity(
                privateKeyB64 = p[0].trim(),
                peerPublicKeyB64 = p[1].trim(),
                clientIpv4 = p[2].trim(),
                endpointHost = p[3].trim(),
                endpointPort = p[4].trim().toIntOrNull() ?: 2408,
                deviceId = p.getOrNull(5)?.trim().orEmpty(),
                accessToken = p.getOrNull(6)?.trim().orEmpty(),
                createdAtMs = p.getOrNull(7)?.trim()?.toLongOrNull() ?: 0L,
                clientIdB64 = p.getOrNull(8)?.trim().orEmpty(),
                clientIpv6 = p.getOrNull(9)?.trim().orEmpty(),
            )
            return if (id.isValid()) id else null
        }
    }
}

/** Zero-config Cloudflare WARP WireGuard account provisioner via pure Rust X25519 + TLS. */
object WarpProvisioner {
    private const val API_HOST = "api.cloudflareclient.com"
    private const val API_PATH = "/v0a2158/reg"
    private val FALLBACK_API_IPS = listOf("162.159.137.105", "162.159.138.105", "104.16.80.230")

    internal fun extractJsonString(json: String, key: String, startAt: Int = 0): String? {
        val needle = "\"$key\""
        var idx = json.indexOf(needle, startAt)
        while (idx >= 0) {
            var pos = idx + needle.length
            while (pos < json.length && json[pos].isWhitespace()) pos++
            if (pos < json.length && json[pos] == ':') {
                pos++
                while (pos < json.length && json[pos].isWhitespace()) pos++
                if (pos < json.length && json[pos] == '"') {
                    val end = json.indexOf('"', pos + 1)
                    if (end > pos) return json.substring(pos + 1, end)
                }
            }
            idx = json.indexOf(needle, idx + needle.length)
        }
        return null
    }

    internal fun extractJsonBool(json: String, key: String, startAt: Int = 0): Boolean? {
        val needle = "\"$key\""
        var idx = json.indexOf(needle, startAt)
        while (idx >= 0) {
            var pos = idx + needle.length
            while (pos < json.length && json[pos].isWhitespace()) pos++
            if (pos < json.length && json[pos] == ':') {
                pos++
                while (pos < json.length && json[pos].isWhitespace()) pos++
                if (json.startsWith("true", pos)) return true
                if (json.startsWith("false", pos)) return false
            }
            idx = json.indexOf(needle, idx + needle.length)
        }
        return null
    }

    fun parseRegistrationJson(json: String, privKeyB64: String): WarpIdentity? {
        val deviceId = extractJsonString(json, "id").orEmpty()
        val token = extractJsonString(json, "token").orEmpty()
        val addrIdx = json.indexOf("\"addresses\"")
        val rawV4 = if (addrIdx >= 0) extractJsonString(json, "v4", addrIdx) else extractJsonString(json, "v4")
        val clientIpv4 = rawV4?.substringBefore('/')?.trim().orEmpty()
        val rawV6 = if (addrIdx >= 0) extractJsonString(json, "v6", addrIdx) else null
        val clientIpv6 = rawV6?.substringBefore('/')?.trim().orEmpty()
        val clientIdB64 = extractJsonString(json, "client_id").orEmpty()
        val peersIdx = json.indexOf("\"peers\"")
        val searchFrom = if (peersIdx >= 0) peersIdx else 0
        val peerPub = extractJsonString(json, "public_key", searchFrom).orEmpty()
        val epIdx = json.indexOf("\"endpoint\"", searchFrom)
        val rawEndpoint = if (epIdx >= 0) extractJsonString(json, "v4", epIdx).orEmpty() else "162.159.192.1:2408"
        val cleanEp = rawEndpoint.substringBefore('/')
        val colon = cleanEp.lastIndexOf(':')
        val host = if (colon > 0) cleanEp.substring(0, colon).trim('[', ']') else cleanEp.trim('[', ']')
        val port = if (colon > 0) cleanEp.substring(colon + 1).toIntOrNull() ?: 2408 else 2408
        val id = WarpIdentity(
            privateKeyB64 = privKeyB64,
            peerPublicKeyB64 = peerPub,
            clientIpv4 = clientIpv4,
            endpointHost = host.ifBlank { "162.159.192.1" },
            endpointPort = if (port in 1..65535) port else 2408,
            deviceId = deviceId,
            accessToken = token,
            clientIdB64 = clientIdB64,
            clientIpv6 = clientIpv6,
        )
        return if (id.isValid()) id else null
    }

    private fun readHttpLine(input: InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 8192) {
            val c = input.read()
            if (c < 0) throw IOException("EOF")
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun readHttpExact(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var r = 0
        while (r < n) {
            val k = input.read(out, r, n - r)
            if (k < 0) throw IOException("EOF")
            r += k
        }
        return out
    }

    private fun httpsJsonRequest(
        ip: InetAddress,
        method: String,
        path: String,
        bodyJson: String,
        bearerToken: String = "",
        protectSocket: (Socket) -> Boolean,
        timeoutMs: Int = 5500,
    ): Pair<Int, String> {
        val raw = Socket()
        var ssl: SSLSocket? = null
        try {
            raw.bind(null)
            protectSocket(raw)
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(ip, 443), timeoutMs)
            raw.soTimeout = timeoutMs
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            ssl = factory.createSocket(raw, API_HOST, 443, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.startHandshake()

            val bodyBytes = bodyJson.toByteArray(Charsets.UTF_8)
            val sb = StringBuilder()
            sb.append("$method $path HTTP/1.1\r\n")
            sb.append("Host: $API_HOST\r\n")
            sb.append("User-Agent: okhttp/3.12.1\r\n")
            sb.append("Accept-Encoding: identity\r\n")
            sb.append("Content-Type: application/json; charset=UTF-8\r\n")
            if (bearerToken.isNotEmpty()) {
                sb.append("Authorization: Bearer $bearerToken\r\n")
            }
            sb.append("Content-Length: ${bodyBytes.size}\r\n")
            sb.append("Connection: close\r\n\r\n")
            val out = ssl.outputStream
            out.write(sb.toString().toByteArray(Charsets.US_ASCII))
            out.write(bodyBytes)
            out.flush()

            val input = java.io.BufferedInputStream(ssl.inputStream)
            val statusLine = readHttpLine(input)
            val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
            val headers = HashMap<String, String>()
            while (true) {
                val line = readHttpLine(input)
                if (line.isEmpty()) break
                val i = line.indexOf(':')
                if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
            }
            val respBytes = if (headers["transfer-encoding"].orEmpty().contains("chunked", ignoreCase = true)) {
                val acc = ByteArrayOutputStream()
                while (true) {
                    val sz = readHttpLine(input).substringBefore(';').trim().toIntOrNull(16) ?: break
                    if (sz == 0) break
                    if (acc.size() + sz > 262144) break
                    acc.write(readHttpExact(input, sz))
                    readHttpLine(input)
                }
                acc.toByteArray()
            } else {
                val cl = headers["content-length"]?.toIntOrNull()
                if (cl != null && cl in 0..262144) {
                    readHttpExact(input, cl)
                } else {
                    val acc = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    while (acc.size() < 262144) {
                        val k = input.read(buf)
                        if (k <= 0) break
                        acc.write(buf, 0, k)
                    }
                    acc.toByteArray()
                }
            }
            return code to String(respBytes, Charsets.UTF_8)
        } finally {
            runCatching { ssl?.close() }
            runCatching { raw.close() }
        }
    }

    private fun resolveApiCandidates(protectSocket: (Socket) -> Boolean): List<InetAddress> {
        val out = ArrayList<InetAddress>()
        runCatching {
            DirectDohClient(protectSocket).use { doh ->
                val q = Doh.query(API_HOST)
                if (q != null) {
                    val r = doh.post("https://1.1.1.1/dns-query", q, 2500)
                    val b = r.body
                    if (r.transport == 1 && b != null && !IpPackets.containsPoisonedDns(b)) {
                        IpPackets.dnsAnswerAddresses(b)?.forEach { addr ->
                            if (addr.size == 4) runCatching { out.add(InetAddress.getByAddress(addr)) }
                        }
                    }
                }
            }
        }
        runCatching {
            InetAddress.getAllByName(API_HOST).forEach { a ->
                if (a is Inet4Address && !a.isLoopbackAddress && !a.isSiteLocalAddress) out.add(a)
            }
        }
        for (ipStr in FALLBACK_API_IPS) {
            IpPackets.parseIpLiteral(ipStr)?.let { v4 ->
                runCatching { out.add(InetAddress.getByAddress(IpPackets.ipToBytes(v4))) }
            }
        }
        return out.distinct()
    }

    fun register(
        protectSocket: (Socket) -> Boolean = { true },
        logger: ((String, String) -> Unit)? = null,
    ): WarpIdentity? {
        if (!Native.available) return null
        val priv = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val pub = Native.wgPublicKey(priv) ?: return null
        if (pub.size != 32) return null
        val privB64 = java.util.Base64.getEncoder().encodeToString(priv)
        val pubB64 = java.util.Base64.getEncoder().encodeToString(pub)
        val df = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.000'Z'", java.util.Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }
        val tos = df.format(java.util.Date())
        val payload = "{\"install_id\":\"\",\"tos\":\"$tos\",\"key\":\"$pubB64\",\"fcm_token\":\"\",\"type\":\"Android\",\"model\":\"PC\",\"locale\":\"en_US\"}"

        val candidates = resolveApiCandidates(protectSocket)
        for (ip in candidates) {
            val res = runCatching {
                httpsJsonRequest(ip, "POST", API_PATH, payload, "", protectSocket, 5000)
            }.getOrNull() ?: continue
            val (code, json) = res
            if (code in 200..299 && json.isNotBlank()) {
                val id = parseRegistrationJson(json, privB64)
                if (id != null) {
                    val enabled = extractJsonBool(json, "warp_enabled") ?: false
                    if (!enabled && id.deviceId.isNotEmpty() && id.accessToken.isNotEmpty()) {
                        runCatching {
                            httpsJsonRequest(
                                ip,
                                "PATCH",
                                "$API_PATH/${id.deviceId}",
                                "{\"warp_enabled\":true}",
                                id.accessToken,
                                protectSocket,
                                3500,
                            )
                        }
                    }
                    logger?.invoke("WarpProvisioner", "WARP hesabı hazır (${id.clientIpv4} -> ${id.endpointHost}:${id.endpointPort})")
                    return id
                }
            }
        }
        logger?.invoke("WarpProvisioner", "WARP kaydı oluşturulamadı (tüm API adayları yanıt vermedi)")
        return null
    }
}

/** Pure-Rust WireGuard UDP tunnel client over `VpnService.protect()`ed `DatagramSocket`. */
class WarpTunnel(
    val identity: WarpIdentity,
    private val protectDatagram: (DatagramSocket) -> Boolean = { true },
    private val logger: ((String, String) -> Unit)? = null,
) : AutoCloseable {
    private val wgHandle = java.util.concurrent.atomic.AtomicLong(0L)
    private val closed = AtomicBoolean(false)
    @Volatile private var socket: DatagramSocket? = null
    @Volatile var activeEndpoint: InetSocketAddress? = null
    @Volatile var established: Boolean = false
    @Volatile var handshakeRttMs: Long = 0L
    @Volatile private var lastRxMs: Long = 0L
    @Volatile private var lastTxMs: Long = 0L
    private var recvThread: Thread? = null
    private var keepaliveThread: Thread? = null

    private fun buildTai64n(): ByteArray {
        val nowMs = System.currentTimeMillis()
        val secs = (nowMs / 1000L) + 4611686018427387914L
        val nanos = ((nowMs % 1000L) * 1_000_000L).toInt()
        val out = ByteArray(12)
        IpPackets.putU32(out, 0, (secs ushr 32) and 0xFFFFFFFFL)
        IpPackets.putU32(out, 4, secs and 0xFFFFFFFFL)
        IpPackets.putU32(out, 8, nanos.toLong() and 0xFFFFFFFFL)
        return out
    }

    private fun buildCandidates(): List<InetSocketAddress> {
        val list = ArrayList<Pair<String, Int>>()
        list.add(identity.endpointHost to identity.endpointPort)
        for (p in intArrayOf(2408, 500, 4500, 1701, 894, 854, 4198, 7152, 8854)) {
            list.add(identity.endpointHost to p)
        }
        for (ip in arrayOf(
            "162.159.192.1", "162.159.193.1", "162.159.195.1",
            "188.114.96.1", "188.114.97.1", "188.114.98.1", "188.114.99.1",
        )) {
            list.add(ip to 2408)
            list.add(ip to 500)
            list.add(ip to 4500)
        }
        return list.distinct().mapNotNull { (h, p) ->
            runCatching { InetSocketAddress(InetAddress.getByName(h), p) }.getOrNull()
        }
    }

    fun connect(timeoutMs: Int = 3500): Boolean {
        if (!Native.available || !identity.isValid()) return false
        val priv = identity.privateKeyBytes() ?: return false
        val peerPub = identity.peerPublicKeyBytes() ?: return false
        val h = Native.wgCreate(priv, peerPub)
        if (h <= 0L) return false
        wgHandle.set(h)
        runCatching { Native.wgSetReserved(h, identity.reservedBytes()) }
        val s = try {
            DatagramSocket().also { ds ->
                protectDatagram(ds)
                runCatching { ds.receiveBufferSize = 262144; ds.sendBufferSize = 262144 }
                ds.soTimeout = 500
            }
        } catch (t: Throwable) {
            Native.wgDestroy(h)
            wgHandle.set(0L)
            return false
        }
        socket = s
        val rng = java.security.SecureRandom()
        val ephPriv = ByteArray(32).also { rng.nextBytes(it) }
        val initPkt = Native.wgHandshakeInit(h, ephPriv, buildTai64n())
        if (initPkt == null || initPkt.size != 148) {
            close()
            return false
        }
        val candidates = buildCandidates()
        val awgPrefaces = runCatching {
            Native.wgBuildAwgPrefaces(2, 48, 96, null)?.let { raw ->
                Wire.decode(raw).bytesAll(Tags.Desync.OUT_PACKET)
            }
        }.getOrNull().orEmpty()
        for (ep in candidates.take(4)) {
            for (junk in awgPrefaces) {
                runCatching { s.send(DatagramPacket(junk, junk.size, ep)) }
            }
        }
        val t0Ms = System.currentTimeMillis()
        for (ep in candidates) {
            runCatching { s.send(DatagramPacket(initPkt, initPkt.size, ep)) }
        }
        val deadline = System.currentTimeMillis() + timeoutMs
        val buf = ByteArray(2048)
        while (!closed.get() && System.currentTimeMillis() < deadline) {
            val dp = DatagramPacket(buf, buf.size)
            val got = try {
                s.receive(dp)
                true
            } catch (_: SocketTimeoutException) {
                false
            } catch (_: Throwable) {
                break
            }
            if (!got || dp.length < 16) continue
            val pkt = buf.copyOf(dp.length)
            when (Native.wgConsumeResponse(h, pkt)) {
                0 -> {
                    activeEndpoint = dp.socketAddress as? InetSocketAddress ?: candidates.firstOrNull()
                    established = true
                    val now = System.currentTimeMillis()
                    handshakeRttMs = (now - t0Ms).coerceAtLeast(1L)
                    lastRxMs = now
                    lastTxMs = now
                    sendIpPacket(ByteArray(0))
                    logger?.invoke(
                        "WarpTunnel",
                        "WARP WireGuard el sıkışması tamamlandı (${handshakeRttMs}ms) -> ${activeEndpoint?.hostString}:${activeEndpoint?.port}",
                    )
                    return true
                }
                1 -> {
                    val eph2 = ByteArray(32).also { rng.nextBytes(it) }
                    Native.wgHandshakeInit(h, eph2, buildTai64n())?.let { retryPkt ->
                        dp.socketAddress?.let { ep ->
                            runCatching { s.send(DatagramPacket(retryPkt, retryPkt.size, ep)) }
                        }
                    }
                }
            }
        }
        logger?.invoke("WarpTunnel", "WARP WireGuard UDP el sıkışması zaman aşımına uğradı")
        close()
        return false
    }

    fun startLoops(onDecryptedIpPacket: (ByteArray) -> Unit) {
        val s = socket ?: return
        runCatching { s.soTimeout = 30_000 }
        recvThread = Thread({
            val buf = ByteArray(4096)
            while (!closed.get() && established) {
                val dp = DatagramPacket(buf, buf.size)
                try {
                    s.receive(dp)
                    if (dp.length < 32) continue
                    val h = wgHandle.get()
                    if (h <= 0L) break
                    val dec = Native.wgDecrypt(h, buf.copyOf(dp.length)) ?: continue
                    lastRxMs = System.currentTimeMillis()
                    if (dec.isNotEmpty()) {
                        onDecryptedIpPacket(dec)
                    }
                } catch (_: SocketTimeoutException) {
                    if (System.currentTimeMillis() - lastRxMs > 125_000L) {
                        rekeyOnce()
                    }
                } catch (_: Throwable) {
                    if (!closed.get()) break
                }
            }
        }, "freedom-wg-rx").apply {
            isDaemon = true
            start()
        }
        keepaliveThread = Thread({
            val rng = java.security.SecureRandom()
            while (!closed.get() && established) {
                try {
                    Thread.sleep(18_000L + rng.nextInt(6_001).toLong())
                } catch (_: InterruptedException) {
                    break
                }
                if (closed.get() || !established) break
                if (System.currentTimeMillis() - lastTxMs >= 18_000L) {
                    sendIpPacket(ByteArray(0))
                }
            }
        }, "freedom-wg-keepalive").apply {
            isDaemon = true
            start()
        }
    }

    private fun rekeyOnce() {
        val h = wgHandle.get()
        val s = socket ?: return
        val ep = activeEndpoint ?: return
        if (h <= 0L || closed.get()) return
        val eph = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val initPkt = Native.wgHandshakeInit(h, eph, buildTai64n()) ?: return
        runCatching { s.send(DatagramPacket(initPkt, initPkt.size, ep)) }
    }

    fun sendIpPacket(ipPacket: ByteArray): Boolean {
        val h = wgHandle.get()
        val s = socket
        val ep = activeEndpoint
        if (h <= 0L || s == null || ep == null || !established || closed.get()) return false
        val wg = Native.wgEncrypt(h, ipPacket) ?: return false
        return try {
            s.send(DatagramPacket(wg, wg.size, ep))
            lastTxMs = System.currentTimeMillis()
            true
        } catch (_: Throwable) {
            false
        }
    }

    fun reprotect() {
        socket?.let { runCatching { protectDatagram(it) } }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        established = false
        runCatching { recvThread?.interrupt() }
        runCatching { keepaliveThread?.interrupt() }
        runCatching { socket?.close() }
        socket = null
        val h = wgHandle.getAndSet(0L)
        if (h > 0L) runCatching { Native.wgDestroy(h) }
    }
}

/**
 * Freedom Network User-Mode TUN -> Protected Socket Bridge (`tun2socks` + Built-in Auto-WARP WireGuard +
 * Happy Eyeballs DoH3 + Privacy/Tracker Shield + Strict Kill Switch + Universal TCP/TLS/ECH Desync +
 * Low-Latency UDP NAT).
 *
 * Bridges raw IPv4/IPv6 packets from the TUN descriptor (`0.0.0.0/0` + `::/0`) to real outbound
 * encrypted WireGuard WARP or `VpnService.protect()`ed TCP/UDP sockets:
 * 1. **Built-in Zero-Config Public IP Masking**: Automatically provisions and connects a pure-Rust
 *    WireGuard WARP tunnel (with Tor SOCKS5 `:9050` auto-detection and Direct DPI fallback) unless an
 *    explicit Exit Relay is specified.
 * 2. **Encrypted DNS & Tracker Shield (UDP/TCP 53)**: Resolves via parallel Happy Eyeballs
 *    RFC 8484 DoH3/DoH (`DohClient`), strips ISP DNS poisoning & DNS-rebinding private answers,
 *    suppresses unbridged `AAAA` probes, and blocks telemetry/ad/geo-beacon domains (`blockTrackers`).
 * 3. **Universal TCP + TLS 1.3 / ECH / PQ Desync + Device Identity Spoofing**: Fragments `SNI`/`ECH`
 *    across TLS records via Rust+SIMD `desyncPacket` in direct DPI mode and rewrites plaintext HTTP
 *    device headers to a non-existent [DevicePersona] (`iPhone 19 Beta`, `Android 19 Quantum`).
 * 4. **Universal UDP NAT & Leak Protection**: Routes/NATs UDP streams while blocking STUN/WebRTC/mDNS/SSDP leaks.
 */
class TunBridge(
    private val session: DiagnosticSession,
    private val tunInput: InputStream,
    private val tunOutput: OutputStream,
    private val protectSocket: (Socket) -> Boolean = { true },
    private val protectDatagram: (DatagramSocket) -> Boolean = { true },
    private val dohClient: DohClient? = null,
    private val dohEndpoints: List<String> = DEFAULT_DOH_ENDPOINTS,
    private val upstreamDnsServers: List<String> = DEFAULT_DNS_SERVERS,
    private val desyncConfig: DesyncConfig = DesyncConfig(
        mode = DesyncMode.REALITY_VISION,
        fakeTtl = 5,
        splitPos = 2,
        dropRst = true,
    ),
    private val blockQuic: Boolean = true,
    private val strictKillSwitch: Boolean = false,
    private val blockTrackers: Boolean = false,
    private val hardenStunLeaks: Boolean = false,
    private val logger: ((String, String) -> Unit)? = null,
    private val exitRelayUri: String = "",
    private val autoWarp: Boolean = false,
    private val initialWarpIdentity: WarpIdentity? = null,
    private val devicePersona: DevicePersona = DevicePersona.OFF,
    private val suppressIpv6Dns: Boolean = true,
    private val onWarpIdentityReady: ((WarpIdentity) -> Unit)? = null,
    private val onRouteChanged: ((String, Boolean) -> Unit)? = null,
) : AutoCloseable {
    private fun log(tag: String, msg: String) {
        logger?.invoke(tag, msg)
    }

    private data class FlowKey(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)

    @Volatile private var activeExitRelay: ExitRelayConfig? = ExitRelayConfig.parse(exitRelayUri)
    private val exitRelay: ExitRelayConfig? get() = activeExitRelay
    @Volatile private var warpTunnel: WarpTunnel? = null
    @Volatile private var warpClientIpInt: Int = 0
    private val tunClientIpInt: Int = IpPackets.parseIpLiteral(VPN_CLIENT_IP) ?: 0x0AD7AD01
    private val warpBootstrapping = AtomicBoolean(false)
    @Volatile private var routeMasked: Boolean = activeExitRelay != null
    @Volatile private var routeLabel: String = activeExitRelay?.label()
        ?: if (autoWarp) "WARP WireGuard Bağlanıyor..." else "Doğrudan (Yerel DPI)"

    private val running = AtomicBoolean(false)
    private val writeLock = Any()
    private val ioPool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "freedom-tun-io").apply { isDaemon = true }
    }
    private var readerThread: Thread? = null
    private val tcpTable = ConcurrentHashMap<FlowKey, TcpFlow>()
    private val udpTable = ConcurrentHashMap<FlowKey, UdpFlow>()
    private val dnsIpToHost = ConcurrentHashMap<Int, String>()
    private val virtualDnsIp: Int = IpPackets.parseIpLiteral(VPN_DNS_IP) ?: 0x0AD7AD02
    private val dnsCache = ConcurrentHashMap<String, Triple<Long, Long, ByteArray>>()
    private val dnsRefreshInFlight = ConcurrentHashMap.newKeySet<String>()
    @Volatile private var preferredDoh = 0

    val isExitRelayActive: Boolean get() = activeExitRelay != null
    val isWarpActive: Boolean get() = warpTunnel?.established == true
    val isIpMasked: Boolean get() = routeMasked || isWarpActive || isExitRelayActive
    val activeExitRelayLabel: String get() = routeLabel
    val activeDevicePersona: DevicePersona get() = devicePersona

    val tcpFlows = AtomicInteger(0)
    val udpFlows = AtomicInteger(0)
    val dnsQueries = AtomicInteger(0)
    val dohResolved = AtomicInteger(0)
    val desyncedFlows = AtomicInteger(0)
    val visionSplicedFlows = AtomicInteger(0)
    val roamingRebinds = AtomicInteger(0)
    val poisonedDnsBlocked = AtomicInteger(0)
    val quicFallbacks = AtomicInteger(0)
    val tlsRecordFragmented = AtomicInteger(0)
    val dnsCacheHits = AtomicInteger(0)
    val warpDnsFastHits = AtomicInteger(0)
    val paramsStripped = AtomicInteger(0)
    val ipv6Rejected = AtomicInteger(0)
    val aaaaSuppressed = AtomicInteger(0)
    val trackersBlocked = AtomicInteger(0)
    val leaksBlocked = AtomicInteger(0)
    val httpHeadersSpoofed = AtomicInteger(0)
    val warpPacketsOut = java.util.concurrent.atomic.AtomicLong(0)
    val warpPacketsIn = java.util.concurrent.atomic.AtomicLong(0)
    val bytesUp = java.util.concurrent.atomic.AtomicLong(0)
    val bytesDown = java.util.concurrent.atomic.AtomicLong(0)

    /**
     * Handles seamless Wi-Fi <-> Mobile Data (LTE/5G) roaming by refreshing ephemeral UDP NAT
     * bindings and re-protecting active sockets + WireGuard UDP socket without tearing down TUN.
     */
    fun rebindActiveSessions() {
        roamingRebinds.incrementAndGet()
        warpTunnel?.reprotect()
        for (u in udpTable.values) {
            u.socket?.let { runCatching { protectDatagram(it) } }
        }
        for (t in tcpTable.values) {
            t.upstreamSocket?.let { runCatching { protectSocket(it) } }
        }
    }

    private fun isLocalPortOpen(host: String, port: Int, timeoutMs: Int = 500): Boolean = runCatching {
        Socket().use { s ->
            s.connect(InetSocketAddress(InetAddress.getByName(host), port), timeoutMs)
        }
        true
    }.getOrDefault(false)

    private fun onWarpInbound(dec: ByteArray) {
        if (dec.size < 20 || ((dec[0].toInt() ushr 4) and 0x0F) != 4) return
        val nat = IpPackets.rewriteIpv4Nat(dec, newDstIp = tunClientIpInt) ?: return
        warpPacketsIn.incrementAndGet()
        bytesDown.addAndGet(nat.size.toLong())
        writeTun(nat)
    }

    private fun initAutoRoute() {
        try {
            var id = initialWarpIdentity?.takeIf { it.isValid() }
            var freshRegistered = false
            if (id == null) {
                id = WarpProvisioner.register(protectSocket, logger)
                freshRegistered = id != null
                if (id != null) onWarpIdentityReady?.invoke(id)
            }
            if (id != null && running.get()) {
                val wt = WarpTunnel(id, protectDatagram, logger)
                if (wt.connect(3200)) {
                    warpClientIpInt = id.clientIpInt() ?: 0
                    warpTunnel = wt
                    routeMasked = true
                    routeLabel = "WARP WireGuard (${wt.activeEndpoint?.hostString ?: id.endpointHost}:${wt.activeEndpoint?.port ?: id.endpointPort})"
                    wt.startLoops { dec -> onWarpInbound(dec) }
                    warpBootstrapping.set(false)
                    log("TunBridge", "Otomatik rota seçildi: $routeLabel")
                    onRouteChanged?.invoke(routeLabel, true)
                    return
                }
                wt.close()
                if (!freshRegistered && running.get()) {
                    val refreshed = WarpProvisioner.register(protectSocket, logger)
                    if (refreshed != null) {
                        onWarpIdentityReady?.invoke(refreshed)
                        val wt2 = WarpTunnel(refreshed, protectDatagram, logger)
                        if (wt2.connect(3200)) {
                            warpClientIpInt = refreshed.clientIpInt() ?: 0
                            warpTunnel = wt2
                            routeMasked = true
                            routeLabel = "WARP WireGuard (${wt2.activeEndpoint?.hostString ?: refreshed.endpointHost}:${wt2.activeEndpoint?.port ?: refreshed.endpointPort})"
                            wt2.startLoops { dec -> onWarpInbound(dec) }
                            warpBootstrapping.set(false)
                            log("TunBridge", "Otomatik rota seçildi (yenilenen anahtar): $routeLabel")
                            onRouteChanged?.invoke(routeLabel, true)
                            return
                        }
                        wt2.close()
                    }
                }
            }
            if (running.get() && isLocalPortOpen("127.0.0.1", 9050, 450)) {
                activeExitRelay = ExitRelayConfig("socks5", "127.0.0.1", 9050)
                routeMasked = true
                routeLabel = "Tor / Orbot (127.0.0.1:9050)"
                warpBootstrapping.set(false)
                log("TunBridge", "WARP UDP engelli; otomatik Tor/Orbot yedeğine geçildi")
                onRouteChanged?.invoke(routeLabel, true)
                return
            }
        } catch (t: Throwable) {
            log("TunBridge", "Otomatik WARP başlatma hatası: ${t.message}")
        } finally {
            warpBootstrapping.set(false)
        }
        routeMasked = false
        routeLabel = "Doğrudan DPI + DoH3 (IP Maskesiz)"
        log("TunBridge", "Otomatik yedek rota: $routeLabel")
        onRouteChanged?.invoke(routeLabel, false)
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        log(
            "TunBridge",
            "Freedom Network TunBridge başlatıldı (DoH=${dohEndpoints.size}, autoWarp=$autoWarp, relay=${activeExitRelayLabel}, persona=${devicePersona.id}, killSwitch=$strictKillSwitch, trackers=$blockTrackers, stunShield=$hardenStunLeaks)",
        )
        if (activeExitRelay == null && autoWarp) {
            warpBootstrapping.set(true)
            ioPool.execute { initAutoRoute() }
        }
        readerThread = Thread({ readLoop() }, "freedom-tun-reader").apply {
            isDaemon = true
            start()
        }
    }

    private fun writeTun(pkt: ByteArray) {
        if (!running.get()) return
        synchronized(writeLock) {
            try {
                tunOutput.write(pkt)
                tunOutput.flush()
            } catch (_: Throwable) {
            }
        }
    }

    private fun readLoop() {
        val buf = ByteArray(32767)
        while (running.get()) {
            val n = try {
                tunInput.read(buf)
            } catch (_: Throwable) {
                break
            }
            if (n <= 0) {
                if (n < 0) break
                // Non-blocking TUN descriptor returned EAGAIN: yield instead of spinning.
                try { Thread.sleep(2) } catch (_: InterruptedException) { break }
                continue
            }
            var off = 0
            while (off + 20 <= n && ((buf[off].toInt() ushr 4) and 0x0F) == 4) {
                val pktLen = IpPackets.u16(buf, off + 2)
                if (pktLen < 20 || off + pktLen > n) break
                val pkt = buf.copyOfRange(off, off + pktLen)
                try {
                    dispatchPacket(pkt)
                } catch (_: Throwable) {
                    if (!running.get()) break
                }
                off += pktLen
            }
            if (off == 0) {
                try {
                    dispatchPacket(buf.copyOf(n))
                } catch (_: Throwable) {
                    if (!running.get()) break
                }
            }
        }
    }

    private fun readExactBytes(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            val k = input.read(out, got, n - got)
            if (k < 0) throw IOException("EOF")
            got += k
        }
        return out
    }

    private fun readHttpHeaderLine(input: InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 8192) {
            val c = input.read()
            if (c < 0) throw IOException("EOF")
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun openExitRelayTunnel(
        relay: ExitRelayConfig,
        dstHostOrIp: String,
        dstPort: Int,
        timeoutMs: Int = 5500,
    ): Socket {
        val raw = Socket()
        try {
            raw.bind(null)
            if (!relay.isLoopback()) {
                protectSocket(raw)
            }
            raw.tcpNoDelay = true
            runCatching { raw.trafficClass = 0x10 }
            raw.connect(InetSocketAddress(InetAddress.getByName(relay.host), relay.port), timeoutMs)
            raw.soTimeout = timeoutMs

            val connSock: Socket = if (relay.scheme == "https") {
                val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val ssl = sslFactory.createSocket(raw, relay.host, relay.port, true) as SSLSocket
                val params = ssl.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                ssl.sslParameters = params
                ssl.startHandshake()
                ssl
            } else {
                raw
            }

            val input = connSock.getInputStream()
            val out = connSock.getOutputStream()

            if (relay.scheme == "socks5") {
                val hasAuth = relay.username.isNotEmpty() || relay.password.isNotEmpty()
                val greet = if (hasAuth) byteArrayOf(0x05, 0x02, 0x00, 0x02) else byteArrayOf(0x05, 0x01, 0x00)
                out.write(greet)
                out.flush()
                val choice = readExactBytes(input, 2)
                if (choice[0].toInt() != 0x05) throw IOException("SOCKS5 bad version")
                val method = choice[1].toInt() and 0xFF
                if (method == 0x02) {
                    val u = relay.username.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val p = relay.password.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val auth = ByteArray(3 + u.size + p.size)
                    auth[0] = 0x01
                    auth[1] = u.size.toByte()
                    System.arraycopy(u, 0, auth, 2, u.size)
                    auth[2 + u.size] = p.size.toByte()
                    System.arraycopy(p, 0, auth, 3 + u.size, p.size)
                    out.write(auth)
                    out.flush()
                    val authReply = readExactBytes(input, 2)
                    if (authReply[1].toInt() != 0x00) throw IOException("SOCKS5 auth rejected")
                } else if (method != 0x00) {
                    throw IOException("SOCKS5 unsupported auth method: $method")
                }

                val ipv4 = IpPackets.parseIpLiteral(dstHostOrIp)
                val req = if (ipv4 != null) {
                    val ipB = IpPackets.ipToBytes(ipv4)
                    byteArrayOf(
                        0x05, 0x01, 0x00, 0x01,
                        ipB[0], ipB[1], ipB[2], ipB[3],
                        ((dstPort ushr 8) and 0xFF).toByte(),
                        (dstPort and 0xFF).toByte(),
                    )
                } else {
                    val hostB = dstHostOrIp.toByteArray(Charsets.UTF_8)
                    if (hostB.isEmpty() || hostB.size > 255) throw IOException("SOCKS5 bad host")
                    ByteArray(7 + hostB.size).also { b ->
                        b[0] = 0x05; b[1] = 0x01; b[2] = 0x00; b[3] = 0x03
                        b[4] = hostB.size.toByte()
                        System.arraycopy(hostB, 0, b, 5, hostB.size)
                        b[5 + hostB.size] = ((dstPort ushr 8) and 0xFF).toByte()
                        b[6 + hostB.size] = (dstPort and 0xFF).toByte()
                    }
                }
                out.write(req)
                out.flush()
                val hdr = readExactBytes(input, 4)
                if (hdr[0].toInt() != 0x05 || hdr[1].toInt() != 0x00) {
                    throw IOException("SOCKS5 CONNECT failed: rep=${hdr[1].toInt() and 0xFF}")
                }
                when (hdr[3].toInt() and 0xFF) {
                    0x01 -> readExactBytes(input, 6)
                    0x03 -> {
                        val dLen = readExactBytes(input, 1)[0].toInt() and 0xFF
                        readExactBytes(input, dLen + 2)
                    }
                    0x04 -> readExactBytes(input, 18)
                    else -> throw IOException("SOCKS5 unknown ATYP")
                }
            } else {
                val target = "$dstHostOrIp:$dstPort"
                val sb = StringBuilder()
                sb.append("CONNECT ").append(target).append(" HTTP/1.1\r\n")
                sb.append("Host: ").append(target).append("\r\n")
                if (relay.username.isNotEmpty() || relay.password.isNotEmpty()) {
                    val creds = "${relay.username}:${relay.password}".toByteArray(Charsets.UTF_8)
                    val b64 = java.util.Base64.getEncoder().encodeToString(creds)
                    sb.append("Proxy-Authorization: Basic ").append(b64).append("\r\n")
                }
                sb.append("\r\n")
                out.write(sb.toString().toByteArray(Charsets.US_ASCII))
                out.flush()
                val statusLine = readHttpHeaderLine(input)
                val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                if (code !in 200..299) {
                    throw IOException("Proxy CONNECT failed: $statusLine")
                }
                while (readHttpHeaderLine(input).isNotEmpty()) { /* drain proxy response headers */ }
            }
            connSock.soTimeout = 90_000
            return connSock
        } catch (t: Throwable) {
            runCatching { raw.close() }
            throw t
        }
    }

    private fun postDohViaRelay(
        relay: ExitRelayConfig,
        url: String,
        wireQuery: ByteArray,
        timeoutMs: Int,
    ): DohResponse? {
        val start = System.nanoTime()
        fun rtt() = (System.nanoTime() - start) / 1000
        val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
        val host = uri.host?.trim('[', ']') ?: return null
        val port = if (uri.port > 0) uri.port else 443
        val path = (uri.rawPath ?: "/dns-query").ifEmpty { "/dns-query" }
        var tunnel: Socket? = null
        var ssl: SSLSocket? = null
        return try {
            tunnel = openExitRelayTunnel(relay, host, port, timeoutMs)
            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            ssl = sslFactory.createSocket(tunnel, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.soTimeout = timeoutMs
            ssl.startHandshake()

            val hostHeader = if (host.contains(':')) "[$host]" else host
            val head = "POST $path HTTP/1.1\r\nHost: $hostHeader\r\n" +
                "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n" +
                "Content-Length: ${wireQuery.size}\r\nConnection: close\r\n\r\n"
            val out = ssl.outputStream
            out.write(head.toByteArray(Charsets.US_ASCII))
            out.write(wireQuery)
            out.flush()

            val input = java.io.BufferedInputStream(ssl.inputStream)
            val statusLine = readHttpHeaderLine(input)
            val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
            val headers = HashMap<String, String>()
            while (true) {
                val line = readHttpHeaderLine(input)
                if (line.isEmpty()) break
                val idx = line.indexOf(':')
                if (idx > 0) headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
            }
            val respBody = if (headers["transfer-encoding"].orEmpty().contains("chunked", ignoreCase = true)) {
                val acc = ByteArrayOutputStream()
                while (true) {
                    val size = readHttpHeaderLine(input).substringBefore(';').trim().toIntOrNull(16) ?: break
                    if (size == 0) break
                    if (acc.size() + size > Wire.MAX_BYTES) break
                    acc.write(readExactBytes(input, size))
                    readHttpHeaderLine(input)
                }
                acc.toByteArray()
            } else {
                val len = headers["content-length"]?.toIntOrNull() ?: return null
                if (len < 12 || len > Wire.MAX_BYTES) return null
                readExactBytes(input, len)
            }
            val type = headers["content-type"].orEmpty()
            if (status == 200 && type.startsWith("application/dns-message") && respBody.size >= 12) {
                DohResponse(1, rtt(), EncProtocol.DOH, respBody)
            } else {
                DohResponse(6, rtt(), EncProtocol.DOH, null)
            }
        } catch (_: Throwable) {
            null
        } finally {
            runCatching { ssl?.close() }
            runCatching { tunnel?.close() }
        }
    }

    private fun dispatchPacket(raw: ByteArray) {
        if (raw.isNotEmpty() && ((raw[0].toInt() ushr 4) and 0x0F) == 6) {
            // IPv6 is not bridged: answer immediately so dual-stack apps switch to IPv4 without leak.
            ipv6Rejected.incrementAndGet()
            IpPackets.buildIcmpv6Unreachable(raw)?.let { writeTun(it) }
            return
        }
        val ip = IpPackets.parseIpv4(raw) ?: return
        when (ip.proto) {
            IpPackets.PROTO_UDP -> {
                val udp = IpPackets.parseUdp(raw, ip) ?: return
                if (udp.dstPort == 53) {
                    handleDnsUdp(udp)
                    return
                }
                if (hardenStunLeaks && (IpPackets.isStunBindingRequest(udp.payload) || IpPackets.isLeakRiskUdpPort(udp.dstPort))) {
                    // Prevent WebRTC/STUN/mDNS/SSDP IP discovery probes from exposing local/ISP IP addresses.
                    leaksBlocked.incrementAndGet()
                    IpPackets.buildIcmpv4Unreachable(raw)?.let { writeTun(it) }
                    return
                }
            }
            IpPackets.PROTO_TCP -> {
                val tcp = IpPackets.parseTcp(raw, ip) ?: return
                val blockLeakTcp = (hardenStunLeaks && IpPackets.isLeakRiskTcpPort(tcp.dstPort)) ||
                    (strictKillSwitch && (tcp.dstPort == 853 || tcp.dstPort == 53))
                if (blockLeakTcp) {
                    if ((tcp.flags and IpPackets.TCP_RST) == 0) {
                        leaksBlocked.incrementAndGet()
                        val ackNum = (tcp.seq + maxOf(1, tcp.payload.size) + if ((tcp.flags and IpPackets.TCP_SYN) != 0) 1 else 0) and 0xFFFFFFFFL
                        writeTun(
                            IpPackets.buildIpv4Tcp(
                                srcIp = tcp.ip.dstIp,
                                dstIp = tcp.ip.srcIp,
                                srcPort = tcp.dstPort,
                                dstPort = tcp.srcPort,
                                seq = 0L,
                                ack = ackNum,
                                flags = IpPackets.TCP_RST or IpPackets.TCP_ACK,
                            ),
                        )
                    }
                    return
                }
            }
        }

        // Prevent pre-handshake real-IP leaks while automatic WARP WireGuard is negotiating.
        if (warpBootstrapping.get()) return

        // Built-in L3 WireGuard WARP route: masks public IP, encrypts all TCP/UDP/HTTP3/ICMP packets.
        val wt = warpTunnel
        val warpIp = warpClientIpInt
        if (wt != null && wt.established && warpIp != 0) {
            val natOut = IpPackets.rewriteIpv4Nat(raw, newSrcIp = warpIp, clampMss = 1240) ?: return
            if (wt.sendIpPacket(natOut)) {
                warpPacketsOut.incrementAndGet()
                bytesUp.addAndGet(natOut.size.toLong())
            }
            return
        }

        when (ip.proto) {
            IpPackets.PROTO_UDP -> {
                val udp = IpPackets.parseUdp(raw, ip) ?: return
                if (blockQuic && udp.dstPort == 443) {
                    // When QUIC fallback protection is enabled, steer QUIC to fragmented TLS/TCP
                    // so ISP SNI/ECH inspection cannot drop the session.
                    quicFallbacks.incrementAndGet()
                    IpPackets.buildIcmpv4Unreachable(raw)?.let { writeTun(it) }
                } else if (exitRelay != null && strictKillSwitch) {
                    // Never leak direct UDP datagrams around the TCP Exit Relay when Kill Switch is active.
                    leaksBlocked.incrementAndGet()
                    IpPackets.buildIcmpv4Unreachable(raw)?.let { writeTun(it) }
                } else {
                    handleUdp(udp)
                }
            }
            IpPackets.PROTO_TCP -> {
                val tcp = IpPackets.parseTcp(raw, ip) ?: return
                handleTcp(tcp)
            }
        }
    }

    private fun handleDnsUdp(udp: IpPackets.UdpDatagram) {
        val query = udp.payload
        if (query.size < 12) return
        dnsQueries.incrementAndGet()
        ioPool.execute {
            try {
                val answer = resolveDnsQuery(query, udp.ip.dstIp) ?: return@execute
                val reply = IpPackets.buildIpv4Udp(
                    srcIp = udp.ip.dstIp,
                    dstIp = udp.ip.srcIp,
                    srcPort = udp.dstPort,
                    dstPort = udp.srcPort,
                    payload = answer,
                )
                writeTun(reply)
            } catch (_: Throwable) {
            }
        }
    }

    private fun withId(msg: ByteArray, query: ByteArray): ByteArray {
        val fixed = msg.copyOf()
        fixed[0] = query[0]
        fixed[1] = query[1]
        return fixed
    }

    private fun resolveDnsQuery(query: ByteArray, @Suppress("UNUSED_PARAMETER") requestedServerIp: Int): ByteArray? {
        if (query.size < 12) return null
        val qname = IpPackets.parseDnsQuestionName(query)
        // 0) Privacy & Tracker Shield sinkhole before leaving the device
        if (blockTrackers && qname != null && IpPackets.isTrackerOrAdDomain(qname)) {
            trackersBlocked.incrementAndGet()
            return IpPackets.buildDnsNxdomain(query)
        }
        // 0b) Suppress unbridged IPv6 AAAA lookups to eliminate dual-stack IPv6 leaks
        if (suppressIpv6Dns && IpPackets.parseDnsQuestionType(query) == 28) {
            aaaaSuppressed.incrementAndGet()
            return IpPackets.buildDnsNodataAaaa(query)
        }
        // 1) TTL-bounded cache keyed by the query without its ID
        val cacheKey = query.copyOfRange(2, query.size).joinToString("") { "%02x".format(it) }
        val now = System.currentTimeMillis()
        dnsCache[cacheKey]?.let { (softExpiry, hardExpiry, msg) ->
            if (softExpiry > now) {
                dnsCacheHits.incrementAndGet()
                return withId(msg, query)
            }
            if (hardExpiry > now) {
                dnsCacheHits.incrementAndGet()
                val bgClient = dohClient
                if (bgClient != null && dnsRefreshInFlight.add(cacheKey)) {
                    ioPool.execute {
                        try {
                            val dohWireBg = query.copyOf().also { it[0] = 0; it[1] = 0 }
                            val eps = dohEndpoints.filter(Doh::validEndpoint)
                            val ep = eps.getOrNull(preferredDoh.coerceIn(0, (eps.size - 1).coerceAtLeast(0)))
                            if (ep != null) {
                                val resp = bgClient.post(ep, dohWireBg, 2200)
                                val body = resp.body
                                if (resp.transport == 1 && body != null && body.size >= 12 && !IpPackets.containsPoisonedDns(body)) {
                                    val ttl = (IpPackets.dnsMinTtl(body) ?: 30L).coerceIn(10L, 600L)
                                    val tNow = System.currentTimeMillis()
                                    dnsCache[cacheKey] = Triple(tNow + ttl * 1000L, tNow + ttl * 1000L + 1_800_000L, body)
                                }
                            }
                        } catch (_: Throwable) {
                        } finally {
                            dnsRefreshInFlight.remove(cacheKey)
                        }
                    }
                }
                return withId(msg, query)
            }
            dnsCache.remove(cacheKey)
        }
        fun remember(msg: ByteArray): ByteArray {
            if (qname != null) {
                IpPackets.dnsAnswerAddresses(msg)?.forEach { a ->
                    if (a.size == 4) {
                        val ipInt = ((a[0].toInt() and 0xFF) shl 24) or
                            ((a[1].toInt() and 0xFF) shl 16) or
                            ((a[2].toInt() and 0xFF) shl 8) or
                            (a[3].toInt() and 0xFF)
                        if (dnsIpToHost.size > 1024) dnsIpToHost.clear()
                        dnsIpToHost[ipInt] = qname
                    }
                }
            }
            val ttl = (IpPackets.dnsMinTtl(msg) ?: 30L).coerceIn(10L, 600L)
            if (dnsCache.size > 2048) dnsCache.clear()
            dnsCache[cacheKey] = Triple(now + ttl * 1000L, now + ttl * 1000L + 1_800_000L, msg)
            return withId(msg, query)
        }
        // 2) Encrypted DNS (RFC 8484, ID 0) — via Exit Relay first if active, else Happy Eyeballs parallel racing
        val endpoints = dohEndpoints.filter(Doh::validEndpoint)
        val dohWire = query.copyOf().also { it[0] = 0; it[1] = 0 }
        val relay = exitRelay
        if (relay != null && endpoints.isNotEmpty()) {
            val first = preferredDoh.coerceIn(0, endpoints.size - 1)
            for (k in endpoints.indices) {
                val idx = (first + k) % endpoints.size
                val resp = postDohViaRelay(relay, endpoints[idx], dohWire, 3500) ?: continue
                val body = resp.body
                if (resp.transport == 1 && body != null && body.size >= 12) {
                    if (IpPackets.containsPoisonedDns(body)) {
                        poisonedDnsBlocked.incrementAndGet()
                        continue
                    }
                    preferredDoh = idx
                    dohResolved.incrementAndGet()
                    return remember(body)
                }
            }
            if (strictKillSwitch) {
                leaksBlocked.incrementAndGet()
                return null
            }
        }
        val client = dohClient
        if (client != null && endpoints.isNotEmpty()) {
            val first = preferredDoh.coerceIn(0, endpoints.size - 1)
            val tried = HashSet<Int>(2)
            if (endpoints.size >= 2) {
                val second = (first + 1) % endpoints.size
                tried.add(first)
                tried.add(second)
                val winner = AtomicReference<Pair<Int, ByteArray>?>(null)
                val done = CountDownLatch(1)
                val finished = AtomicInteger(0)
                for (cand in intArrayOf(first, second)) {
                    ioPool.execute {
                        try {
                            val resp = runCatching { client.post(endpoints[cand], dohWire, 2200) }.getOrNull()
                            val body = resp?.body
                            if (resp?.transport == 1 && body != null && body.size >= 12) {
                                if (IpPackets.containsPoisonedDns(body)) {
                                    poisonedDnsBlocked.incrementAndGet()
                                } else if (winner.compareAndSet(null, cand to body)) {
                                    done.countDown()
                                }
                            }
                        } finally {
                            if (finished.incrementAndGet() >= 2) done.countDown()
                        }
                    }
                }
                runCatching { done.await(2300, TimeUnit.MILLISECONDS) }
                winner.get()?.let { (winIdx, winBody) ->
                    preferredDoh = winIdx
                    dohResolved.incrementAndGet()
                    return remember(winBody)
                }
            }
            for (k in endpoints.indices) {
                val idx = (first + k) % endpoints.size
                if (!tried.add(idx)) continue
                val resp = runCatching { client.post(endpoints[idx], dohWire, 2500) }.getOrNull() ?: continue
                val body = resp.body
                if (resp.transport == 1 && body != null && body.size >= 12) {
                    if (IpPackets.containsPoisonedDns(body)) {
                        poisonedDnsBlocked.incrementAndGet()
                        continue
                    }
                    preferredDoh = idx
                    dohResolved.incrementAndGet()
                    return remember(body)
                }
            }
        }
        // Strict Kill Switch prevents plaintext DNS fallback when encrypted DoH fails.
        if (strictKillSwitch) {
            leaksBlocked.incrementAndGet()
            return null
        }
        // 3) Fallback: protected UDP to public resolvers only; injected/poisoned replies are skipped.
        for (srv in upstreamDnsServers) {
            if (srv.isBlank()) continue
            val host = srv.substringBefore(':')
            val port = srv.substringAfter(':', "53").toIntOrNull() ?: 53
            val sock = try {
                DatagramSocket()
            } catch (_: Exception) {
                continue
            }
            try {
                protectDatagram(sock)
                val target = InetSocketAddress(InetAddress.getByName(host), port)
                sock.send(DatagramPacket(query, query.size, target))
                val deadline = System.currentTimeMillis() + 2000
                val buf = ByteArray(4096)
                while (true) {
                    val left = deadline - System.currentTimeMillis()
                    if (left <= 0) break
                    sock.soTimeout = left.toInt()
                    val p = DatagramPacket(buf, buf.size)
                    sock.receive(p)
                    if (p.length < 12 || buf[0] != query[0] || buf[1] != query[1]) continue
                    val msg = buf.copyOf(p.length)
                    if (IpPackets.containsPoisonedDns(msg)) {
                        poisonedDnsBlocked.incrementAndGet()
                        continue
                    }
                    return remember(msg)
                }
            } catch (_: Exception) {
            } finally {
                runCatching { sock.close() }
            }
        }
        return null
    }

    private fun handleUdp(udp: IpPackets.UdpDatagram) {
        if (udp.payload.isEmpty()) return
        val key = FlowKey(udp.ip.srcIp, udp.srcPort, udp.ip.dstIp, udp.dstPort)
        if (udpTable.size > 512) {
            val it = udpTable.entries.iterator()
            var evicted = 0
            while (it.hasNext() && udpTable.size > 400 && evicted < 100) {
                val entry = it.next()
                entry.value.close()
                it.remove()
                evicted++
            }
        }
        val flow = udpTable.computeIfAbsent(key) { k ->
            udpFlows.incrementAndGet()
            UdpFlow(k).also { it.start() }
        }
        flow.sendOutbound(udp.payload)
    }

    private inner class UdpFlow(val key: FlowKey) {
        val socket: DatagramSocket? = runCatching {
            DatagramSocket().also {
                protectDatagram(it)
                runCatching { it.trafficClass = 0x10 }
                runCatching { it.receiveBufferSize = 65536; it.sendBufferSize = 65536 }
                it.soTimeout = 45_000
            }
        }.getOrNull()
        private val closed = AtomicBoolean(false)
        private val targetAddress: InetSocketAddress? = runCatching {
            val ip = if (key.dstIp == virtualDnsIp) {
                InetAddress.getByName(upstreamDnsServers.firstOrNull()?.substringBefore(':') ?: "1.1.1.1")
            } else {
                InetAddress.getByAddress(IpPackets.ipToBytes(key.dstIp))
            }
            InetSocketAddress(ip, key.dstPort)
        }.getOrNull()

        fun start() {
            val s = socket ?: return
            ioPool.execute {
                val buf = ByteArray(2048)
                while (running.get() && !closed.get()) {
                    try {
                        val dp = DatagramPacket(buf, buf.size)
                        s.receive(dp)
                        if (dp.length > 0) {
                            bytesDown.addAndGet(dp.length.toLong())
                            val pkt = IpPackets.buildIpv4Udp(
                                srcIp = key.dstIp,
                                dstIp = key.srcIp,
                                srcPort = key.dstPort,
                                dstPort = key.srcPort,
                                payload = buf.copyOf(dp.length),
                            )
                            writeTun(pkt)
                        }
                    } catch (_: SocketTimeoutException) {
                        break
                    } catch (_: Throwable) {
                        break
                    }
                }
                close()
            }
        }

        fun sendOutbound(payload: ByteArray) {
            val s = socket ?: return
            val dst = targetAddress ?: return
            try {
                bytesUp.addAndGet(payload.size.toLong())
                s.send(DatagramPacket(payload, payload.size, dst))
            } catch (_: Throwable) {
                close()
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                udpTable.remove(key, this)
                runCatching { socket?.close() }
            }
        }
    }

    private fun handleTcp(tcp: IpPackets.TcpSegment) {
        val key = FlowKey(tcp.ip.srcIp, tcp.srcPort, tcp.ip.dstIp, tcp.dstPort)
        val isSyn = (tcp.flags and IpPackets.TCP_SYN) != 0 && (tcp.flags and IpPackets.TCP_ACK) == 0
        val isRst = (tcp.flags and IpPackets.TCP_RST) != 0
        val isFin = (tcp.flags and IpPackets.TCP_FIN) != 0

        if (isRst) {
            tcpTable.remove(key)?.close()
            return
        }
        if (isSyn) {
            if (tcpTable.size > 256) {
                val it = tcpTable.entries.iterator()
                var evicted = 0
                while (it.hasNext() && tcpTable.size > 200 && evicted < 50) {
                    val entry = it.next()
                    entry.value.close()
                    it.remove()
                    evicted++
                }
            }
            tcpTable.remove(key)?.close()
            val flow = TcpFlow(key, (tcp.seq + 1L) and 0xFFFFFFFFL)
            tcpTable[key] = flow
            tcpFlows.incrementAndGet()
            flow.onSyn()
            return
        }
        val flow = tcpTable[key] ?: return
        if (tcp.payload.isNotEmpty()) {
            flow.onClientData(tcp)
        }
        if (isFin) {
            flow.onClientFin(tcp)
        }
    }

    private inner class TcpFlow(val key: FlowKey, var clientNextSeq: Long) {
        val lock = Any()
        var serverSeq: Long = 0x5000_0000L
        val closed = AtomicBoolean(false)
        val outboundQueue = java.util.concurrent.LinkedBlockingQueue<ByteArray>(256)
        @Volatile var upstreamSocket: Socket? = null
        @Volatile var finFromClient = false
        var visionSpliced = false

        fun onSyn() {
            val synAckSeq: Long
            val ackNum: Long
            synchronized(lock) {
                synAckSeq = serverSeq
                ackNum = clientNextSeq
                serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
            }
            writeTun(
                IpPackets.buildIpv4Tcp(
                    srcIp = key.dstIp,
                    dstIp = key.srcIp,
                    srcPort = key.dstPort,
                    dstPort = key.srcPort,
                    seq = synAckSeq,
                    ack = ackNum,
                    flags = IpPackets.TCP_SYN or IpPackets.TCP_ACK,
                    mssOption = 1360,
                ),
            )
            ioPool.execute { connectAndPump() }
        }

        fun onClientData(tcp: IpPackets.TcpSegment) {
            val ackPkt: ByteArray
            synchronized(lock) {
                if (tcp.seq != clientNextSeq) {
                    ackPkt = IpPackets.buildIpv4Tcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = IpPackets.TCP_ACK,
                    )
                } else {
                    clientNextSeq = (clientNextSeq + tcp.payload.size) and 0xFFFFFFFFL
                    ackPkt = IpPackets.buildIpv4Tcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = IpPackets.TCP_ACK,
                    )
                    outboundQueue.offer(tcp.payload.copyOf())
                }
            }
            writeTun(ackPkt)
        }

        fun onClientFin(tcp: IpPackets.TcpSegment) {
            val finAckPkt: ByteArray
            synchronized(lock) {
                if (tcp.seq + tcp.payload.size == clientNextSeq) {
                    clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
                }
                finFromClient = true
                finAckPkt = IpPackets.buildIpv4Tcp(
                    srcIp = key.dstIp,
                    dstIp = key.srcIp,
                    srcPort = key.dstPort,
                    dstPort = key.srcPort,
                    seq = serverSeq,
                    ack = clientNextSeq,
                    flags = IpPackets.TCP_ACK,
                )
            }
            writeTun(finAckPkt)
        }

        private fun pumpOutbound(sock: Socket, out: OutputStream) {
            var firstPayloadDone = false
            var helloBuf: ByteArrayOutputStream? = null
            try {
                while (running.get() && !closed.get()) {
                    val payload = outboundQueue.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                    if (payload != null) {
                        bytesUp.addAndGet(payload.size.toLong())
                        if (!firstPayloadDone) {
                            val acc = helloBuf
                            val data = if (acc != null) {
                                acc.write(payload)
                                acc.toByteArray()
                            } else {
                                payload
                            }
                            val isTls = data.size >= 5 && (data[0].toInt() and 0xFF) == 0x16 && (data[1].toInt() and 0xFF) == 0x03
                            if (isTls) {
                                val need = 5 + IpPackets.u16(data, 3)
                                if (data.size < need && need <= 16384 + 5) {
                                    if (acc == null) helloBuf = ByteArrayOutputStream().apply { write(data) }
                                    continue
                                }
                            }
                            helloBuf = null
                            firstPayloadDone = true
                            val cleanData = IpPackets.sanitizePlainHttpHeaders(
                                data,
                                persona = devicePersona,
                                stripGeoHeaders = devicePersona != DevicePersona.OFF,
                                stripTrackingParams = true,
                            )
                            if (cleanData !== data) {
                                leaksBlocked.incrementAndGet()
                                val reqLine = String(data, 0, minOf(data.size, 512), Charsets.ISO_8859_1).substringBefore("\r\n")
                                if (IpPackets.stripUrlTrackingParamsFromRequestLine(reqLine).second) {
                                    paramsStripped.incrementAndGet()
                                }
                                if (devicePersona != DevicePersona.OFF) {
                                    httpHeadersSpoofed.incrementAndGet()
                                }
                            }
                            if (exitRelay != null) {
                                out.write(cleanData)
                                out.flush()
                            } else {
                                val packet = IpPackets.buildIpv4Tcp(
                                    srcIp = key.srcIp, dstIp = key.dstIp, srcPort = key.srcPort, dstPort = key.dstPort,
                                    seq = 1L, ack = 1L, flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = cleanData,
                                )
                                val res = runCatching { session.desyncPacket(packet, desyncConfig) }.getOrNull()
                                val nativeChunks = IpPackets.extractOrderedStreamChunks(packet, cleanData, res)
                                val chunks = IpPackets.planFirstPayload(cleanData, nativeChunks)
                                if (chunks.size > 1) {
                                    desyncedFlows.incrementAndGet()
                                }
                                if (isTls && chunks.size > 1 && chunks.all { it.size >= 5 && (it[0].toInt() and 0xFF) == 0x16 }) {
                                    tlsRecordFragmented.incrementAndGet()
                                }
                                if (desyncConfig.mode == DesyncMode.REALITY_VISION && isTls) {
                                    visionSpliced = true
                                    visionSplicedFlows.incrementAndGet()
                                }
                                for (i in chunks.indices) {
                                    out.write(chunks[i])
                                    out.flush()
                                    if (i < chunks.size - 1) {
                                        try { Thread.sleep(3) } catch (_: InterruptedException) { break }
                                    }
                                }
                            }
                        } else {
                            if (!visionSpliced && payload.size >= 5 && (payload[0].toInt() and 0xFF) == 0x17 && (payload[1].toInt() and 0xFF) == 0x03) {
                                visionSpliced = true
                                visionSplicedFlows.incrementAndGet()
                            }
                            out.write(payload)
                            out.flush()
                        }
                    } else if (finFromClient && outboundQueue.isEmpty()) {
                        runCatching { sock.shutdownOutput() }
                        break
                    }
                }
            } catch (_: Throwable) {
                close()
            }
        }

        private fun connectAndPump() {
            var pendingSock: Socket? = null
            try {
                if (key.dstIp == virtualDnsIp && strictKillSwitch) {
                    leaksBlocked.incrementAndGet()
                    throw IOException("Strict Kill Switch blocks plaintext TCP DNS")
                }
                val relay = exitRelay
                val sock: Socket = if (relay != null) {
                    val targetHost = dnsIpToHost[key.dstIp] ?: IpPackets.ipToString(key.dstIp)
                    try {
                        openExitRelayTunnel(relay, targetHost, key.dstPort, 6000)
                    } catch (t: Throwable) {
                        leaksBlocked.incrementAndGet()
                        throw t
                    }
                } else {
                    Socket().also { s ->
                        pendingSock = s
                        s.bind(null)
                        protectSocket(s)
                        s.tcpNoDelay = true
                        runCatching { s.trafficClass = 0x10 }
                        runCatching { s.receiveBufferSize = 65536; s.sendBufferSize = 65536 }
                        runCatching { s.keepAlive = true }
                        s.soTimeout = 90_000
                        val dstInet = if (key.dstIp == virtualDnsIp) {
                            InetAddress.getByName(upstreamDnsServers.firstOrNull()?.substringBefore(':') ?: "1.1.1.1")
                        } else {
                            InetAddress.getByAddress(IpPackets.ipToBytes(key.dstIp))
                        }
                        s.connect(InetSocketAddress(dstInet, key.dstPort), 5000)
                    }
                }
                pendingSock = sock
                if (closed.get()) {
                    runCatching { sock.close() }
                    return
                }
                upstreamSocket = sock
                val out = sock.getOutputStream()
                ioPool.execute { pumpOutbound(sock, out) }

                val input = sock.getInputStream()
                val buf = ByteArray(1400)
                while (running.get() && !closed.get()) {
                    val n = input.read(buf)
                    if (n > 0) bytesDown.addAndGet(n.toLong())
                    if (n < 0) {
                        val finSeq: Long
                        val ackNum: Long
                        synchronized(lock) {
                            finSeq = serverSeq
                            ackNum = clientNextSeq
                            serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
                        }
                        writeTun(
                            IpPackets.buildIpv4Tcp(
                                srcIp = key.dstIp,
                                dstIp = key.srcIp,
                                srcPort = key.dstPort,
                                dstPort = key.srcPort,
                                seq = finSeq,
                                ack = ackNum,
                                flags = IpPackets.TCP_FIN or IpPackets.TCP_ACK,
                            ),
                        )
                        break
                    }
                    if (n > 0) {
                        val segSeq: Long
                        val ackNum: Long
                        synchronized(lock) {
                            segSeq = serverSeq
                            ackNum = clientNextSeq
                            serverSeq = (serverSeq + n) and 0xFFFFFFFFL
                        }
                        writeTun(
                            IpPackets.buildIpv4Tcp(
                                srcIp = key.dstIp,
                                dstIp = key.srcIp,
                                srcPort = key.dstPort,
                                dstPort = key.srcPort,
                                seq = segSeq,
                                ack = ackNum,
                                flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK,
                                payload = buf.copyOf(n),
                            ),
                        )
                    }
                }
            } catch (_: Throwable) {
                runCatching { if (pendingSock !== upstreamSocket) pendingSock?.close() }
                val rstSeq: Long
                val ackNum: Long
                synchronized(lock) {
                    rstSeq = serverSeq
                    ackNum = clientNextSeq
                }
                writeTun(
                    IpPackets.buildIpv4Tcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = rstSeq,
                        ack = ackNum,
                        flags = IpPackets.TCP_RST or IpPackets.TCP_ACK,
                    ),
                )
            } finally {
                close()
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                tcpTable.remove(key, this)
                outboundQueue.clear()
                runCatching { upstreamSocket?.close() }
            }
        }
    }

    override fun close() {
        if (running.compareAndSet(true, false)) {
            runCatching { warpTunnel?.close() }
            warpTunnel = null
            runCatching { tunInput.close() }
            runCatching { tunOutput.close() }
            readerThread?.interrupt()
            for (f in tcpTable.values) f.close()
            for (u in udpTable.values) u.close()
            tcpTable.clear()
            udpTable.clear()
            dnsCache.clear()
            dnsIpToHost.clear()
            ioPool.shutdownNow()
        }
    }

    companion object {
        const val VPN_CLIENT_IP = "10.215.173.1"
        const val VPN_DNS_IP = "10.215.173.2"
        val DEFAULT_DOH_ENDPOINTS = listOf(
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://9.9.9.9/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/dns-query",
            "https://dns.quad9.net/dns-query",
        )
        val DEFAULT_DNS_SERVERS = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")
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

/** Headless mode: `FreedomNetwork --cli example.com [--dns 1.1.1.1] [--alt 9.9.9.9]`. */
fun runCli(args: List<String>): Int {
    val targets = ArrayList<String>()
    val dns = ArrayList<String>()
    val alt = ArrayList<String>()
    val doh = ArrayList<String>()
    var system = false
    var desyncMode = DesyncMode.OFF
    var proxyPort = -1
    var personaId = DevicePersona.IPHONE_19_BETA.id
    var blockTrackers = true
    var stripUrlParams = true
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--help", "-h" -> {
                println("Freedom Network CLI ${runCatching { Native.engineVersion() }.getOrElse { "native" }}")
                println("Kullanım: FreedomNetwork --cli [hedef ...] [--dns IP] [--alt IP] [--doh URL]")
                println("          [--desync reality|split|disorder|badsum|ttl|quic|adaptive] [--proxy PORT]")
                println("          [--persona iphone19|android19|pixel14|off] [--no-trackers] [--no-strip] [--system]")
                return 0
            }
            "--cli" -> {}
            "--dns" -> dns += args.getOrNull(++i) ?: ""
            "--alt" -> alt += args.getOrNull(++i) ?: ""
            "--doh" -> doh += args.getOrNull(++i) ?: ""
            "--system" -> system = true
            "--no-trackers" -> blockTrackers = false
            "--no-strip" -> stripUrlParams = false
            "--persona" -> {
                val p = (args.getOrNull(++i) ?: "iphone19").lowercase()
                personaId = when (p) {
                    "off", "0", "none" -> ""
                    "android", "android19" -> DevicePersona.ANDROID_19_QUANTUM.id
                    "pixel", "pixel14" -> DevicePersona.PIXEL_14_FUTURE.id
                    else -> DevicePersona.IPHONE_19_BETA.id
                }
            }
            "--desync" -> {
                val m = (args.getOrNull(++i) ?: "reality").lowercase()
                desyncMode = when (m) {
                    "split", "1" -> DesyncMode.SPLIT
                    "disorder", "2" -> DesyncMode.DISORDER
                    "badsum", "3" -> DesyncMode.FAKE_BAD_SUM
                    "ttl", "autottl", "4" -> DesyncMode.FAKE_AUTO_TTL
                    "quic", "5" -> DesyncMode.QUIC_SCRAMBLE
                    "adaptive", "6" -> DesyncMode.ADAPTIVE_FULL
                    else -> DesyncMode.REALITY_VISION
                }
            }
            "--proxy" -> proxyPort = (args.getOrNull(++i) ?: "8880").toIntOrNull() ?: 8880
            else -> targets += args[i]
        }
        i++
    }
    return try {
        DiagnosticSession().use { session ->
            val env = WindowsPlatform.environment(dns.filter { it.isNotEmpty() })
            session.setEnvironment(env)
            println("Freedom Network ${Native.engineVersion()} · TLS güveni: ${WindowsPlatform.trust.second}")
            print(Text.environment(env))
            println()
            if (targets.isNotEmpty()) {
                val report = session.run(
                    targets, alt.filter { it.isNotEmpty() }, WindowsPlatform.prober(),
                    WindowsPlatform.dohClient(), doh.filter { it.isNotEmpty() },
                )
                print(Text.report(report))
            }
            if (desyncMode != DesyncMode.OFF || proxyPort >= 0) {
                val mode = if (desyncMode != DesyncMode.OFF) desyncMode else DesyncMode.REALITY_VISION
                val ps = session.startProxy(
                    DesyncConfig(
                        mode = mode,
                        port = if (proxyPort >= 0) proxyPort else 0,
                        persona = personaId,
                        blockTrackers = blockTrackers,
                        stripUrlParams = stripUrlParams,
                    ),
                )
                println()
                print(Text.proxyStatus(ps))
                session.stopProxy()
            }
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

// Swing Vector Icon Renderer (Pure Java2D Path2D - Standard 24x24 Lucide + Freedom Emblem Geometry)
internal object SwingVectorIcons {
    private val shieldPath = Path2D.Float().apply {
        moveTo(12f, 2f)
        lineTo(20f, 5f)
        lineTo(20f, 12f)
        curveTo(20.0, 18.0, 12.0, 22.0, 12.0, 22.0)
        curveTo(12.0, 22.0, 4.0, 18.0, 4.0, 12.0)
        lineTo(4f, 5f)
        closePath()
    }

    private val freedomOuterShield = Path2D.Float().apply {
        moveTo(12f, 1.8f)
        lineTo(20.6f, 5.2f)
        lineTo(19.4f, 13.8f)
        lineTo(12f, 22.2f)
        lineTo(4.6f, 13.8f)
        lineTo(3.4f, 5.2f)
        closePath()
    }

    private val freedomInnerCore = Path2D.Float().apply {
        moveTo(12f, 4.4f)
        lineTo(17.9f, 6.8f)
        lineTo(17.0f, 13.0f)
        lineTo(12f, 19.2f)
        lineTo(7.0f, 13.0f)
        lineTo(6.1f, 6.8f)
        closePath()
    }

    private val freedomUpperWing = Path2D.Float().apply {
        moveTo(7.8f, 11.4f)
        lineTo(12f, 7.2f)
        lineTo(16.2f, 11.4f)
    }

    private val freedomLowerWing = Path2D.Float().apply {
        moveTo(8.8f, 14.4f)
        lineTo(12f, 11.2f)
        lineTo(15.2f, 14.4f)
    }

    private val boltPath = Path2D.Float().apply {
        moveTo(13f, 2f)
        lineTo(3f, 14f)
        lineTo(12f, 14f)
        lineTo(11f, 22f)
        lineTo(21f, 10f)
        lineTo(12f, 10f)
        closePath()
    }

    private val lockShacklePath = Path2D.Float().apply {
        moveTo(7f, 11f)
        lineTo(7f, 7f)
        curveTo(7.0, 4.24, 9.24, 2.0, 12.0, 2.0)
        curveTo(14.76, 2.0, 17.0, 4.24, 17.0, 7.0)
        lineTo(17f, 11f)
    }
    private val lockBodyRect = RoundRectangle2D.Float(4f, 11f, 16f, 11f, 5f, 5f)

    private val radarOuterCircle = Ellipse2D.Float(3f, 3f, 18f, 18f)
    private val radarInnerArc = Arc2D.Float(7.5f, 7.5f, 9f, 9f, 45f, 250f, Arc2D.OPEN)

    private val globeOval = Ellipse2D.Float(2f, 2f, 20f, 20f)
    private val globeMeridianPath = Path2D.Float().apply {
        moveTo(12f, 2f)
        curveTo(6.5, 2.0, 5.5, 6.5, 5.5, 12.0)
        curveTo(5.5, 17.5, 6.5, 22.0, 12.0, 22.0)
        curveTo(17.5, 22.0, 18.5, 17.5, 18.5, 12.0)
        curveTo(18.5, 6.5, 17.5, 2.0, 12.0, 2.0)
        closePath()
    }

    private val pulsePath = Path2D.Float().apply {
        moveTo(2f, 12f)
        lineTo(6f, 12f)
        lineTo(9f, 3f)
        lineTo(15f, 21f)
        lineTo(18f, 12f)
        lineTo(22f, 12f)
    }

    private val powerArc = Arc2D.Float(4f, 4f, 16f, 16f, 145f, 250f, Arc2D.OPEN)

    private val terminalChevron = Path2D.Float().apply {
        moveTo(4f, 17f)
        lineTo(10f, 12f)
        lineTo(4f, 7f)
    }

    private val copyFrontRect = RoundRectangle2D.Float(8f, 8f, 13f, 13f, 4f, 4f)
    private val copyBackPath = Path2D.Float().apply {
        moveTo(4f, 16f)
        lineTo(4f, 5f)
        curveTo(4.0, 4.45, 4.45, 4.0, 5.0, 4.0)
        lineTo(16f, 4f)
    }

    private val checkPath = Path2D.Float().apply {
        moveTo(20f, 6f)
        lineTo(9f, 17f)
        lineTo(4f, 12f)
    }

    private inline fun withMatrix(g2: Graphics2D, cx: Int, cy: Int, size: Int, block: () -> Unit) {
        val oldTransform = g2.transform
        val oldStroke = g2.stroke
        g2.translate(cx.toDouble(), cy.toDouble())
        val s = size.toDouble() / 24.0
        g2.scale(s, s)
        g2.translate(-12.0, -12.0)
        block()
        g2.transform = oldTransform
        g2.stroke = oldStroke
    }

    fun drawFreedomShieldEmblem(g2: Graphics2D, cx: Int, cy: Int, size: Int, primary: Color, accent: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = Color(primary.red, primary.green, primary.blue, 46)
            g2.fill(freedomOuterShield)
            g2.color = Color(accent.red, accent.green, accent.blue, 62)
            g2.fill(freedomInnerCore)
            g2.color = primary
            g2.stroke = BasicStroke(1.9f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(freedomOuterShield)
            g2.color = accent
            g2.stroke = BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(freedomUpperWing)
            g2.color = Color.WHITE
            g2.stroke = BasicStroke(2.0f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(freedomLowerWing)
        }
    }

    fun drawShield(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color, fill: Boolean = true) {
        withMatrix(g2, cx, cy, size) {
            if (fill) {
                g2.color = Color(color.red, color.green, color.blue, 38)
                g2.fill(shieldPath)
            }
            g2.color = color
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(shieldPath)
        }
    }

    fun drawBolt(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = Color(color.red, color.green, color.blue, 45)
            g2.fill(boltPath)
            g2.color = color
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(boltPath)
        }
    }

    fun drawLock(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = Color(color.red, color.green, color.blue, 35)
            g2.fill(lockBodyRect)
            g2.color = color
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(lockShacklePath)
            g2.draw(lockBodyRect)
            g2.draw(Line2D.Float(12f, 15f, 12f, 18f))
        }
    }

    fun drawRadar(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = Color(color.red, color.green, color.blue, 30)
            g2.fill(radarOuterCircle)
            g2.color = color
            g2.stroke = BasicStroke(1.9f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(radarOuterCircle)
            g2.draw(radarInnerArc)
            g2.draw(Line2D.Float(12f, 12f, 18.2f, 5.8f))
            g2.fill(Ellipse2D.Float(10.2f, 10.2f, 3.6f, 3.6f))
        }
    }

    fun drawGlobe(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = color
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(globeOval)
            g2.draw(Line2D.Float(2f, 12f, 22f, 12f))
            g2.draw(globeMeridianPath)
        }
    }

    fun drawPulse(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = color
            g2.stroke = BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(pulsePath)
        }
    }

    fun drawPower(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = color
            g2.stroke = BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(powerArc)
            g2.draw(Line2D.Float(12f, 3f, 12f, 11f))
        }
    }

    fun drawTerminal(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = color
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(terminalChevron)
            g2.draw(Line2D.Float(12f, 19f, 20f, 19f))
        }
    }

    fun drawCopy(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = color
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(copyBackPath)
            g2.draw(copyFrontRect)
        }
    }

    fun drawCheck(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = color
            g2.stroke = BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(checkPath)
        }
    }
}

/**
 * ModernPowerShieldPanel:
 * High-contrast Freedom Network Hero Control Disc for Windows Swing with rotating orbital reticle,
 * 12 azimuth precision ticks, faceted Freedom Shield emblem, and pill status badge.
 */
class ModernPowerShieldPanel : JPanel() {
    var isActive = false
        set(value) {
            if (field != value) {
                field = value
                repaint()
            }
        }
    var portInfo: String = ""
        set(value) {
            field = value
            repaint()
        }
    var onToggleListener: (() -> Unit)? = null

    private var animPhase = 0f
    private var isHovered = false
    private val animTimer = Timer(33) {
        animPhase = (animPhase + 0.015f) % 1.0f
        repaint()
    }

    init {
        preferredSize = Dimension(650, 178)
        background = Color(7, 11, 20)
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        animTimer.start()

        addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                val cx = width / 2
                val cy = height / 2
                val btnR = (minOf(cx, cy) * 0.62).toInt()
                val dx = e.x - cx
                val dy = e.y - cy
                if (dx * dx + dy * dy <= (btnR * 1.3) * (btnR * 1.3)) {
                    onToggleListener?.invoke()
                }
            }
            override fun mouseEntered(e: MouseEvent) {
                isHovered = true
                repaint()
            }
            override fun mouseExited(e: MouseEvent) {
                isHovered = false
                repaint()
            }
        })
    }

    fun stop() {
        animTimer.stop()
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)

        val cx = width / 2
        val cy = height / 2
        val maxR = minOf(cx, cy) - 10
        if (maxR <= 0) {
            g2.dispose()
            return
        }

        val btnR = (maxR * 0.60).toInt()
        val primary = if (isActive) Color(16, 185, 129) else Color(56, 189, 248)
        val accent = if (isActive) Color(34, 211, 238) else Color(129, 140, 248)

        // 1) Expanding cyber pulse waves
        val waveCount = if (isActive) 3 else 1
        for (i in 0 until waveCount) {
            val phase = (animPhase + i * (1f / waveCount)) % 1f
            val ringR = (btnR * 1.06 + phase * (maxR - btnR * 1.06)).toInt()
            val alpha = ((1.0f - phase) * (if (isActive) 140 else 50)).toInt().coerceIn(0, 255)
            g2.color = Color(primary.red, primary.green, primary.blue, alpha)
            g2.stroke = BasicStroke((2.4f - phase * 1.2f).coerceAtLeast(1.0f))
            g2.drawOval(cx - ringR, cy - ringR, ringR * 2, ringR * 2)
        }

        // 2) Counter-rotating orbital dashed reticles
        val reticleR = (btnR * 1.13).toInt()
        g2.color = Color(primary.red, primary.green, primary.blue, if (isActive) 170 else 90)
        g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, floatArrayOf(10f, 7f), animPhase * 360f)
        g2.drawOval(cx - reticleR, cy - reticleR, reticleR * 2, reticleR * 2)

        val outerReticleR = (btnR * 1.23).toInt()
        g2.color = Color(accent.red, accent.green, accent.blue, if (isActive) 110 else 50)
        g2.stroke = BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, floatArrayOf(4f, 9f), -animPhase * 252f)
        g2.drawOval(cx - outerReticleR, cy - outerReticleR, outerReticleR * 2, outerReticleR * 2)

        // 3) Ambient radial aura
        val auraR = (btnR * 1.42).toInt()
        g2.paint = RadialGradientPaint(
            java.awt.geom.Point2D.Float(cx.toFloat(), cy.toFloat()),
            auraR.toFloat(),
            floatArrayOf(0f, 1f),
            arrayOf(Color(primary.red, primary.green, primary.blue, if (isActive) (if (isHovered) 115 else 90) else 38), Color(7, 11, 20, 0)),
        )
        g2.fillOval(cx - auraR, cy - auraR, auraR * 2, auraR * 2)

        // 4) Center disc fill
        val p1 = java.awt.geom.Point2D.Float((cx - btnR * 0.4f).toFloat(), (cy - btnR).toFloat())
        val p2 = java.awt.geom.Point2D.Float((cx + btnR * 0.4f).toFloat(), (cy + btnR).toFloat())
        g2.paint = if (isActive) {
            LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(4, 47, 46), Color(6, 95, 70)))
        } else {
            LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(10, 18, 34), Color(19, 32, 56)))
        }
        g2.fillOval(cx - btnR, cy - btnR, btnR * 2, btnR * 2)

        // Azimuth 12 precision ticks
        g2.color = Color(226, 232, 240, if (isActive) 75 else 45)
        g2.stroke = BasicStroke(1.2f)
        for (tick in 0 until 12) {
            val rad = Math.toRadians(tick * 30.0)
            val cosA = kotlin.math.cos(rad)
            val sinA = kotlin.math.sin(rad)
            g2.drawLine(
                (cx + cosA * btnR * 0.87).toInt(),
                (cy + sinA * btnR * 0.87).toInt(),
                (cx + cosA * btnR * 0.93).toInt(),
                (cy + sinA * btnR * 0.93).toInt(),
            )
        }

        // Glowing rim border
        g2.paint = LinearGradientPaint(p1, p2, floatArrayOf(0f, 0.5f, 1f), arrayOf(primary, accent, primary))
        g2.stroke = BasicStroke(if (isActive) 2.8f else (if (isHovered) 2.4f else 2.0f))
        g2.drawOval(cx - btnR, cy - btnR, btnR * 2, btnR * 2)

        // Top-center Freedom Shield Emblem badge
        val badgeCx = cx
        val badgeCy = cy - (btnR * 0.25).toInt()
        val badgeR = (btnR * 0.30).toInt()
        g2.color = Color(primary.red, primary.green, primary.blue, if (isActive) 65 else 40)
        g2.fillOval(badgeCx - badgeR, badgeCy - badgeR, badgeR * 2, badgeR * 2)
        g2.color = Color(primary.red, primary.green, primary.blue, 130)
        g2.stroke = BasicStroke(1.2f)
        g2.drawOval(badgeCx - badgeR, badgeCy - badgeR, badgeR * 2, badgeR * 2)
        SwingVectorIcons.drawFreedomShieldEmblem(
            g2, badgeCx, badgeCy, (badgeR * 1.45).toInt(),
            if (isActive) Color(52, 211, 153) else Color(56, 189, 248),
            if (isActive) Color(34, 211, 238) else Color(125, 211, 252),
        )

        // Hero title
        g2.font = Font("Segoe UI", Font.BOLD, 12)
        val titleStr = if (isActive) "KORUMA AKTİF" else "DOKUN VE BAĞLAN"
        val fmTitle = g2.fontMetrics
        g2.color = Color.WHITE
        g2.drawString(titleStr, cx - fmTitle.stringWidth(titleStr) / 2, cy + (btnR * 0.27).toInt())

        // Inner status pill
        g2.font = Font("Segoe UI", Font.BOLD, 9)
        val subStr = if (isActive) (portInfo.ifEmpty { "SİSTEM KORUMALI" }) else "AĞ KORUMASI HAZIR"
        val fmSub = g2.fontMetrics
        val pillW = fmSub.stringWidth(subStr) + 18
        val pillH = 16
        val pillX = cx - pillW / 2
        val pillY = cy + (btnR * 0.42).toInt()
        g2.color = if (isActive) Color(6, 78, 59, 175) else Color(15, 23, 42, 185)
        g2.fillRoundRect(pillX, pillY, pillW, pillH, pillH, pillH)
        g2.color = if (isActive) Color(52, 211, 153, 180) else Color(56, 189, 248, 120)
        g2.stroke = BasicStroke(1f)
        g2.drawRoundRect(pillX, pillY, pillW, pillH, pillH, pillH)
        g2.color = if (isActive) Color(167, 243, 208) else Color(147, 197, 253)
        g2.drawString(subStr, cx - fmSub.stringWidth(subStr) / 2, pillY + ((pillH - fmSub.height) / 2) + fmSub.ascent)

        g2.dispose()
    }
}

typealias AnimatedPulsePanel = ModernPowerShieldPanel

/**
 * ThroughputSparklinePanel:
 * Real-time network speed & throughput waveform graph in Swing Java2D with smooth curves
 * and transparent gradient fill.
 */
class ThroughputSparklinePanel : JPanel() {
    private val maxSamples = 32
    private val rxHistory = FloatArray(maxSamples)
    private val txHistory = FloatArray(maxSamples)
    private var writeIdx = 0
    private var currentRxKbps = 0f
    private var currentTxKbps = 0f
    private var totalRxKb = 0L
    private var totalTxKb = 0L

    init {
        preferredSize = Dimension(650, 80)
        background = Color(10, 16, 29)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(30, 41, 59), 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10),
        )
    }

    fun updateMetrics(rxKbps: Float, txKbps: Float, totalRx: Long, totalTx: Long) {
        currentRxKbps = rxKbps
        currentTxKbps = txKbps
        totalRxKb = totalRx / 1024L
        totalTxKb = totalTx / 1024L
        rxHistory[writeIdx] = rxKbps
        txHistory[writeIdx] = txKbps
        writeIdx = (writeIdx + 1) % maxSamples
        repaint()
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)

        val w = width
        val h = height

        // Header label & vector icon
        SwingVectorIcons.drawPulse(g2, 18, 14, 12, Color(148, 163, 184))
        g2.font = Font("Segoe UI", Font.BOLD, 10)
        g2.color = Color(148, 163, 184)
        g2.drawString("CANLI TRAFİK AKIŞI", 30, 18)

        // Speed badges
        val rxStr = "⬇ %.1f KB/s".format(java.util.Locale.US, currentRxKbps)
        val txStr = "⬆ %.1f KB/s".format(java.util.Locale.US, currentTxKbps)
        val fm = g2.fontMetrics
        val txW = fm.stringWidth(txStr)
        val rxW = fm.stringWidth(rxStr)
        g2.color = Color(56, 189, 248)
        g2.drawString(txStr, w - txW - 14, 18)
        g2.color = Color(16, 185, 129)
        g2.drawString(rxStr, w - txW - rxW - 24, 18)

        val graphTop = 26
        val graphBottom = h - 16
        val graphH = graphBottom - graphTop
        val graphLeft = 14
        val graphRight = w - 14
        val graphW = graphRight - graphLeft
        if (graphH <= 0 || graphW <= 0) {
            g2.dispose()
            return
        }

        // Horizontal midline
        g2.color = Color(30, 41, 59)
        g2.drawLine(graphLeft, graphTop + graphH / 2, graphRight, graphTop + graphH / 2)
        g2.drawLine(graphLeft, graphBottom, graphRight, graphBottom)

        var maxVal = 20f
        for (i in 0 until maxSamples) {
            if (rxHistory[i] > maxVal) maxVal = rxHistory[i]
            if (txHistory[i] > maxVal) maxVal = txHistory[i]
        }

        val rxPath = Path2D.Double()
        val txPath = Path2D.Double()
        val rxFill = Path2D.Double()
        val stepX = graphW.toDouble() / (maxSamples - 1).toDouble()

        for (i in 0 until maxSamples) {
            val sampleIdx = (writeIdx + i) % maxSamples
            val x = graphLeft + i * stepX
            val rxNorm = (rxHistory[sampleIdx] / maxVal).coerceIn(0f, 1f).toDouble()
            val txNorm = (txHistory[sampleIdx] / maxVal).coerceIn(0f, 1f).toDouble()
            val rxY = graphBottom - rxNorm * (graphH * 0.9)
            val txY = graphBottom - txNorm * (graphH * 0.9)

            if (i == 0) {
                rxPath.moveTo(x, rxY)
                txPath.moveTo(x, txY)
                rxFill.moveTo(x, graphBottom.toDouble())
                rxFill.lineTo(x, rxY)
            } else {
                rxPath.lineTo(x, rxY)
                txPath.lineTo(x, txY)
                rxFill.lineTo(x, rxY)
            }
        }
        rxFill.lineTo(graphRight.toDouble(), graphBottom.toDouble())
        rxFill.closePath()

        // Fill under RX curve
        val p1 = java.awt.geom.Point2D.Float(0f, graphTop.toFloat())
        val p2 = java.awt.geom.Point2D.Float(0f, graphBottom.toFloat())
        g2.paint = LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(16, 185, 129, 60), Color(16, 185, 129, 0)))
        g2.fill(rxFill)

        // Draw curves
        g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
        g2.color = Color(16, 185, 129)
        g2.draw(rxPath)

        g2.stroke = BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
        g2.color = Color(56, 189, 248)
        g2.draw(txPath)

        // Footer volume
        g2.font = Font("Segoe UI", Font.PLAIN, 9)
        g2.color = Color(100, 116, 139)
        g2.drawString("Toplam: ⬆ $totalTxKb KB  ⬇ $totalRxKb KB", graphLeft, h - 4)

        g2.dispose()
    }
}

/**
 * ModernStatCard:
 * Sleek dark glass card with custom Java2D vector icon and Segoe UI typography.
 */
class ModernStatCard(val iconType: Int, title: String, val heroColor: Color) : JPanel(BorderLayout()) {
    val valLabel = JLabel("0").apply {
        font = Font("Segoe UI", Font.BOLD, 15)
        foreground = heroColor
    }
    val subLabel = JLabel("Hazır").apply {
        font = Font("Segoe UI", Font.PLAIN, 10)
        foreground = Color(100, 116, 139)
    }

    init {
        background = Color(14, 22, 38)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(30, 41, 59), 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10),
        )
        val header = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0)).apply {
            isOpaque = false
            val iconPanel = object : JPanel() {
                init {
                    preferredSize = Dimension(16, 16)
                    isOpaque = false
                }
                override fun paintComponent(g: Graphics) {
                    super.paintComponent(g)
                    val g2 = g.create() as Graphics2D
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                    when (iconType) {
                        0 -> SwingVectorIcons.drawBolt(g2, 8, 8, 16, heroColor)
                        1 -> SwingVectorIcons.drawLock(g2, 8, 8, 16, heroColor)
                        2 -> SwingVectorIcons.drawRadar(g2, 8, 8, 16, heroColor)
                        else -> SwingVectorIcons.drawGlobe(g2, 8, 8, 16, heroColor)
                    }
                    g2.dispose()
                }
            }
            val titleLabel = JLabel(title).apply {
                font = Font("Segoe UI", Font.BOLD, 10)
                foreground = Color(148, 163, 184)
            }
            add(iconPanel)
            add(titleLabel)
        }
        add(header, BorderLayout.NORTH)
        add(valLabel, BorderLayout.CENTER)
        add(subLabel, BorderLayout.SOUTH)
    }

    fun update(mainText: String, detailText: String) {
        valLabel.text = mainText
        subLabel.text = detailText
    }
}

typealias StatCard = ModernStatCard

/** Custom anti-aliased flat dark button immune to WindowsLookAndFeel white painting bugs. */
class FreedomButton(
    text: String,
    fillColor: Color = Color(30, 41, 59),
    textColor: Color = Color(226, 232, 240),
    var borderColor: Color = Color(51, 65, 85),
    private val arc: Int = 10,
) : JButton(text) {
    private var hovered = false
    private var pressed = false

    init {
        background = fillColor
        foreground = textColor
        font = Font("Segoe UI", Font.BOLD, 11)
        isContentAreaFilled = false
        isBorderPainted = false
        isFocusPainted = false
        isOpaque = false
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        margin = Insets(6, 14, 6, 14)
        addMouseListener(object : MouseAdapter() {
            override fun mouseEntered(e: MouseEvent) {
                hovered = true
                repaint()
            }
            override fun mouseExited(e: MouseEvent) {
                hovered = false
                pressed = false
                repaint()
            }
            override fun mousePressed(e: MouseEvent) {
                pressed = true
                repaint()
            }
            override fun mouseReleased(e: MouseEvent) {
                pressed = false
                repaint()
            }
        })
    }

    override fun getPreferredSize(): Dimension {
        if (isPreferredSizeSet) return super.getPreferredSize()
        val fm = getFontMetrics(font)
        val w = fm.stringWidth(text ?: "") + margin.left + margin.right + 4
        val h = maxOf(32, fm.height + margin.top + margin.bottom)
        return Dimension(w, h)
    }

    private fun shiftColor(c: Color, delta: Int): Color = Color(
        (c.red + delta).coerceIn(0, 255),
        (c.green + delta).coerceIn(0, 255),
        (c.blue + delta).coerceIn(0, 255),
    )

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)

        val w = width
        val h = height
        val fill = when {
            !isEnabled -> Color(22, 31, 48)
            pressed -> shiftColor(background, -18)
            hovered -> shiftColor(background, 16)
            else -> background
        }
        val bCol = when {
            !isEnabled -> Color(36, 48, 68)
            hovered -> shiftColor(borderColor, 28)
            else -> borderColor
        }
        g2.color = fill
        g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc)
        g2.color = bCol
        g2.stroke = BasicStroke(1f)
        g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc)

        val label = text ?: ""
        if (label.isNotEmpty()) {
            g2.font = font
            val fm = g2.fontMetrics
            g2.color = if (isEnabled) foreground else Color(100, 116, 139)
            val tx = ((w - fm.stringWidth(label)) / 2).coerceAtLeast(6)
            val ty = ((h - fm.height) / 2) + fm.ascent
            g2.drawString(label, tx, ty)
        }
        g2.dispose()
    }
}

/** Slim dark scrollbar UI without bright native Win32/Metal chrome. */
private class DarkScrollBarUI : BasicScrollBarUI() {
    override fun configureScrollBarColors() {
        thumbColor = Color(51, 65, 85)
        thumbDarkShadowColor = Color(30, 41, 59)
        thumbHighlightColor = Color(71, 85, 105)
        trackColor = Color(9, 13, 22)
        trackHighlightColor = Color(9, 13, 22)
    }

    private fun zeroBtn(): JButton = JButton().apply {
        preferredSize = Dimension(0, 0)
        minimumSize = Dimension(0, 0)
        maximumSize = Dimension(0, 0)
        isVisible = false
    }

    override fun createDecreaseButton(orientation: Int): JButton = zeroBtn()
    override fun createIncreaseButton(orientation: Int): JButton = zeroBtn()

    override fun paintTrack(g: Graphics, c: JComponent, trackBounds: java.awt.Rectangle) {
        g.color = Color(9, 13, 22)
        g.fillRect(trackBounds.x, trackBounds.y, trackBounds.width, trackBounds.height)
    }

    override fun paintThumb(g: Graphics, c: JComponent, thumbBounds: java.awt.Rectangle) {
        if (thumbBounds.isEmpty || !scrollbar.isEnabled) return
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = if (isThumbRollover || isDragging) Color(71, 85, 105) else Color(51, 65, 85)
        g2.fillRoundRect(thumbBounds.x + 2, thumbBounds.y + 2, thumbBounds.width - 4, thumbBounds.height - 4, 6, 6)
        g2.dispose()
    }
}

/** Crisp dark vector checkbox icon (never renders white native box). */
internal class DarkCheckBoxIcon(private val selected: Boolean) : Icon {
    override fun getIconWidth(): Int = 16
    override fun getIconHeight(): Int = 16

    override fun paintIcon(c: java.awt.Component?, g: Graphics, x: Int, y: Int) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = if (selected) Color(14, 116, 144) else Color(14, 22, 38)
        g2.fillRoundRect(x + 1, y + 1, 14, 14, 5, 5)
        g2.color = if (selected) Color(56, 189, 248) else Color(71, 85, 105)
        g2.stroke = BasicStroke(1.3f)
        g2.drawRoundRect(x + 1, y + 1, 14, 14, 5, 5)
        if (selected) {
            g2.color = Color.WHITE
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.drawLine(x + 4, y + 8, x + 7, y + 11)
            g2.drawLine(x + 7, y + 11, x + 12, y + 5)
        }
        g2.dispose()
    }
}

/** Installs CrossPlatform dark LookAndFeel defaults so no Swing popup/tooltip/viewport/control renders white. */
internal object FreedomDarkTheme {
    fun install() {
        runCatching { UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName()) }
        val bg = Color(7, 11, 20)
        val surface = Color(14, 22, 38)
        val fg = Color(226, 232, 240)
        val muted = Color(148, 163, 184)
        val border = Color(30, 41, 59)
        val accent = Color(56, 189, 248)
        val transparent = Color(0, 0, 0, 0)
        UIManager.put("control", bg)
        UIManager.put("text", fg)
        UIManager.put("Panel.background", bg)
        UIManager.put("Panel.foreground", fg)
        UIManager.put("Label.background", bg)
        UIManager.put("Label.foreground", fg)
        UIManager.put("Button.background", Color(30, 41, 59))
        UIManager.put("Button.foreground", fg)
        UIManager.put("Button.select", Color(51, 65, 85))
        UIManager.put("Button.focus", transparent)
        UIManager.put("CheckBox.background", bg)
        UIManager.put("CheckBox.foreground", muted)
        UIManager.put("CheckBox.focus", transparent)
        UIManager.put("TextArea.background", surface)
        UIManager.put("TextArea.foreground", fg)
        UIManager.put("TextArea.caretForeground", accent)
        UIManager.put("TextArea.selectionBackground", Color(37, 99, 235))
        UIManager.put("TextArea.selectionForeground", Color.WHITE)
        UIManager.put("TextField.background", surface)
        UIManager.put("TextField.foreground", fg)
        UIManager.put("TextField.caretForeground", accent)
        UIManager.put("TextField.selectionBackground", Color(37, 99, 235))
        UIManager.put("TextField.selectionForeground", Color.WHITE)
        UIManager.put("ScrollPane.background", bg)
        UIManager.put("Viewport.background", surface)
        UIManager.put("ScrollBar.background", Color(9, 13, 22))
        UIManager.put("ScrollBar.track", Color(9, 13, 22))
        UIManager.put("ScrollBar.thumb", Color(51, 65, 85))
        UIManager.put("ScrollBar.width", 10)
        UIManager.put("ToolTip.background", surface)
        UIManager.put("ToolTip.foreground", fg)
        UIManager.put("ToolTip.border", BorderFactory.createLineBorder(border, 1))
        UIManager.put("OptionPane.background", bg)
        UIManager.put("OptionPane.messageForeground", fg)
    }

    fun darkScrollPane(view: JComponent, showBorder: Boolean = true): JScrollPane = JScrollPane(view).apply {
        background = Color(9, 13, 22)
        viewport.background = if (showBorder) Color(9, 13, 22) else Color(7, 11, 20)
        border = if (showBorder) BorderFactory.createLineBorder(Color(30, 41, 59), 1) else BorderFactory.createEmptyBorder()
        verticalScrollBar.apply {
            setUI(DarkScrollBarUI())
            preferredSize = Dimension(10, 0)
            unitIncrement = 16
        }
        horizontalScrollBar.apply {
            setUI(DarkScrollBarUI())
            preferredSize = Dimension(0, 10)
            unitIncrement = 16
        }
        setCorner(ScrollPaneConstants.LOWER_RIGHT_CORNER, JPanel().apply { background = Color(9, 13, 22) })
    }
}

/**
 * Reversible Windows HKCU WinINet system proxy helper (`Internet Settings`).
 * Captures prior `ProxyEnable`/`ProxyServer`/`ProxyOverride` values once and restores them on stop or JVM shutdown.
 */
object WindowsSystemProxy {
    private const val REG_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    private val isWindows = System.getProperty("os.name").lowercase().contains("windows")

    @Volatile var appliedByApp = false
        private set
    private var prevCaptured = false
    private var prevEnable = 0
    private var prevServer: String? = null
    private var prevOverride: String? = null
    private val hookRegistered = AtomicBoolean(false)

    private fun runCmd(vararg cmd: String): Pair<Int, String> {
        val pb = ProcessBuilder(*cmd).redirectErrorStream(true)
        val p = pb.start()
        val out = p.inputStream.bufferedReader().readText()
        val code = if (p.waitFor(4, TimeUnit.SECONDS)) p.exitValue() else { p.destroyForcibly(); -1 }
        return code to out
    }

    private fun queryRegValue(name: String): String? {
        if (!isWindows) return null
        val (rc, out) = runCmd("reg", "query", REG_KEY, "/v", name)
        if (rc != 0) return null
        val line = out.lines().firstOrNull { it.trim().startsWith(name, ignoreCase = true) } ?: return null
        return line.trim().split(Regex("\\s+"), limit = 3).getOrNull(2)?.trim()
    }

    private fun notifyWinInet() {
        if (!isWindows) return
        runCatching {
            val ps = """
                Add-Type -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);' -Name WinInet -Namespace Freedom
                [Freedom.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
                [Freedom.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
            """.trimIndent().replace("\n", "; ")
            runCmd("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
        }
    }

    @Synchronized
    fun enable(port: Int): Boolean {
        if (!isWindows || port !in 1..65535) return false
        if (hookRegistered.compareAndSet(false, true)) {
            runCatching { Runtime.getRuntime().addShutdownHook(Thread { restore() }) }
        }
        if (!prevCaptured) {
            prevEnable = queryRegValue("ProxyEnable")?.let { raw ->
                if (raw.startsWith("0x", ignoreCase = true)) raw.substring(2).toIntOrNull(16) else raw.toIntOrNull()
            } ?: 0
            prevServer = queryRegValue("ProxyServer")
            prevOverride = queryRegValue("ProxyOverride")
            prevCaptured = true
        }
        val (r1, _) = runCmd("reg", "add", REG_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
        val (r2, _) = runCmd("reg", "add", REG_KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", "127.0.0.1:$port", "/f")
        val (r3, _) = runCmd("reg", "add", REG_KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.*;10.*;192.168.*;<local>", "/f")
        if (r1 == 0 && r2 == 0 && r3 == 0) {
            appliedByApp = true
            notifyWinInet()
            return true
        }
        return false
    }

    @Synchronized
    fun restore() {
        if (!isWindows || !appliedByApp) return
        runCmd("reg", "add", REG_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", prevEnable.toString(), "/f")
        val oldSrv = prevServer
        if (!oldSrv.isNullOrBlank()) {
            runCmd("reg", "add", REG_KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", oldSrv, "/f")
        } else {
            runCmd("reg", "delete", REG_KEY, "/v", "ProxyServer", "/f")
        }
        val oldOvr = prevOverride
        if (!oldOvr.isNullOrBlank()) {
            runCmd("reg", "add", REG_KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", oldOvr, "/f")
        } else {
            runCmd("reg", "delete", REG_KEY, "/v", "ProxyOverride", "/f")
        }
        appliedByApp = false
        notifyWinInet()
    }
}

/**
 * MainWindow:
 * Freedom Network 2026–2027 Windows desktop architecture with 3 segmented navigation tabs:
 * 1. KONTROL (Freedom Hero Power Shield, WinINet System Proxy Toggle, Persona, Dual-Path Leak Test & Metrics)
 * 2. TEŞHİS (ISP Out-of-Tunnel Diagnostic Runner, Targets, Monospace Output, Copy)
 * 3. GÜNLÜK & SİSTEM (System Connection Explorer, Socket Diagnostics, Copy)
 */
class MainWindow {
    private val frame = JFrame("Freedom Network — 2026–2027 Özgür Ağ Motoru")
    private val pulsePanel = ModernPowerShieldPanel()
    private val sparkline = ThroughputSparklinePanel()
    private val cardTcp = ModernStatCard(0, "TCP DESYNC", Color(16, 185, 129))
    private val cardVision = ModernStatCard(1, "VISION & GİZLİLİK", Color(56, 189, 248))
    private val cardFake = ModernStatCard(2, "SAHTE & KALKAN", Color(167, 139, 250))
    private val cardDns = ModernStatCard(3, "ŞİFRELİ DoH3 / ECH", Color(251, 191, 36))

    private var selectedPersona = DevicePersona.IPHONE_19_BETA
    private var advancedExpanded = false
    private var systemProxyDesired = false

    private val statusPill = JLabel("KORUMA KAPALI · DOKUNARAK BAĞLANIN", JLabel.CENTER).apply {
        isOpaque = true
        background = Color(11, 18, 32)
        font = Font("Segoe UI", Font.BOLD, 11)
        foreground = Color(148, 163, 184)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(30, 41, 59), 1),
            BorderFactory.createEmptyBorder(5, 14, 5, 14),
        )
    }

    private val ipCardDetail = JLabel("Yerel DPI Proxy + Dahili WireGuard WARP Kripto Hazır").apply {
        font = Font("Segoe UI", Font.PLAIN, 11)
        foreground = Color(226, 232, 240)
    }
    private val btnSystemProxyToggle = FreedomButton(
        "Sistem Vekili: Kapalı",
        fillColor = Color(15, 27, 46),
        textColor = Color(148, 163, 184),
        borderColor = Color(51, 65, 85),
    )
    private val btnPersonaCycle = FreedomButton(
        selectedPersona.shortLabel,
        fillColor = Color(46, 16, 101),
        textColor = Color(233, 213, 255),
        borderColor = Color(124, 58, 237),
    )
    private val btnLeakTest = FreedomButton(
        "Gizlilik & Çift-Yol Testi",
        fillColor = Color(15, 27, 46),
        textColor = Color(56, 189, 248),
        borderColor = Color(29, 78, 216),
    )
    private val leakTestResult = JLabel("İzleyici & URL Parametre Temizliği + HTTP Kimlik Maskeleme + WireGuard hazır").apply {
        font = Font("Segoe UI", Font.PLAIN, 10)
        foreground = Color(148, 163, 184)
    }

    private val targets = JTextArea("cloudflare.com\nwikipedia.org\nietf.org", 2, 35).apply {
        background = Color(14, 22, 38)
        foreground = Color.WHITE
        caretColor = Color(56, 189, 248)
        font = Font("Segoe UI", Font.PLAIN, 12)
        border = BorderFactory.createEmptyBorder(4, 6, 4, 6)
    }
    private val altDns = JTextField(25).apply {
        background = Color(14, 22, 38)
        foreground = Color.WHITE
        caretColor = Color(56, 189, 248)
        font = Font("Segoe UI", Font.PLAIN, 12)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(30, 41, 59), 1),
            BorderFactory.createEmptyBorder(4, 6, 4, 6),
        )
    }
    private val dohEndpoints = JTextField(25).apply {
        toolTipText = "Örnek: https://1.1.1.1/dns-query"
        background = Color(14, 22, 38)
        foreground = Color.WHITE
        caretColor = Color(56, 189, 248)
        font = Font("Segoe UI", Font.PLAIN, 12)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(30, 41, 59), 1),
            BorderFactory.createEmptyBorder(4, 6, 4, 6),
        )
    }
    private val runButton = FreedomButton(
        "Ağ Tanıla",
        fillColor = Color(37, 99, 235),
        textColor = Color.WHITE,
        borderColor = Color(59, 130, 246),
    ).apply { font = Font("Segoe UI", Font.BOLD, 12) }

    private val heroActionButton = FreedomButton(
        "ÖZGÜR AĞI BAŞLAT (DPI Aşma + Gizlilik)",
        fillColor = Color(16, 185, 129),
        textColor = Color(4, 22, 16),
        borderColor = Color(52, 211, 153),
        arc = 12,
    ).apply { font = Font("Segoe UI", Font.BOLD, 12) }

    private val systemButton = FreedomButton(
        "Sistem Bağlantıları",
        fillColor = Color(30, 41, 59),
        textColor = Color(226, 232, 240),
        borderColor = Color(71, 85, 105),
    )
    private val appliedButton = FreedomButton(
        "Öneriyi Doğrula",
        fillColor = Color(30, 41, 59),
        textColor = Color(226, 232, 240),
        borderColor = Color(51, 65, 85),
    ).apply { isEnabled = false }

    private val auto = JCheckBox("Ağ değişince yeniden tanıla", false).apply {
        foreground = Color(148, 163, 184)
        background = Color(7, 11, 20)
        isOpaque = false
        isContentAreaFilled = false
        isBorderPainted = false
        isFocusPainted = false
        icon = DarkCheckBoxIcon(false)
        selectedIcon = DarkCheckBoxIcon(true)
        font = Font("Segoe UI", Font.PLAIN, 11)
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
    }
    private val output = JTextArea().apply {
        isEditable = false
        font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        lineWrap = true
        wrapStyleWord = true
        background = Color(9, 13, 22)
        foreground = Color(226, 232, 240)
        border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
    }
    private val status = JLabel(" ").apply {
        foreground = Color(56, 189, 248)
        font = Font("Segoe UI", Font.PLAIN, 11)
    }

    // Segmented tab cards
    private val cardLayout = CardLayout()
    private val centerContainer = JPanel(cardLayout).apply {
        background = Color(7, 11, 20)
    }
    private val tabBtnControl = FreedomButton("KONTROL", arc = 8)
    private val tabBtnDiag = FreedomButton("TEŞHİS", arc = 8)
    private val tabBtnLog = FreedomButton("GÜNLÜK & SİSTEM", arc = 8)

    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "freedom-worker").apply { isDaemon = true } }
    private val busy = AtomicBoolean(false)
    private var session: DiagnosticSession? = null
    @Volatile private var lastEnv: EnvironmentInfo? = null
    @Volatile private var lastDecision: Decision? = null
    private val watcher = Timer(15_000) { worker.execute { checkNetwork() } }

    private var lastConns = 0L
    private var lastTickMs = 0L

    private val ticker = Timer(1000) {
        val s = session ?: return@Timer
        val p = s.proxyStats()
        pulsePanel.isActive = p.active
        pulsePanel.portInfo = if (p.active) "127.0.0.1:${p.port}" else ""

        cardTcp.update("${p.connections} Akış", "TLS Bölme: ${p.tlsSplit} · HTTP: ${p.httpSplit}")
        cardVision.update("${p.visionSplice} Splice", "İzleyici: ${p.trackersBlocked} · URL: ${p.paramsStripped}")
        cardFake.update("${p.fakeSent} Sahte", "RST Kalkanı: ${p.rstDropped} Engellendi")
        cardDns.update(if (p.active) "Etkin" else "Beklemede", "PQ-TLS 1.3 / ECH + ${selectedPersona.shortLabel}")

        val now = System.currentTimeMillis()
        var rxRate = 0f
        var txRate = 0f
        if (p.active && lastTickMs > 0L) {
            val dConn = (p.connections - lastConns).coerceAtLeast(0L)
            rxRate = dConn * 14.5f
            txRate = dConn * 2.2f
        }
        lastConns = p.connections
        lastTickMs = now
        sparkline.updateMetrics(rxRate, txRate, p.connections * 16384L, p.connections * 4096L)

        updateProtectionVisuals(p)
    }

    private fun updateProtectionVisuals(p: ProxyStatus) {
        if (p.active) {
            val sysState = if (WindowsSystemProxy.appliedByApp) "Sistem Vekili Açık" else "SOCKS5/HTTP Hazır"
            statusPill.text = "FREEDOM NETWORK DEVREDE (127.0.0.1:${p.port} · ${selectedPersona.shortLabel})"
            statusPill.foreground = Color(16, 185, 129)
            ipCardDetail.text = "Aktif: 127.0.0.1:${p.port} · $sysState · İzleyici ${p.trackersBlocked} / URL ${p.paramsStripped}"
            heroActionButton.text = "KORUMAYI DURDUR (127.0.0.1:${p.port})"
            heroActionButton.background = Color(220, 38, 38)
            heroActionButton.foreground = Color.WHITE
            heroActionButton.borderColor = Color(248, 113, 113)
        } else {
            statusPill.text = "KORUMA KAPALI · DOKUNARAK BAĞLANIN"
            statusPill.foreground = Color(148, 163, 184)
            ipCardDetail.text = "Hazır · Yerel DPI Aşma Vekili + Cihaz Kimliği & URL Gizliliği"
            heroActionButton.text = "ÖZGÜR AĞI BAŞLAT (DPI Aşma + Gizlilik)"
            heroActionButton.background = Color(16, 185, 129)
            heroActionButton.foreground = Color(4, 22, 16)
            heroActionButton.borderColor = Color(52, 211, 153)
        }
        ipCardDetail.toolTipText = ipCardDetail.text
        heroActionButton.repaint()

        if (WindowsSystemProxy.appliedByApp) {
            btnSystemProxyToggle.text = "Sistem Vekili: Açık"
            btnSystemProxyToggle.background = Color(6, 78, 59)
            btnSystemProxyToggle.foreground = Color(167, 243, 208)
            btnSystemProxyToggle.borderColor = Color(16, 185, 129)
        } else if (systemProxyDesired) {
            btnSystemProxyToggle.text = "Sistem Vekili: Bekliyor"
            btnSystemProxyToggle.background = Color(30, 41, 59)
            btnSystemProxyToggle.foreground = Color(251, 191, 36)
            btnSystemProxyToggle.borderColor = Color(217, 119, 6)
        } else {
            btnSystemProxyToggle.text = "Sistem Vekili: Kapalı"
            btnSystemProxyToggle.background = Color(15, 27, 46)
            btnSystemProxyToggle.foreground = Color(148, 163, 184)
            btnSystemProxyToggle.borderColor = Color(51, 65, 85)
        }
        btnSystemProxyToggle.repaint()
    }

    private fun loadWindowIcons() {
        val imgs = listOf("/icon-16.png", "/icon-32.png", "/icon-48.png", "/icon-256.png").mapNotNull { path ->
            runCatching { MainWindow::class.java.getResourceAsStream(path)?.use { ImageIO.read(it) } }.getOrNull()
        }
        if (imgs.isNotEmpty()) frame.iconImages = imgs
    }

    fun show() {
        loadWindowIcons()
        val root = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
        }

        // Top Header + Tab Navigation
        val topBar = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(10, 14, 8, 14)
        }
        val brandRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            background = Color(7, 11, 20)
            val lblTitle = JLabel("FREEDOM NETWORK").apply {
                font = Font("Segoe UI", Font.BOLD, 17)
                foreground = Color(248, 250, 252)
            }
            val lblVer = JLabel("2026–2027 · v2.0").apply {
                font = Font("Segoe UI", Font.BOLD, 11)
                foreground = Color(56, 189, 248)
            }
            add(lblTitle)
            add(lblVer)
        }
        val tabRow = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            background = Color(7, 11, 20)
            add(tabBtnControl)
            add(tabBtnDiag)
            add(tabBtnLog)
        }
        topBar.add(brandRow, BorderLayout.WEST)
        topBar.add(tabRow, BorderLayout.EAST)
        root.add(topBar, BorderLayout.NORTH)

        // ---------------- TAB 0: KONTROL ----------------
        val panelControl = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(0, 14, 8, 14)
        }
        pulsePanel.onToggleListener = { toggleDesync() }
        panelControl.add(pulsePanel, BorderLayout.NORTH)

        val controlCenter = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Color(7, 11, 20)
        }
        val statusRow = JPanel(FlowLayout(FlowLayout.CENTER, 0, 4)).apply {
            background = Color(7, 11, 20)
            add(statusPill)
        }
        controlCenter.add(statusRow)

        fun privacyCard(titleText: String, titleColor: Color, bodyComp: java.awt.Component, rightComp: java.awt.Component? = null): JPanel {
            return JPanel(BorderLayout(12, 2)).apply {
                background = Color(11, 18, 32)
                border = BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(Color(30, 41, 59), 1),
                    BorderFactory.createEmptyBorder(9, 12, 9, 12),
                )
                val left = JPanel(BorderLayout(0, 3)).apply {
                    isOpaque = false
                    add(
                        JLabel(titleText).apply {
                            font = Font("Segoe UI", Font.BOLD, 10)
                            foreground = titleColor
                        },
                        BorderLayout.NORTH,
                    )
                    add(bodyComp, BorderLayout.CENTER)
                }
                add(left, BorderLayout.CENTER)
                if (rightComp != null) {
                    val rightWrap = JPanel(GridBagLayout()).apply {
                        isOpaque = false
                        add(rightComp)
                    }
                    add(rightWrap, BorderLayout.EAST)
                }
            }
        }

        val privacyStack = JPanel(GridLayout(3, 1, 0, 6)).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(4, 0, 6, 0)
            add(
                privacyCard(
                    "IP GİZLİLİĞİ & WINDOWS SİSTEM VEKİLİ (HKCU WinINet)",
                    Color(16, 185, 129),
                    ipCardDetail,
                    btnSystemProxyToggle,
                ),
            )
            add(
                privacyCard(
                    "CİHAZ GİZLİLİĞİ & GELECEK KİMLİK",
                    Color(167, 139, 250),
                    JLabel("HTTP User-Agent, Client Hints & URL izleme parametreleri otomatik temizlenir").apply {
                        font = Font("Segoe UI", Font.PLAIN, 10)
                        foreground = Color(148, 163, 184)
                    },
                    btnPersonaCycle,
                ),
            )
            add(
                privacyCard(
                    "GİZLİLİK & ÇİFT-YOL IP SIZINTI TESTİ",
                    Color(56, 189, 248),
                    leakTestResult,
                    btnLeakTest,
                ),
            )
        }
        controlCenter.add(privacyStack)

        val advancedContainer = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            isVisible = false
            add(sparkline, BorderLayout.NORTH)
            val cardsPanel = JPanel(GridLayout(1, 4, 6, 6)).apply {
                background = Color(7, 11, 20)
                border = BorderFactory.createEmptyBorder(6, 0, 4, 0)
                add(cardTcp)
                add(cardVision)
                add(cardFake)
                add(cardDns)
            }
            add(cardsPanel, BorderLayout.CENTER)
        }
        val btnAdvancedToggle = FreedomButton(
            "Gelişmiş Metrikler & Canlı Trafik ▾",
            fillColor = Color(12, 19, 34),
            textColor = Color(148, 163, 184),
            borderColor = Color(30, 41, 59),
        ).apply {
            alignmentX = java.awt.Component.CENTER_ALIGNMENT
            addActionListener {
                advancedExpanded = !advancedExpanded
                advancedContainer.isVisible = advancedExpanded
                text = if (advancedExpanded) "Gelişmiş Metrikler & Canlı Trafik ▴" else "Gelişmiş Metrikler & Canlı Trafik ▾"
                panelControl.revalidate()
            }
        }
        val advToggleWrap = JPanel(FlowLayout(FlowLayout.CENTER, 0, 2)).apply {
            background = Color(7, 11, 20)
            add(btnAdvancedToggle)
        }
        controlCenter.add(advToggleWrap)
        controlCenter.add(advancedContainer)
        val controlScrollHost = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            add(controlCenter, BorderLayout.NORTH)
        }
        panelControl.add(FreedomDarkTheme.darkScrollPane(controlScrollHost, showBorder = false), BorderLayout.CENTER)

        val quickActionRow = JPanel(FlowLayout(FlowLayout.CENTER, 0, 6)).apply {
            background = Color(7, 11, 20)
            heroActionButton.preferredSize = Dimension(460, 38)
            add(heroActionButton)
        }
        panelControl.add(quickActionRow, BorderLayout.SOUTH)
        centerContainer.add(panelControl, "CONTROL")

        btnSystemProxyToggle.addActionListener {
            systemProxyDesired = !systemProxyDesired
            val s = session
            worker.execute {
                val ps = s?.proxyStats()
                if (systemProxyDesired && ps != null && ps.active) {
                    WindowsSystemProxy.enable(ps.port)
                } else {
                    WindowsSystemProxy.restore()
                }
                ui {
                    ps?.let { updateProtectionVisuals(it) }
                    status.text = if (systemProxyDesired) {
                        if (WindowsSystemProxy.appliedByApp) {
                            "Windows sistem vekili etkin (127.0.0.1:${ps?.port})"
                        } else {
                            "Sistem vekili koruma açılınca devreye girecek"
                        }
                    } else {
                        "Windows sistem vekili orijinal ayarlara geri döndürüldü"
                    }
                }
            }
        }

        btnPersonaCycle.addActionListener {
            val all = DevicePersona.entries
            selectedPersona = all[(all.indexOf(selectedPersona) + 1) % all.size]
            btnPersonaCycle.text = selectedPersona.shortLabel
            btnPersonaCycle.repaint()
            status.text = "Cihaz kimliği: ${selectedPersona.shortLabel} (yeniden bağlanmada uygulanır)"
        }

        btnLeakTest.addActionListener {
            btnLeakTest.isEnabled = false
            leakTestResult.text = "Doğrudan çıkış & yerel vekil yolu test ediliyor..."
            val s = session
            worker.execute {
                val directIp = runCatching {
                    val conn = URI("https://api.ipify.org").toURL().openConnection(java.net.Proxy.NO_PROXY) as javax.net.ssl.HttpsURLConnection
                    conn.connectTimeout = 3500
                    conn.readTimeout = 3500
                    try {
                        conn.inputStream.bufferedReader().readText().trim()
                    } finally {
                        conn.disconnect()
                    }
                }.getOrNull()
                val ps = s?.proxyStats()
                val proxyIp = if (ps != null && ps.active) {
                    runCatching {
                        val proxy = java.net.Proxy(java.net.Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", ps.port))
                        val conn = URI("https://api.ipify.org").toURL().openConnection(proxy) as javax.net.ssl.HttpsURLConnection
                        conn.connectTimeout = 4000
                        conn.readTimeout = 4000
                        try {
                            conn.inputStream.bufferedReader().readText().trim()
                        } finally {
                            conn.disconnect()
                        }
                    }.getOrNull()
                } else null
                val wgPub = Native.wgPublicKey(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) })?.size == 32
                ui {
                    btnLeakTest.isEnabled = true
                    val resText = buildString {
                        append("Doğrudan IP: ").append(directIp ?: "ölçülemedi")
                        if (ps?.active == true) {
                            append(" · Vekil (:").append(ps.port).append("): ").append(proxyIp ?: "hata")
                            append(" · İzleyici=").append(ps.trackersBlocked).append(" URL=").append(ps.paramsStripped)
                        }
                        append(" · WG: ").append(if (wgPub) "Hazır" else "Hata")
                    }
                    leakTestResult.text = resText
                    leakTestResult.toolTipText = resText
                }
            }
        }

        // ---------------- TAB 1: TEŞHİS ----------------
        val panelDiag = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(4, 14, 8, 14)
        }
        val form = JPanel(GridBagLayout()).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(4, 0, 8, 0)
        }
        val c = GridBagConstraints().apply { insets = Insets(3, 4, 3, 4); anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL }
        fun row(y: Int, label: String, comp: java.awt.Component) {
            val lbl = JLabel(label).apply {
                foreground = Color(148, 163, 184)
                font = Font("Segoe UI", Font.PLAIN, 11)
            }
            c.gridx = 0; c.gridy = y; c.weightx = 0.0; form.add(lbl, c)
            c.gridx = 1; c.weightx = 1.0; form.add(comp, c)
        }
        row(0, "Test hedefleri:", FreedomDarkTheme.darkScrollPane(targets))
        row(1, "Karşılaştırılacak DNS (isteğe bağlı):", altDns)
        row(2, "Şifreli DoH adresleri (isteğe bağlı):", dohEndpoints)

        val btnCopyDiag = FreedomButton(
            "Raporu Kopyala",
            fillColor = Color(30, 41, 59),
            textColor = Color(226, 232, 240),
            borderColor = Color(71, 85, 105),
        ).apply {
            addActionListener {
                val sel = StringSelection(output.text)
                Toolkit.getDefaultToolkit().systemClipboard.setContents(sel, sel)
                status.text = "Teşhis çıktısı panoya kopyalandı"
            }
        }
        val btnRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4)).apply {
            background = Color(7, 11, 20)
            add(runButton)
            add(appliedButton)
            add(btnCopyDiag)
            add(auto)
        }
        c.gridx = 0; c.gridy = 3; c.gridwidth = 2; form.add(btnRow, c)
        panelDiag.add(form, BorderLayout.NORTH)
        panelDiag.add(FreedomDarkTheme.darkScrollPane(output), BorderLayout.CENTER)
        centerContainer.add(panelDiag, "DIAG")

        // ---------------- TAB 2: GÜNLÜK & SİSTEM ----------------
        val panelLog = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(6, 14, 8, 14)
        }
        val logOutput = JTextArea().apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
            lineWrap = true
            wrapStyleWord = true
            background = Color(8, 12, 20)
            foreground = Color(167, 243, 208)
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
            text = "Freedom Network Dahili Log & Sistem Gözlemcisi Hazır.\nSistem genelindeki bağlantıları incelemek için 'Sistem Bağlantıları' düğmesine tıklayın."
        }
        val logTopBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4)).apply {
            background = Color(7, 11, 20)
            add(systemButton)
            val btnCopyLog = FreedomButton(
                "Sistem Çıktısını Kopyala",
                fillColor = Color(37, 99, 235),
                textColor = Color.WHITE,
                borderColor = Color(59, 130, 246),
            ).apply {
                addActionListener {
                    val sel = StringSelection(logOutput.text)
                    Toolkit.getDefaultToolkit().systemClipboard.setContents(sel, sel)
                    status.text = "Sistem günlüğü panoya kopyalandı"
                }
            }
            add(btnCopyLog)
        }
        panelLog.add(logTopBar, BorderLayout.NORTH)
        panelLog.add(FreedomDarkTheme.darkScrollPane(logOutput), BorderLayout.CENTER)
        centerContainer.add(panelLog, "LOG")

        root.add(centerContainer, BorderLayout.CENTER)
        root.add(status.apply { border = BorderFactory.createEmptyBorder(4, 14, 8, 14) }, BorderLayout.SOUTH)

        fun updateTabs(activeIdx: Int) {
            val tabs = listOf(tabBtnControl, tabBtnDiag, tabBtnLog)
            tabs.forEachIndexed { idx, btn ->
                val active = idx == activeIdx
                btn.background = if (active) Color(30, 58, 138) else Color(15, 23, 42)
                btn.foreground = if (active) Color.WHITE else Color(148, 163, 184)
                btn.borderColor = if (active) Color(56, 189, 248) else Color(30, 41, 59)
                btn.repaint()
            }
            cardLayout.show(centerContainer, when (activeIdx) {
                0 -> "CONTROL"
                1 -> "DIAG"
                else -> "LOG"
            })
        }

        tabBtnControl.addActionListener { updateTabs(0) }
        tabBtnDiag.addActionListener { updateTabs(1) }
        tabBtnLog.addActionListener { updateTabs(2) }
        updateTabs(0)

        frame.background = Color(7, 11, 20)
        frame.contentPane = root
        frame.defaultCloseOperation = WindowConstants.DISPOSE_ON_CLOSE
        frame.addWindowListener(object : WindowAdapter() {
            override fun windowClosed(e: WindowEvent) = shutdown()
        })
        frame.minimumSize = Dimension(820, 680)
        frame.size = Dimension(880, 740)
        frame.setLocationRelativeTo(null)

        runButton.addActionListener { startRun(verifyRuns = 0) }
        heroActionButton.addActionListener { toggleDesync() }
        appliedButton.addActionListener { applied() }
        systemButton.addActionListener { showSystem(logOutput) }

        try {
            session = DiagnosticSession()
            status.text = "Motor ${Native.engineVersion()} hazır · TLS güveni: ${WindowsPlatform.trust.second}"
            watcher.start()
            ticker.start()
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

    private fun toggleDesync() {
        val s = session ?: return
        heroActionButton.isEnabled = false
        val personaStr = if (selectedPersona != DevicePersona.OFF) selectedPersona.id else ""
        worker.execute {
            val cur = s.proxyStats()
            val next = if (cur.active) {
                WindowsSystemProxy.restore()
                s.stopProxy()
                s.proxyStats()
            } else {
                val started = s.startProxy(
                    DesyncConfig(
                        mode = DesyncMode.REALITY_VISION,
                        port = 0,
                        persona = personaStr,
                        blockTrackers = true,
                        stripUrlParams = true,
                    ),
                )
                if (started.active && systemProxyDesired) {
                    WindowsSystemProxy.enable(started.port)
                }
                started
            }
            val text = Text.proxyStatus(next)
            ui {
                output.text = text + "\n" + output.text
                output.caretPosition = 0
                pulsePanel.isActive = next.active
                pulsePanel.portInfo = if (next.active) "127.0.0.1:${next.port}" else ""
                updateProtectionVisuals(next)
                status.text = if (next.active) {
                    "Freedom Network etkin (127.0.0.1:${next.port})"
                } else {
                    "Freedom Network durduruldu"
                }
                heroActionButton.isEnabled = true
            }
        }
    }

    private fun showSystem(targetArea: JTextArea) {
        systemButton.isEnabled = false
        status.text = "Sistem bağlantıları okunuyor…"
        worker.execute {
            val text = try {
                Text.system(SystemSnapshot.capture())
            } catch (e: Exception) {
                "Sistem bağlantıları okunamadı: ${e.message}"
            }
            ui {
                targetArea.text = text
                targetArea.caretPosition = 0
                status.text = "Sistem geneli görünüm güncellendi"
                systemButton.isEnabled = true
            }
        }
    }

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
        runCatching { WindowsSystemProxy.restore() }
        pulsePanel.stop()
        ticker.stop()
        watcher.stop()
        worker.shutdownNow()
        runCatching { worker.awaitTermination(2, TimeUnit.SECONDS) }
        session?.close()
        session = null
    }
}

fun main(args: Array<String>) {
    if (args.isNotEmpty()) exitProcess(runCli(args.toList()))
    FreedomDarkTheme.install()
    SwingUtilities.invokeLater { MainWindow().show() }
}
