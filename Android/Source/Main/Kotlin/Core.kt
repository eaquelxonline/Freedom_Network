// THE DPI — Android 11–17 application (Kotlin, native Android SDK Views, Rust .so via JNI).
//
// Self-contained: the JNI boundary (class thedpi.Native), the wire codec mirrored from
// Native/Core.rs, typed models, the platform-TLS prober, the diagnostic session
// orchestrator, the Turkish text catalogue, and this platform's integration.
// The shared section below is kept byte-identical with the other platform module.

package thedpi

import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.net.UnknownHostException
import java.net.URL
import java.net.ConnectException
import android.net.http.UrlResponseInfo
import android.net.http.UrlRequest
import android.net.http.UploadDataSink
import android.net.http.UploadDataProvider
import android.net.http.NetworkException
import android.net.http.HttpException
import android.net.http.HttpEngine
import android.content.Context
import android.content.Intent
import android.app.Activity
import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.pm.ServiceInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.drawable.GradientDrawable
import android.animation.ValueAnimator
import android.view.Gravity
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.view.WindowInsets
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

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
) {
    fun toRecord(): Record = Record()
        .int(Tags.Desync.MODE, mode).int(Tags.Desync.FAKE_TTL, fakeTtl)
        .int(Tags.Desync.SPLIT_POS, splitPos).int(Tags.Desync.DROP_RST, if (dropRst) 1 else 0)
        .int(Tags.Desync.PORT, port)
}

data class DesyncResult(
    val status: Int, val mode: Int, val dropped: Boolean, val protocol: Int,
    val sni: String, val ech: Boolean, val postQuantum: Boolean, val packets: List<ByteArray>,
)

data class ProxyStatus(
    val status: Int, val active: Boolean, val port: Int, val mode: Int,
    val connections: Long = 0, val tlsSplit: Long = 0, val httpSplit: Long = 0,
    val fakeSent: Long = 0, val rstDropped: Long = 0, val visionSplice: Long = 0,
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
            45 -> "$s: DNS yanıtı zehirlenmiş / sansür IP'sine yönlendirildi (${a(0)}.${a(1)}.${a(2)}.${a(3)})"
            39 -> "$s: işletim sistemi bağlantıya izin vermedi (Android 17+: yerel ağ adresleri ACCESS_LOCAL_NETWORK izni gerektirir; THE DPI bu izni istemez). Bu bir ağ arızası değildir."
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
        appendLine("THE DPI — KİŞİSEL SUNUCU YÖNETİCİSİ (${list.size} profil)")
        for (p in list) {
            val kota = if (p.quotaBytes > 0) "${p.usedBytes}/${p.quotaBytes} bayt" else "${p.usedBytes} bayt (sınırsız)"
            appendLine("  • ${p.name} [${serverStatus(p.status)}] → ${p.activeEndpoint} (REALITY hedefi: ${p.coverDest} · cihaz: ${p.deviceId} · gecikme: ${p.latencyMs} ms · kayıp: %${p.lossPct} · kota: $kota)")
        }
    }

    fun proxyStatus(p: ProxyStatus): String = buildString {
        if (!p.active) {
            appendLine("ENGELSİZ MOD (YEREL DPI AŞMA): Kapalı")
            return@buildString
        }
        appendLine("ENGELSİZ MOD (YEREL DPI AŞMA): Etkin · 127.0.0.1:${p.port} (SOCKS5 + HTTP CONNECT)")
        appendLine("  Strateji   : ${desyncMode(p.mode)}")
        appendLine("  İstatistik : bağlantı ${p.connections} · TLS bölme ${p.tlsSplit} · HTTP bölme ${p.httpSplit} · sahte paket ${p.fakeSent} · RST kalkanı ${p.rstDropped} · Vision doğrudan aktarım ${p.visionSplice}")
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
    ): String = buildString {
        if (!vpnActive && !p.active) {
            appendLine("ENGELSİZ MOD (SİSTEM GENELİ VPN + DPI AŞMA): Kapalı")
            return@buildString
        }
        val modeDesc = if (vpnActive) {
            "Sistem Geneli TUN Köprüsü (0.0.0.0/0 · DoH DNS + REALITY/Vision Desync + Roblox/Discord UDP NAT)"
        } else {
            "Yerel Proxy (127.0.0.1:${p.port})"
        }
        appendLine("ENGELSİZ MOD: Etkin · $modeDesc")
        if (p.active) {
            appendLine("  Yerel Proxy: 127.0.0.1:${p.port} (SOCKS5 + HTTP CONNECT)")
        }
        appendLine("  Strateji   : ${desyncMode(p.mode)}")
        appendLine("  TUN Köprüsü: TCP $tcpFlows (Desync $desyncedFlows, TLS Kayıt Parçalama $tlsFragmented, Vision Splice $visionSplicedFlows) · UDP/Oyun-Ses $udpFlows (QUIC Geçişi $quicFallbacks) · DNS $dnsQueries (Şifreli DoH $dohResolved, Zehirlenme Engellendi $poisonedBlocked)")
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
     * True when a DNS response points to a known ISP block/warning page or a sinkhole:
     * Türk Telekom / BTK `195.175.254.0/24` and `2a01:358:4014:a00::/64`, `0.0.0.0`,
     * `127.0.0.0/8`, or the IPv6 unspecified/loopback addresses.
     */
    fun containsPoisonedDns(payload: ByteArray): Boolean {
        val addrs = dnsAnswerAddresses(payload) ?: return false
        for (a in addrs) {
            val b0 = a[0].toInt() and 0xFF
            if (a.size == 4) {
                val b1 = a[1].toInt() and 0xFF
                val b2 = a[2].toInt() and 0xFF
                if (b0 == 195 && b1 == 175 && b2 == 254) return true
                if (b0 == 127) return true
                if (a.all { it.toInt() == 0 }) return true
            } else {
                if (a.copyOfRange(0, 15).all { it.toInt() == 0 }) return true // :: and ::1
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

    /** Builds a 74-byte Discord Voice UDP IP Discovery packet (`0x00 0x01 0x00 0x46` + SSRC). */
    fun buildDiscordVoiceIpDiscovery(ssrc: Int, address: String = "", port: Int = 0): ByteArray {
        val pkt = ByteArray(74)
        putU16(pkt, 0, 0x0001)
        putU16(pkt, 2, 70)
        putU32(pkt, 4, ssrc.toLong() and 0xFFFFFFFFL)
        val addrBytes = address.toByteArray(Charsets.UTF_8)
        System.arraycopy(addrBytes, 0, pkt, 8, minOf(addrBytes.size, 63))
        putU16(pkt, 72, port)
        return pkt
    }

    /** Builds a Roblox RakNet `ID_OPEN_CONNECTION_REQUEST_1` (`0x05`) UDP handshake datagram. */
    fun buildRobloxRakNetOpenConnectionRequest1(totalSize: Int = 48): ByteArray {
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
        pkt[17] = 11 // RakNet protocol version
        return pkt
    }
}

/**
 * RFC 8484 DoH client that needs **no DNS of its own**: endpoints are IP literals
 * (`https://1.1.1.1/dns-query`) or well-known resolver names mapped to their anycast IPs, so
 * the ISP resolver (which answers `discord.com` with the `195.175.254.2` block page) is never
 * consulted and a VPN TUN cannot recurse into itself. Every socket is passed to
 * [protectSocket] (Android `VpnService.protect`). IP-literal hosts send no SNI; the server
 * certificate is validated by the platform trust store and the host/IP SAN is verified
 * through endpoint identification plus an optional platform [verifier]. HTTP/1.1
 * keep-alive connections are pooled per endpoint.
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
                val head = "POST $path HTTP/1.1\r\nHost: $hostHeader\r\nUser-Agent: TheDPI\r\n" +
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

/**
 * User-mode TUN -> Protected Socket Bridge (`tun2socks` + DoH DNS + UDP NAT + Active DPI Desync).
 *
 * Bridges raw IPv4 packets from the Android `VpnService` TUN descriptor (`0.0.0.0/0`) to real
 * outbound TCP/UDP sockets protected with `VpnService.protect()`:
 * 1. **Encrypted DNS (UDP/TCP 53)**: Intercepts DNS queries and resolves them via RFC 8484
 *    DoH3/DoH (`DohClient`) first so ISP DNS poisoning on `discord.com` / `roblox.com` is
 *    bypassed; falls back to `protect()`ed UDP DNS sockets (`1.1.1.1` / `8.8.8.8`).
 * 2. **TCP + TLS/HTTP Desync (Discord TCP 443, HTTPS, Web)**: Terminates the local TUN TCP
 *    3-way handshake, inspects the initial `ClientHello` / HTTP request via the Rust+SIMD
 *    `desyncPacket` engine (`REALITY` + `X25519MLKEM768` + `xtls-rprx-vision`), writes the
 *    split `SNI`/`ECH`/`Host:` segments with `TCP_NODELAY` over a `protect()`ed outbound `Socket`,
 *    and directly splices subsequent TLS 1.3 `ApplicationData` records (`0x17 0x03 0x03`).
 * 3. **Lossless UDP NAT Relay (Roblox RakNet UDP, Discord Voice RTC UDP, QUIC UDP 443)**:
 *    Maintains per-flow NAT bindings over `protect()`ed `DatagramSocket`s and relays UDP
 *    datagrams bidirectionally with zero packet drops.
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
    private val logger: ((String, String) -> Unit)? = null,
) : AutoCloseable {
    private fun log(tag: String, msg: String) {
        logger?.invoke(tag, msg)
    }

    private data class FlowKey(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)

    private val running = AtomicBoolean(false)
    private val writeLock = Any()
    private val ioPool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "thedpi-tun-io").apply { isDaemon = true }
    }
    private var readerThread: Thread? = null
    private val tcpTable = ConcurrentHashMap<FlowKey, TcpFlow>()
    private val udpTable = ConcurrentHashMap<FlowKey, UdpFlow>()
    private val virtualDnsIp: Int = IpPackets.parseIpLiteral(VPN_DNS_IP) ?: 0x0AD7AD02
    private val dnsCache = ConcurrentHashMap<String, Pair<Long, ByteArray>>()
    @Volatile private var preferredDoh = 0

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
    val ipv6Rejected = AtomicInteger(0)
    val bytesUp = java.util.concurrent.atomic.AtomicLong(0)
    val bytesDown = java.util.concurrent.atomic.AtomicLong(0)

    /**
     * Handles seamless Wi-Fi <-> Mobile Data (LTE/5G) roaming by refreshing ephemeral UDP NAT
     * bindings and re-protecting active sockets without tearing down the TUN interface.
     */
    fun rebindActiveSessions() {
        roamingRebinds.incrementAndGet()
        for (u in udpTable.values) {
            u.socket?.let { runCatching { protectDatagram(it) } }
        }
        for (t in tcpTable.values) {
            t.upstreamSocket?.let { runCatching { protectSocket(it) } }
        }
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        log("TunBridge", "TunBridge worker başlatıldı (DoH=${dohEndpoints.size}, DNS=${upstreamDnsServers.size})")
        readerThread = Thread({ readLoop() }, "thedpi-tun-reader").apply {
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
            } catch (_: IOException) {
            }
        }
    }

    private fun readLoop() {
        val buf = ByteArray(32767)
        while (running.get()) {
            val n = try {
                tunInput.read(buf)
            } catch (_: IOException) {
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
                dispatchPacket(pkt)
                off += pktLen
            }
            if (off == 0) {
                dispatchPacket(buf.copyOf(n))
            }
        }
    }

    private fun dispatchPacket(raw: ByteArray) {
        if (raw.isNotEmpty() && ((raw[0].toInt() ushr 4) and 0x0F) == 6) {
            // IPv6 is not bridged: answer immediately so dual-stack apps switch to IPv4 at once.
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
                } else if (blockQuic && udp.dstPort == 443) {
                    // QUIC Initial carries the SNI in a form the stream splitter cannot protect;
                    // refuse it so Chrome/Discord/Roblox fall back to fragmented TLS over TCP.
                    quicFallbacks.incrementAndGet()
                    IpPackets.buildIcmpv4Unreachable(raw)?.let { writeTun(it) }
                } else {
                    handleUdp(raw, udp)
                }
            }
            IpPackets.PROTO_TCP -> {
                val tcp = IpPackets.parseTcp(raw, ip) ?: return
                handleTcp(raw, tcp)
            }
        }
    }

    private fun handleDnsUdp(udp: IpPackets.UdpDatagram) {
        val query = udp.payload
        if (query.size < 12) return
        dnsQueries.incrementAndGet()
        ioPool.execute {
            val answer = resolveDnsQuery(query, udp.ip.dstIp) ?: return@execute
            val reply = IpPackets.buildIpv4Udp(
                srcIp = udp.ip.dstIp,
                dstIp = udp.ip.srcIp,
                srcPort = udp.dstPort,
                dstPort = udp.srcPort,
                payload = answer,
            )
            writeTun(reply)
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
        // 0) TTL-bounded cache keyed by the query without its ID
        val cacheKey = query.copyOfRange(2, query.size).joinToString("") { "%02x".format(it) }
        val now = System.currentTimeMillis()
        dnsCache[cacheKey]?.let { (expiry, msg) ->
            if (expiry > now) {
                dnsCacheHits.incrementAndGet()
                return withId(msg, query)
            }
            dnsCache.remove(cacheKey)
        }
        fun remember(msg: ByteArray): ByteArray {
            val ttl = (IpPackets.dnsMinTtl(msg) ?: 30L).coerceIn(10L, 600L)
            if (dnsCache.size > 2048) dnsCache.clear()
            dnsCache[cacheKey] = (now + ttl * 1000L) to msg
            return withId(msg, query)
        }
        // 1) Encrypted DNS (RFC 8484, ID 0) — the ISP resolver is never consulted.
        val client = dohClient
        val endpoints = dohEndpoints.filter(Doh::validEndpoint)
        if (client != null && endpoints.isNotEmpty()) {
            val dohWire = query.copyOf()
            dohWire[0] = 0
            dohWire[1] = 0
            val first = preferredDoh.coerceIn(0, endpoints.size - 1)
            for (k in endpoints.indices) {
                val idx = (first + k) % endpoints.size
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
        // 2) Fallback: protected UDP to public resolvers only; injected/poisoned replies are skipped.
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

    private fun handleUdp(raw: ByteArray, udp: IpPackets.UdpDatagram) {
        if (udp.payload.isEmpty()) return
        val key = FlowKey(udp.ip.srcIp, udp.srcPort, udp.ip.dstIp, udp.dstPort)
        val flow = udpTable.computeIfAbsent(key) { k ->
            udpFlows.incrementAndGet()
            UdpFlow(k).also { it.start() }
        }
        flow.sendOutbound(raw, udp.payload)
    }

    private inner class UdpFlow(val key: FlowKey) {
        val socket: DatagramSocket? = runCatching {
            DatagramSocket(0).also {
                protectDatagram(it)
                it.soTimeout = 30_000
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
                val buf = ByteArray(16384)
                while (running.get() && !closed.get()) {
                    val dp = DatagramPacket(buf, buf.size)
                    try {
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
                    } catch (_: IOException) {
                        break
                    }
                }
                close()
            }
        }

        fun sendOutbound(rawIpPacket: ByteArray, payload: ByteArray) {
            val s = socket ?: return
            val dst = targetAddress ?: return
            ioPool.execute {
                try {
                    bytesUp.addAndGet(payload.size.toLong())
                    // Apply QUIC Initial scramble via Native.desyncPacket when applicable
                    val res = if (key.dstPort == 443) {
                        runCatching { session.desyncPacket(rawIpPacket, desyncConfig) }.getOrNull()
                    } else {
                        null
                    }
                    if (res != null && res.status == Codes.OK && !res.dropped && res.packets.size > 1) {
                        desyncedFlows.incrementAndGet()
                        for (pkt in res.packets) {
                            val u = IpPackets.parseUdp(pkt) ?: continue
                            if (u.payload.isNotEmpty()) {
                                s.send(DatagramPacket(u.payload, u.payload.size, dst))
                            }
                        }
                    } else {
                        s.send(DatagramPacket(payload, payload.size, dst))
                    }
                } catch (_: IOException) {
                    close()
                }
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                udpTable.remove(key, this)
                runCatching { socket?.close() }
            }
        }
    }

    private fun handleTcp(raw: ByteArray, tcp: IpPackets.TcpSegment) {
        val key = FlowKey(tcp.ip.srcIp, tcp.srcPort, tcp.ip.dstIp, tcp.dstPort)
        val isSyn = (tcp.flags and IpPackets.TCP_SYN) != 0 && (tcp.flags and IpPackets.TCP_ACK) == 0
        val isRst = (tcp.flags and IpPackets.TCP_RST) != 0
        val isFin = (tcp.flags and IpPackets.TCP_FIN) != 0

        if (isRst) {
            tcpTable.remove(key)?.close()
            return
        }
        if (isSyn) {
            tcpTable.remove(key)?.close()
            val flow = TcpFlow(key, (tcp.seq + 1L) and 0xFFFFFFFFL)
            tcpTable[key] = flow
            tcpFlows.incrementAndGet()
            flow.onSyn()
            return
        }
        val flow = tcpTable[key] ?: return
        if (tcp.payload.isNotEmpty()) {
            flow.onClientData(raw, tcp)
        }
        if (isFin) {
            flow.onClientFin(tcp)
        }
    }

    private inner class TcpFlow(val key: FlowKey, var clientNextSeq: Long) {
        val lock = Any()
        var serverSeq: Long = 0x5000_0000L
        var helloBuf: ByteArrayOutputStream? = null
        var connected = false
        var finFromClient = false
        var firstPayloadDone = false
        var visionSpliced = false
        val closed = AtomicBoolean(false)
        val pending = ArrayList<Pair<ByteArray, ByteArray>>()
        @Volatile var upstreamSocket: Socket? = null

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

        fun onClientData(raw: ByteArray, tcp: IpPackets.TcpSegment) {
            val ackPkt: ByteArray
            var immediateSend: Pair<ByteArray, ByteArray>? = null
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
                    val item = raw.copyOf() to tcp.payload.copyOf()
                    if (connected) {
                        immediateSend = item
                    } else {
                        pending.add(item)
                    }
                }
            }
            writeTun(ackPkt)
            immediateSend?.let { (r, p) ->
                synchronized(lock) {
                    sendToUpstreamLocked(r, p)
                }
            }
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
                if (connected) {
                    runCatching { upstreamSocket?.shutdownOutput() }
                }
            }
            writeTun(finAckPkt)
        }

        private fun sendToUpstreamLocked(rawIpPacket: ByteArray, payload: ByteArray) {
            val sock = upstreamSocket ?: return
            try {
                val out = sock.getOutputStream()
                bytesUp.addAndGet(payload.size.toLong())
                if (!firstPayloadDone) {
                    // Reassemble a TLS ClientHello that spans several TCP segments (post-quantum
                    // key shares push it past one MSS) so the SNI can be protected as a whole.
                    val acc = helloBuf
                    val data: ByteArray
                    if (acc != null) {
                        acc.write(payload)
                        data = acc.toByteArray()
                    } else {
                        data = payload
                    }
                    val isTls = data.size >= 5 && (data[0].toInt() and 0xFF) == 0x16 && (data[1].toInt() and 0xFF) == 0x03
                    if (isTls) {
                        val need = 5 + IpPackets.u16(data, 3)
                        if (data.size < need && need <= 16384 + 5) {
                            if (acc == null) helloBuf = ByteArrayOutputStream().apply { write(data) }
                            return
                        }
                    }
                    helloBuf = null
                    firstPayloadDone = true
                    val packet = if (data === payload) rawIpPacket else IpPackets.buildIpv4Tcp(
                        srcIp = key.srcIp, dstIp = key.dstIp, srcPort = key.srcPort, dstPort = key.dstPort,
                        seq = 1L, ack = 1L, flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = data,
                    )
                    val res = runCatching { session.desyncPacket(packet, desyncConfig) }.getOrNull()
                    val nativeChunks = IpPackets.extractOrderedStreamChunks(packet, data, res)
                    val chunks = IpPackets.planFirstPayload(data, nativeChunks)
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
                    for (chunk in chunks) {
                        out.write(chunk)
                        out.flush()
                    }
                } else {
                    if (!visionSpliced && payload.size >= 5 && (payload[0].toInt() and 0xFF) == 0x17 && (payload[1].toInt() and 0xFF) == 0x03) {
                        visionSpliced = true
                        visionSplicedFlows.incrementAndGet()
                    }
                    out.write(payload)
                    out.flush()
                }
            } catch (_: IOException) {
                close()
            }
        }

        private fun connectAndPump() {
            val sock = Socket()
            try {
                protectSocket(sock)
                sock.tcpNoDelay = true
                runCatching { sock.keepAlive = true }
                val dstInet = if (key.dstIp == virtualDnsIp) {
                    InetAddress.getByName(upstreamDnsServers.firstOrNull()?.substringBefore(':') ?: "1.1.1.1")
                } else {
                    InetAddress.getByAddress(IpPackets.ipToBytes(key.dstIp))
                }
                sock.connect(InetSocketAddress(dstInet, key.dstPort), 5000)
                // Long-lived idle streams (Discord gateway heartbeat ≈ 41 s) must not time out.
                sock.soTimeout = 0
                synchronized(lock) {
                    if (closed.get()) {
                        runCatching { sock.close() }
                        return
                    }
                    upstreamSocket = sock
                    connected = true
                    val queued = ArrayList(pending)
                    pending.clear()
                    for ((r, p) in queued) {
                        sendToUpstreamLocked(r, p)
                    }
                    if (finFromClient) {
                        runCatching { sock.shutdownOutput() }
                    }
                }

                val input = sock.getInputStream()
                val buf = ByteArray(1360)
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
            } catch (_: Exception) {
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
                runCatching { upstreamSocket?.close() }
            }
        }
    }

    override fun close() {
        if (running.compareAndSet(true, false)) {
            readerThread?.interrupt()
            for (f in tcpTable.values) f.close()
            for (u in udpTable.values) u.close()
            tcpTable.clear()
            udpTable.clear()
            dnsCache.clear()
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
// ANDROID PLATFORM SECTION
// ==================================================================================

/**
 * CrashLogger & Dahili Debugger:
 * Uygulamanın Android 11–17 cihazlardaki tüm adımlarını, çökmelerini ve hata yığınlarını
 * doğrudan yerel depolama dizinine (`/Android/data/com.the.dpi/files/`) kaydeder.
 *
 * Scoped Storage kuralları gereğince getExternalFilesDir(null) dizini (`/Android/data/com.the.dpi/files`)
 * için herhangi bir özel çalışma zamanı izni (READ/WRITE_EXTERNAL_STORAGE) gerekmez.
 * Kullanıcı telefonundaki Dosya Yöneticisi ile doğrudan bu klasöre girip logları inceleyebilir.
 */
object CrashLogger {
    private const val TAG = "TheDpiCrashLogger"
    private const val CRASH_FILE_NAME = "thedpi_crash.log"
    private const val DEBUG_FILE_NAME = "thedpi_debug.log"
    private const val MAX_DEBUG_LOG_BYTES = 1024 * 1024 // 1 MB döner günlük

    @Volatile private var appContext: Context? = null
    @Volatile private var isInitialized = false
    private val logLock = Any()
    private val dateFormat = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.US).apply {
        timeZone = java.util.TimeZone.getDefault()
    }

    fun init(app: Application) {
        if (isInitialized) return
        appContext = app.applicationContext
        isInitialized = true

        val oldHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                handleUncaughtException(thread, throwable)
            } catch (t: Throwable) {
                android.util.Log.e(TAG, "CrashLogger kendi içinde hata yakaladı: ${t.message}", t)
            } finally {
                oldHandler?.uncaughtException(thread, throwable)
            }
        }

        log("SYSTEM", "CrashLogger & Dahili Debugger başlatıldı.")
        log("SYSTEM", "Paket: ${app.packageName} · Ver: 1.0.0 (1)")
        log("SYSTEM", "Kayıt Yolu: ${getDebugLogPath()}")
    }

    fun log(component: String, message: String, throwable: Throwable? = null) {
        val nowStr = synchronized(dateFormat) { dateFormat.format(java.util.Date()) }
        val threadName = Thread.currentThread().name
        val line = "[$nowStr] [$threadName] [$component] $message"

        if (throwable != null) {
            android.util.Log.e(component, message, throwable)
        } else {
            android.util.Log.i(component, message)
        }

        val ctx = appContext ?: return
        try {
            val targetDir = ctx.getExternalFilesDir(null) ?: ctx.filesDir
            if (!targetDir.exists()) targetDir.mkdirs()
            val debugFile = java.io.File(targetDir, DEBUG_FILE_NAME)
            synchronized(logLock) {
                if (debugFile.exists() && debugFile.length() > MAX_DEBUG_LOG_BYTES) {
                    val bakFile = java.io.File(targetDir, "$DEBUG_FILE_NAME.old")
                    if (bakFile.exists()) bakFile.delete()
                    debugFile.renameTo(bakFile)
                }
                java.io.FileOutputStream(debugFile, true).use { fos ->
                    fos.write(line.toByteArray(Charsets.UTF_8))
                    fos.write('\n'.code)
                    if (throwable != null) {
                        val sw = java.io.StringWriter()
                        throwable.printStackTrace(java.io.PrintWriter(sw))
                        fos.write(sw.toString().toByteArray(Charsets.UTF_8))
                    }
                    fos.flush()
                }
            }
        } catch (_: Throwable) {}
    }

    private fun handleUncaughtException(thread: Thread, throwable: Throwable) {
        val nowStr = synchronized(dateFormat) { dateFormat.format(java.util.Date()) }
        val ctx = appContext
        val sb = java.lang.StringBuilder()
        sb.append("================================================================================\n")
        sb.append("THE DPI (com.the.dpi) — ÇÖKME / HATA RAPORU (CRASH DUMP)\n")
        sb.append("Zaman          : $nowStr\n")
        sb.append("Cihaz          : ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})\n")
        sb.append("Donanım        : Board=${Build.BOARD}, Hardware=${Build.HARDWARE}\n")
        sb.append("Android Sürüm  : ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT}, Build ${Build.DISPLAY})\n")
        sb.append("Desteklenen ABI: ${Build.SUPPORTED_ABIS.joinToString(", ")}\n")
        sb.append("Native Motor   : ${if (Native.available) "Yüklendi (v${try { Native.engineVersion() } catch (_: Throwable) { "?" }})" else "YÜKLENEMEDİ: ${Native.loadError?.message}"}\n")
        sb.append("Tetikleyen Hat : Thread[${thread.name}, id=${thread.id}, prio=${thread.priority}]\n")
        val rt = Runtime.getRuntime()
        sb.append("Bellek (RAM)   : Boş=${rt.freeMemory() / 1024} KB, Toplam=${rt.totalMemory() / 1024} KB, Maks=${rt.maxMemory() / 1024} KB\n")
        sb.append("--------------------------------------------------------------------------------\n")
        sb.append("ÇÖKME DETAYI / HATA YIĞINI:\n")
        val sw = java.io.StringWriter()
        val pw = java.io.PrintWriter(sw)
        throwable.printStackTrace(pw)
        sb.append(sw.toString())
        sb.append("--------------------------------------------------------------------------------\n")
        sb.append("TÜM ÇALIŞAN THREAD'LER:\n")
        try {
            val allStacks = Thread.getAllStackTraces()
            for ((t, stack) in allStacks) {
                sb.append("Thread [${t.name}] (id=${t.id}, state=${t.state}, daemon=${t.isDaemon}):\n")
                for (el in stack) {
                    sb.append("    at $el\n")
                }
            }
        } catch (_: Throwable) {}
        sb.append("================================================================================\n\n")

        val report = sb.toString()
        android.util.Log.e(TAG, report)

        // 1. Harici /Android/data/com.the.dpi/files/thedpi_crash.log
        try {
            val extDir = ctx?.getExternalFilesDir(null)
            if (extDir != null) {
                if (!extDir.exists()) extDir.mkdirs()
                val f = java.io.File(extDir, CRASH_FILE_NAME)
                java.io.FileOutputStream(f, true).use { fos ->
                    fos.write(report.toByteArray(Charsets.UTF_8))
                    fos.flush()
                    try { fos.fd.sync() } catch (_: Throwable) {}
                }
            }
        } catch (_: Throwable) {}

        // 2. Dahili context.filesDir/thedpi_crash.log
        try {
            val intDir = ctx?.filesDir
            if (intDir != null) {
                if (!intDir.exists()) intDir.mkdirs()
                val f = java.io.File(intDir, CRASH_FILE_NAME)
                java.io.FileOutputStream(f, true).use { fos ->
                    fos.write(report.toByteArray(Charsets.UTF_8))
                    fos.flush()
                    try { fos.fd.sync() } catch (_: Throwable) {}
                }
            }
        } catch (_: Throwable) {}

        log("CRASH", "KRİTİK HATA! $CRASH_FILE_NAME dosyasına yazıldı.", throwable)
    }

    fun getCrashLogContent(): String? {
        val ctx = appContext ?: return null
        val ext = ctx.getExternalFilesDir(null)?.let { java.io.File(it, CRASH_FILE_NAME) }
        if (ext?.exists() == true && ext.length() > 0) {
            return runCatching { ext.readText(Charsets.UTF_8) }.getOrNull()
        }
        val intF = java.io.File(ctx.filesDir, CRASH_FILE_NAME)
        if (intF.exists() && intF.length() > 0) {
            return runCatching { intF.readText(Charsets.UTF_8) }.getOrNull()
        }
        return null
    }

    fun getDebugLogPath(): String {
        val ctx = appContext
        val dir = ctx?.getExternalFilesDir(null) ?: ctx?.filesDir
        return dir?.let { java.io.File(it, DEBUG_FILE_NAME).absolutePath } ?: "Bilinmiyor"
    }

    fun getCrashLogPath(): String {
        val ctx = appContext
        val dir = ctx?.getExternalFilesDir(null) ?: ctx?.filesDir
        return dir?.let { java.io.File(it, CRASH_FILE_NAME).absolutePath } ?: "Bilinmiyor"
    }
}

/** Android Application sınıfı: Uygulama ayağa kalktığında ilk çalışan giriş noktası. */
class TheDpiApp : Application() {
    override fun onCreate() {
        super.onCreate()
        CrashLogger.init(this)
        CrashLogger.log("TheDpiApp", "==================================================")
        CrashLogger.log("TheDpiApp", "The DPI (com.the.dpi) v1.0.0 Başlatıldı")
        CrashLogger.log("TheDpiApp", "Cihaz: ${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE}, SDK ${Build.VERSION.SDK_INT}, ABI ${Build.SUPPORTED_ABIS.joinToString(", ")})")
        if (Native.available) {
            try {
                CrashLogger.log("TheDpiApp", "Native Rust motoru yüklendi: v${Native.engineVersion()} (API ${Native.apiVersion()})")
            } catch (t: Throwable) {
                CrashLogger.log("TheDpiApp", "Native motor sürüm sorgusunda hata: ${t.message}", t)
            }
        } else {
            CrashLogger.log("TheDpiApp", "UYARI: Native Rust motoru yüklenemedi: ${Native.loadError?.message}", Native.loadError)
        }
        CrashLogger.log("TheDpiApp", "==================================================")
    }
}

/** Android platform services: ConnectivityManager facts and network-bound platform TLS. */
object AndroidPlatform {
    fun environment(cm: ConnectivityManager): EnvironmentInfo {
        val base = EnvironmentInfo(
            osName = "Android",
            osVersion = Build.VERSION.RELEASE,
            osBuild = Build.VERSION.SDK_INT.toLong(),
            arch = Build.SUPPORTED_ABIS.firstOrNull() ?: "",
        )
        val net = cm.activeNetwork ?: return base.copy(connected = NO)
        val caps = cm.getNetworkCapabilities(net)
        val lp = cm.getLinkProperties(net)
        fun cap(c: Int) = when {
            caps == null -> UNKNOWN
            caps.hasCapability(c) -> YES
            else -> NO
        }
        val type = when {
            caps == null -> NetworkType.UNKNOWN
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> NetworkType.VPN
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
            else -> NetworkType.OTHER
        }
        val addrs = lp?.linkAddresses?.map { it.address } ?: emptyList()
        val notMetered = cap(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        return base.copy(
            networkType = type,
            interfaceName = lp?.interfaceName ?: "",
            dnsServers = lp?.dnsServers?.map(::literal)?.filter { it.isNotEmpty() } ?: emptyList(),
            gateways = lp?.routes?.filter { it.isDefaultRoute && it.hasGateway() }?.mapNotNull { it.gateway?.let(::literal) } ?: emptyList(),
            mtu = lp?.mtu ?: 0,
            hasIpv4 = if (lp == null) UNKNOWN else if (addrs.any { it is Inet4Address && !it.isLinkLocalAddress && !it.isLoopbackAddress }) YES else NO,
            hasIpv6 = if (lp == null) UNKNOWN else if (addrs.any { it is Inet6Address && isGlobal(it) }) YES else NO,
            captive = cap(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            validated = cap(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            metered = when (notMetered) { YES -> NO; NO -> YES; else -> UNKNOWN },
            privateDns = if (lp == null) UNKNOWN else if (lp.isPrivateDnsActive) YES else NO,
            privateDnsName = lp?.privateDnsServerName ?: "",
            connected = YES,
            restrictBackground = if (cm.restrictBackgroundStatus == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED) YES else NO,
        )
    }

    /** IP literal the native core can parse; IPv6 scope is passed numerically ("fe80::1%3"). */
    fun literal(a: InetAddress): String = when (a) {
        is Inet6Address -> {
            val host = (a.hostAddress ?: "").substringBefore('%')
            if (a.scopeId != 0) "$host%${a.scopeId}" else host
        }
        else -> a.hostAddress ?: ""
    }

    private fun isGlobal(a: Inet6Address) = !a.isLinkLocalAddress && !a.isLoopbackAddress && (a.address[0].toInt() and 0xE0) == 0x20

    /**
     * Platform TLS on a socket bound to [net]. Endpoint identification is requested and the
     * platform hostname verifier is applied as well. When system DNS returns poisoned ISP addresses
     * (e.g. Türk Telekom 195.175.254.2), the target address is resolved via clean DoH.
     */
    fun prober(
        net: Network,
        dohClient: DohClient? = null,
        dohEndpoints: List<String> = emptyList(),
    ): TlsProber = TlsProber(
        SSLSocketFactory.getDefault() as SSLSocketFactory,
        { host, port, timeout ->
            val addresses = runCatching { net.getAllByName(host) }.getOrNull() ?: emptyArray()
            val clean = addresses.firstOrNull { addr ->
                val b = addr.address
                if (b.size == 4) {
                    !((b[0].toInt() and 0xFF) == 195 && (b[1].toInt() and 0xFF) == 175 && (b[2].toInt() and 0xFF) == 254) &&
                    (b[0].toInt() and 0xFF) != 127 && (b[0].toInt() and 0xFF) != 0
                } else {
                    !addr.isLoopbackAddress && !addr.isAnyLocalAddress
                }
            }
            val target = clean ?: run {
                val q = Doh.query(host)
                var resolved: InetAddress? = null
                if (q != null && dohClient != null) {
                    val eps = dohEndpoints.ifEmpty { TunBridge.DEFAULT_DOH_ENDPOINTS }
                    for (ep in eps) {
                        val resp = runCatching { dohClient.post(ep, q, 3000) }.getOrNull() ?: continue
                        if (resp.transport == 1 && resp.body != null && resp.body.size >= 12) {
                            val addrs = IpPackets.dnsAnswerAddresses(resp.body)
                            val cleanBytes = addrs?.firstOrNull { a ->
                                val b0 = a[0].toInt() and 0xFF
                                if (a.size == 4) {
                                    !(b0 == 195 && (a[1].toInt() and 0xFF) == 175 && (a[2].toInt() and 0xFF) == 254) && b0 != 127 && b0 != 0
                                } else true
                            }
                            if (cleanBytes != null) {
                                resolved = runCatching { InetAddress.getByAddress(cleanBytes) }.getOrNull()
                                if (resolved != null) break
                            }
                        }
                    }
                }
                resolved ?: net.getByName(host)
            }
            net.socketFactory.createSocket().apply { connect(InetSocketAddress(target, port), timeout) }
        },
        { host, session -> HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session) },
    )
}

/**
 * RFC 8484 DoH through the platform's own HTTP stacks, bound to the active network.
 * Android 14+ (API 34): android.net.http.HttpEngine with QUIC enabled (DoH3 over HTTP/3,
 * falling back to HTTP/2); the negotiated protocol is reported, never assumed.
 * Android 11–13: HttpsURLConnection from Network.openConnection (DoH over HTTP/1.1/2).
 * Certificate validation is the platform's; redirects are refused.
 */
class AndroidDohClient(
    private val context: Context,
    private val network: Network?,
    private val protectSocket: ((Socket) -> Boolean)? = null,
) : DohClient {
    override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse = postEngine(url, body, timeoutMs)

    /** Reads at most [max] bytes (InputStream.readNBytes needs API 33; this path serves API 30+). */
    private fun readBounded(input: java.io.InputStream, max: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (out.size() < max) {
            val n = input.read(buf, 0, minOf(buf.size, max - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun wrapProtectedSslFactory(base: SSLSocketFactory, protect: (Socket) -> Boolean): SSLSocketFactory =
        object : SSLSocketFactory() {
            override fun getDefaultCipherSuites(): Array<String> = base.defaultCipherSuites
            override fun getSupportedCipherSuites(): Array<String> = base.supportedCipherSuites
            override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket =
                base.createSocket(s, host, port, autoClose).also { protect(it) }
            override fun createSocket(host: String?, port: Int): Socket =
                base.createSocket(host, port).also { protect(it) }
            override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
                base.createSocket(host, port, localHost, localPort).also { protect(it) }
            override fun createSocket(host: InetAddress?, port: Int): Socket =
                base.createSocket(host, port).also { protect(it) }
            override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
                base.createSocket(address, port, localAddress, localPort).also { protect(it) }
        }

    private fun postLegacy(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
        val start = System.nanoTime()
        fun rtt() = (System.nanoTime() - start) / 1000
        var conn: HttpsURLConnection? = null
        return try {
            val u = URL(url)
            conn = ((network?.openConnection(u) ?: u.openConnection()) as HttpsURLConnection).apply {
                protectSocket?.let { prot ->
                    sslSocketFactory = wrapProtectedSslFactory(SSLSocketFactory.getDefault() as SSLSocketFactory, prot)
                }
                requestMethod = "POST"
                instanceFollowRedirects = false
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                doOutput = true
                setRequestProperty("Content-Type", "application/dns-message")
                setRequestProperty("Accept", "application/dns-message")
            }
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            val type = conn.contentType ?: ""
            if (code == 200 && type.startsWith("application/dns-message")) {
                val b = conn.inputStream.use { readBounded(it, Wire.MAX_BYTES) }
                DohResponse(1, rtt(), EncProtocol.DOH, b)
            } else {
                DohResponse(6, rtt(), EncProtocol.DOH, null)
            }
        } catch (e: SocketTimeoutException) {
            DohResponse(2, rtt(), EncProtocol.DOH, null)
        } catch (e: UnknownHostException) {
            DohResponse(4, rtt(), EncProtocol.DOH, null)
        } catch (e: ConnectException) {
            DohResponse(4, rtt(), EncProtocol.DOH, null)
        } catch (e: IOException) {
            DohResponse(5, rtt(), EncProtocol.DOH, null)
        } catch (e: RuntimeException) {
            DohResponse(6, rtt(), EncProtocol.DOH, null)
        } finally {
            conn?.disconnect()
        }
    }

    private fun postEngine(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
        // When explicitly protecting sockets inside VpnService without an underlying Network handle,
        // use HttpsURLConnection with the VpnService.protect()-wrapped SSLSocketFactory.
        if (protectSocket != null && network == null) return postLegacy(url, body, timeoutMs)
        // HttpEngine (QUIC/HTTP3) is a platform API from Android 14 (API 34).
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return postLegacy(url, body, timeoutMs)
        val host = runCatching { URL(url).host }.getOrNull() ?: return DohResponse(6, 0, EncProtocol.UNKNOWN, null)
        val engine = HttpEngine.Builder(context)
            .setEnableQuic(true)
            .setEnableHttp2(true)
            .addQuicHint(host, 443, 443)
            .build()
        network?.let { engine.bindToNetwork(it) }
        val executor = Executors.newSingleThreadExecutor()
        val done = CountDownLatch(1)
        val received = java.io.ByteArrayOutputStream()
        var status = 0
        var protocol = ""
        var contentType = ""
        var failure = 0
        val start = System.nanoTime()
        val callback = object : UrlRequest.Callback {
            override fun onRedirectReceived(request: UrlRequest, info: UrlResponseInfo, newLocationUrl: String) {
                failure = 6
                request.cancel()
            }
            override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                status = info.httpStatusCode
                protocol = info.negotiatedProtocol
                contentType = info.headers.asMap["content-type"]?.firstOrNull()
                    ?: info.headers.asMap["Content-Type"]?.firstOrNull() ?: ""
                request.read(ByteBuffer.allocateDirect(Wire.MAX_BYTES))
            }
            override fun onReadCompleted(request: UrlRequest, info: UrlResponseInfo, byteBuffer: ByteBuffer) {
                byteBuffer.flip()
                val chunk = ByteArray(byteBuffer.remaining())
                byteBuffer.get(chunk)
                if (received.size() + chunk.size <= Wire.MAX_BYTES) received.write(chunk) else failure = 6
                byteBuffer.clear()
                if (failure == 0) request.read(byteBuffer) else request.cancel()
            }
            override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) = done.countDown()
            override fun onFailed(request: UrlRequest, info: UrlResponseInfo?, error: HttpException) {
                failure = when ((error as? NetworkException)?.errorCode) {
                    NetworkException.ERROR_TIMED_OUT, NetworkException.ERROR_CONNECTION_TIMED_OUT -> 2
                    NetworkException.ERROR_CONNECTION_REFUSED -> 3
                    NetworkException.ERROR_HOSTNAME_NOT_RESOLVED, NetworkException.ERROR_ADDRESS_UNREACHABLE,
                    NetworkException.ERROR_INTERNET_DISCONNECTED -> 4
                    else -> 5
                }
                done.countDown()
            }
            override fun onCanceled(request: UrlRequest, info: UrlResponseInfo?) {
                if (failure == 0) failure = 2
                done.countDown()
            }
        }
        val upload = object : UploadDataProvider() {
            private var pos = 0
            override fun getLength(): Long = body.size.toLong()
            override fun read(sink: UploadDataSink, buffer: ByteBuffer) {
                val n = minOf(buffer.remaining(), body.size - pos)
                buffer.put(body, pos, n)
                pos += n
                sink.onReadSucceeded(false)
            }
            override fun rewind(sink: UploadDataSink) {
                pos = 0
                sink.onRewindSucceeded()
            }
        }
        val request = engine.newUrlRequestBuilder(url, executor, callback)
            .setHttpMethod("POST")
            .addHeader("Content-Type", "application/dns-message")
            .addHeader("Accept", "application/dns-message")
            .setUploadDataProvider(upload, executor)
            .build()
        try {
            request.start()
            if (!done.await(timeoutMs.toLong(), TimeUnit.MILLISECONDS)) {
                request.cancel()
                done.await(1, TimeUnit.SECONDS)
                failure = 2
            }
        } finally {
            executor.shutdown()
            engine.shutdown()
        }
        val rtt = (System.nanoTime() - start) / 1000
        val proto = if (protocol.startsWith("h3") || protocol.contains("quic")) EncProtocol.DOH3 else EncProtocol.DOH
        return when {
            failure != 0 -> DohResponse(failure, rtt, proto, null)
            status == 200 && contentType.startsWith("application/dns-message") -> DohResponse(1, rtt, proto, received.toByteArray())
            else -> DohResponse(6, rtt, proto, null)
        }
    }
}

/**
 * Local on-device Android VpnService that captures system-wide device traffic (`0.0.0.0/0`)
 * via a local TUN interface and bridges it to external networks through [TunBridge]:
 * - Encrypted DNS (DoH3/DoH) + protected UDP DNS fallback for port 53
 * - TCP/TLS 1.3 & HTTP Active Desync (`SNI`/`ECH`/`Host:` segmentation) over `protect()`ed sockets
 *   for Discord text/login (TCP 443) and web traffic
 * - Lossless UDP NAT forwarding over `protect()`ed `DatagramSocket`s for Roblox in-game RakNet
 *   traffic, Discord Voice RTC channels, and QUIC v1/v2.
 */
class TheDpiVpnService : VpnService() {
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var session: DiagnosticSession? = null
    @Volatile private var bridge: TunBridge? = null
    @Volatile private var roamingCallback: ConnectivityManager.NetworkCallback? = null
    private val running = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        CrashLogger.log("TheDpiVpnService", "onCreate çağrıldı")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        CrashLogger.log("TheDpiVpnService", "onStartCommand çağrıldı (action=${intent?.action})")
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        val customDoh = intent?.getStringArrayListExtra(EXTRA_DOH)?.filter { it.isNotBlank() }.orEmpty()
        val customDns = intent?.getStringArrayListExtra(EXTRA_DNS)?.filter { it.isNotBlank() }.orEmpty()
        if (running.compareAndSet(false, true)) {
            startTunnel(customDoh, customDns)
        }
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "THE DPI Engelsiz Mod Tüneli",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "THE DPI sistem geneli TUN köprüsü ve sansür kalkanı durum bildirimi"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, TheDpiVpnService::class.java).apply {
                action = ACTION_STOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("THE DPI — Engelsiz Mod Aktif")
            .setContentText(statusText)
            .setContentIntent(pendingIntent)
            .addAction(Notification.Action.Builder(null, "Durdur", stopIntent).build())
            .setOngoing(true)
            .build()
    }

    @android.annotation.SuppressLint("InlinedApi")
    private fun startTunnel(customDoh: List<String>, customDns: List<String>) {
        CrashLogger.log("TheDpiVpnService", "startTunnel başlatılıyor... (doh=${customDoh.size}, dns=${customDns.size})")
        createNotificationChannel()
        val notif = buildNotification("Sistem Geneli TUN Köprüsü Devrede (DoH + REALITY/Vision)")
        try {
            if (Build.VERSION.SDK_INT >= 34) { // Android 14+ (UPSIDE_DOWN_CAKE)
                startForeground(NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notif)
            }
            CrashLogger.log("TheDpiVpnService", "startForeground başarıyla çağrıldı (Foreground Service aktif).")
        } catch (e: Throwable) {
            CrashLogger.log("TheDpiVpnService", "startForeground uyarı/hata: ${e.message}", e)
        }

        try {
            val s = DiagnosticSession()
            session = s
            s.startProxy(DesyncConfig(mode = DesyncMode.REALITY_VISION, port = 0))
            val builder = Builder()
                .setSession("THE DPI Engelsiz Mod")
                .setMtu(1500)
                .addAddress(TunBridge.VPN_CLIENT_IP, 30)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(TunBridge.VPN_DNS_IP)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
            // Route IPv6 into TUN so TunBridge answers with immediate ICMPv6 unreachable,
            // preventing dual-stack apps from leaking past the VPN to the ISP.
            runCatching {
                builder.addAddress("fd00:7468:6564:7069::1", 64)
                builder.addRoute("::", 0)
            }
            val pfd = builder.EstablishSafe()
            tun = pfd
            if (pfd != null) {
                CrashLogger.log("TheDpiVpnService", "TUN arabirimi başarıyla açıldı (fd=${pfd.fd})")
                // Sockets inside DirectDohClient and TunBridge are explicitly protected with protect(),
                // allowing MainActivity's diagnostic tests to run through the VPN tunnel without loops.
                val doh = DirectDohClient(
                    protectSocket = { sock -> protect(sock) },
                )
                val b = TunBridge(
                    session = s,
                    tunInput = FileInputStream(pfd.fileDescriptor),
                    tunOutput = FileOutputStream(pfd.fileDescriptor),
                    protectSocket = { sock -> protect(sock) },
                    protectDatagram = { ds -> protect(ds) },
                    dohClient = doh,
                    dohEndpoints = customDoh.ifEmpty { TunBridge.DEFAULT_DOH_ENDPOINTS },
                    upstreamDnsServers = customDns.ifEmpty { TunBridge.DEFAULT_DNS_SERVERS },
                    desyncConfig = DesyncConfig(
                        mode = DesyncMode.REALITY_VISION,
                        fakeTtl = 5,
                        splitPos = 2,
                        dropRst = true,
                    ),
                    blockQuic = true,
                    logger = { tag, msg -> CrashLogger.log(tag, msg) },
                )
                bridge = b
                ActiveBridgeHolder.current = b
                isRunning.set(true)
                b.start()
                CrashLogger.log("TheDpiVpnService", "TunBridge döngüsü başlatıldı.")
                val cm = getSystemService(ConnectivityManager::class.java)
                cm?.activeNetwork?.let { activeNet ->
                    runCatching { setUnderlyingNetworks(arrayOf(activeNet)) }
                }
                registerRoamingCallback()
            } else {
                CrashLogger.log("TheDpiVpnService", "TUN arabirimi açılamadı (pfd == null)!")
                stopTunnel()
            }
        } catch (e: Throwable) {
            CrashLogger.log("TheDpiVpnService", "startTunnel kritik hata: ${e.message}", e)
            stopTunnel()
        }
    }

    private fun registerRoamingCallback() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    runCatching { setUnderlyingNetworks(arrayOf(network)) }
                    bridge?.rebindActiveSessions()
                }
            }
        }
        if (runCatching { cm.registerDefaultNetworkCallback(cb) }.isSuccess) {
            roamingCallback = cb
        }
    }

    private fun Builder.EstablishSafe(): ParcelFileDescriptor? =
        try {
            establish()
        } catch (t: Throwable) {
            CrashLogger.log("TheDpiVpnService", "Builder.establish() başarısız: ${t.message}", t)
            null
        }

    private fun stopTunnel() {
        CrashLogger.log("TheDpiVpnService", "stopTunnel çağrıldı.")
        running.set(false)
        isRunning.set(false)
        ActiveBridgeHolder.current = null
        roamingCallback?.let { cb ->
            val cm = getSystemService(ConnectivityManager::class.java)
            runCatching { cm?.unregisterNetworkCallback(cb) }
        }
        roamingCallback = null
        runCatching { bridge?.close() }
        bridge = null
        runCatching { tun?.close() }
        tun = null
        runCatching { session?.stopProxy(); session?.close() }
        session = null
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (t: Throwable) {
            CrashLogger.log("TheDpiVpnService", "stopForeground hatası: ${t.message}", t)
        }
    }

    override fun onRevoke() {
        CrashLogger.log("TheDpiVpnService", "VPN izni kullanıcı veya sistem tarafından geri çekildi (onRevoke).")
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        CrashLogger.log("TheDpiVpnService", "onDestroy çağrıldı.")
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.the.dpi.STOP_TUNNEL"
        const val EXTRA_DOH = "com.the.dpi.EXTRA_DOH"
        const val EXTRA_DNS = "com.the.dpi.EXTRA_DNS"
        const val NOTIFICATION_CHANNEL_ID = "thedpi_vpn_channel"
        const val NOTIFICATION_ID = 2026
        val isRunning = AtomicBoolean(false)
    }
}

internal object ActiveBridgeHolder {
    @Volatile var current: TunBridge? = null
}

class RadarPulseView(context: Context) : View(context) {
    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 3f * resources.displayMetrics.density
    }
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 13f * resources.displayMetrics.density
    }
    private val subTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        textSize = 10f * resources.displayMetrics.density
        color = Color.parseColor("#94A3B8")
    }
    var isActive = false
        set(value) {
            if (field != value) {
                field = value
                invalidate()
            }
        }
    private var animFraction = 0f
    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 1800L
        repeatCount = ValueAnimator.INFINITE
        repeatMode = ValueAnimator.RESTART
        addUpdateListener {
            animFraction = it.animatedValue as Float
            postInvalidateOnAnimation()
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        animator.start()
    }

    override fun onDetachedFromWindow() {
        animator.cancel()
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        try {
            val cx = width / 2f
            val cy = height / 2f
            val maxR = minOf(cx, cy) * 0.92f
            if (maxR <= 0f) return
            val baseColor = if (isActive) Color.parseColor("#00E676") else Color.parseColor("#00B0FF")
            val r = Color.red(baseColor)
            val g = Color.green(baseColor)
            val b = Color.blue(baseColor)

            // Draw 3 expanding concentric animated radar wave rings
            for (i in 0 until 3) {
                val phase = (animFraction + i * 0.333f) % 1f
                val ringR = maxR * phase
                if (ringR > 0f) {
                    val alpha = ((1f - phase) * 180).toInt().coerceIn(0, 255)
                    ringPaint.color = Color.argb(alpha, r, g, b)
                    canvas.drawCircle(cx, cy, ringR, ringPaint)
                }
            }

            // Center glowing badge orb
            val centerR = maxR * 0.42f
            if (centerR > 0f) {
                glowPaint.color = Color.argb(if (isActive) 55 else 32, r, g, b)
                canvas.drawCircle(cx, cy, centerR * 1.25f, glowPaint)

                glowPaint.color = Color.parseColor(if (isActive) "#064E3B" else "#0C2340")
                canvas.drawCircle(cx, cy, centerR, glowPaint)

                ringPaint.color = Color.argb(240, r, g, b)
                ringPaint.strokeWidth = 2f * resources.displayMetrics.density
                canvas.drawCircle(cx, cy, centerR, ringPaint)

                // Status text in center orb
                textPaint.color = Color.parseColor(if (isActive) "#00E676" else "#38BDF8")
                val statusStr = if (isActive) "ENGELSİZ AKTİF" else "BEKLEMEDE"
                val subStr = if (isActive) "DPI AŞMA & DOH TUNEL" else "SİSTEM GENELİ KORUMA"
                canvas.drawText(statusStr, cx, cy - 2f * resources.displayMetrics.density, textPaint)
                canvas.drawText(subStr, cx, cy + 14f * resources.displayMetrics.density, subTextPaint)
            }
        } catch (_: Throwable) {}
    }
}

class MainActivity : Activity() {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "thedpi-worker").apply { isDaemon = true } }
    private val main = Handler(Looper.getMainLooper())
    private val busy = AtomicBoolean(false)
    @Volatile private var session: DiagnosticSession? = null
    @Volatile private var lastFingerprint: String? = null
    @Volatile private var lastDecision: Decision? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private lateinit var cm: ConnectivityManager
    private lateinit var radarView: RadarPulseView
    private lateinit var cardTcpVal: TextView
    private lateinit var cardTcpSub: TextView
    private lateinit var cardTlsVal: TextView
    private lateinit var cardTlsSub: TextView
    private lateinit var cardUdpVal: TextView
    private lateinit var cardUdpSub: TextView
    private lateinit var cardDnsVal: TextView
    private lateinit var cardDnsSub: TextView
    private lateinit var txTraffic: TextView
    private lateinit var targets: EditText
    private lateinit var altDns: EditText
    private lateinit var dohEndpoints: EditText
    private lateinit var runButton: Button
    private lateinit var desyncButton: Button
    private lateinit var appliedButton: Button
    private lateinit var auto: CheckBox
    private lateinit var status: TextView
    private lateinit var output: TextView

    private val tickerRunnable = object : Runnable {
        override fun run() {
            val isVpn = TheDpiVpnService.isRunning.get()
            val s = session
            val p = s?.proxyStats()
            val b = ActiveBridgeHolder.current
            radarView.isActive = isVpn || (p?.active == true)
            updateDashboardCards(isVpn, p, b)
            main.postDelayed(this, 1000)
        }
    }
    private val networkCheck = Runnable { if (!worker.isShutdown) worker.execute { checkNetwork() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        CrashLogger.log("MainActivity", "onCreate başladı")
        try {
            cm = getSystemService(ConnectivityManager::class.java)
            setContentView(buildUi(savedInstanceState))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
                }
            }
        } catch (t: Throwable) {
            CrashLogger.log("MainActivity", "setContentView / buildUi hatası!", t)
            throw t
        }

        worker.execute {
            try {
                CrashLogger.log("MainActivity", "DiagnosticSession oluşturuluyor...")
                session = DiagnosticSession()
                CrashLogger.log("MainActivity", "DiagnosticSession hazır: v${Native.engineVersion()}")
                ui {
                    status.text = "Motor ${Native.engineVersion()} hazır · 2026–2027 Hibrit Ağ Motoru"
                    runButton.isEnabled = true
                }
            } catch (e: NativeException) {
                CrashLogger.log("MainActivity", "NativeException: ${e.message}", e)
                ui { status.text = "Yerel motor başlatılamadı: ${e.message}" }
            } catch (t: Throwable) {
                CrashLogger.log("MainActivity", "DiagnosticSession başlatma hatası: ${t.message}", t)
                ui { status.text = "Yerel motor hatası: ${t.message}" }
            }
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun ui(block: () -> Unit) {
        main.post { if (!isDestroyed) block() }
    }

    private fun createCardShape(bgColor: String, borderColor: String = "#1E293B", cornerDp: Float = 12f): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            setColor(Color.parseColor(bgColor))
            cornerRadius = cornerDp * resources.displayMetrics.density
            setStroke(dp(1), Color.parseColor(borderColor))
        }
    }

    private fun buildCard(title: String, valColor: String): Triple<LinearLayout, TextView, TextView> {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#131D31")
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(dp(4), dp(4), dp(4), dp(4))
            }
        }
        val titleView = TextView(this).apply {
            text = title
            textSize = 10f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#94A3B8"))
        }
        val valView = TextView(this).apply {
            text = "0"
            textSize = 17f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor(valColor))
            setPadding(0, dp(2), 0, dp(1))
        }
        val subView = TextView(this).apply {
            text = "Hazır"
            textSize = 9.5f
            setTextColor(Color.parseColor("#64748B"))
        }
        root.addView(titleView)
        root.addView(valView)
        root.addView(subView)
        return Triple(root, valView, subView)
    }

    private fun buildUi(state: Bundle?): View {
        val pad = dp(14)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0A0E17"))
            setPadding(pad, pad, pad, pad)
        }

        // Header
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(8))
        }
        val titleText = TextView(this).apply {
            text = "THE DPI"
            textSize = 23f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#00E676"))
        }
        val badgeText = TextView(this).apply {
            text = "  2026–2027 v2.0"
            textSize = 12f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#38BDF8"))
        }
        header.addView(titleText)
        header.addView(badgeText)
        column.addView(header)

        // Animated Radar Pulse
        radarView = RadarPulseView(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(150))
        }
        column.addView(radarView)

        // Traffic Bar
        txTraffic = TextView(this).apply {
            text = "⚡ Ağ Trafiği: ⬆ 0 KB  ⬇ 0 KB"
            textSize = 11f
            gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(4), 0, dp(8))
        }
        column.addView(txTraffic)

        // 4 Live Metric Dashboard Cards (2x2)
        val row1 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        val (c1, v1, s1) = buildCard("⚡ TCP DESYNC", "#00E676")
        val (c2, v2, s2) = buildCard("🛡️ TLS PARÇALAMA", "#38BDF8")
        cardTcpVal = v1; cardTcpSub = s1
        cardTlsVal = v2; cardTlsSub = s2
        row1.addView(c1)
        row1.addView(c2)
        column.addView(row1)

        val row2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        val (c3, v3, s3) = buildCard("🎮 ROBLOX / DISCORD UDP", "#A78BFA")
        val (c4, v4, s4) = buildCard("🔒 ŞİFRELİ DoH DNS", "#FBBF24")
        cardUdpVal = v3; cardUdpSub = s3
        cardDnsVal = v4; cardDnsSub = s4
        row2.addView(c3)
        row2.addView(c4)
        column.addView(row2)

        // Hero Button (Toggle Engelsiz Mod)
        desyncButton = Button(this).apply {
            val isVpn = TheDpiVpnService.isRunning.get()
            text = if (isVpn) {
                "🛡️ ENGELSİZ MODU DURDUR (Sistem Geneli TUN Aktif)"
            } else {
                "⚡ ENGELSİZ MODU BAŞLAT (Sistem Geneli VPN + DPI Aşma)"
            }
            textSize = 13.5f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(if (isVpn) Color.WHITE else Color.parseColor("#0A0E17"))
            background = createCardShape(if (isVpn) "#DC2626" else "#00E676", cornerDp = 14f)
            setPadding(dp(16), dp(14), dp(16), dp(14))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, dp(12), 0, dp(10))
            }
            setOnClickListener { toggleDesync() }
        }
        column.addView(desyncButton)

        // Diagnostic Action Row
        val actRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        runButton = Button(this).apply {
            text = "Ağ Tanıla"
            isEnabled = false
            textSize = 12.5f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.WHITE)
            background = createCardShape("#2563EB", cornerDp = 10f)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(0, 0, dp(4), 0)
            }
            setOnClickListener { startRun(verifyRuns = 1) }
        }
        appliedButton = Button(this).apply {
            text = "Öneriyi Doğrula"
            isEnabled = false
            textSize = 12.5f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#94A3B8"))
            background = createCardShape("#1E293B", cornerDp = 10f)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(dp(4), 0, 0, 0)
            }
            setOnClickListener { applied() }
        }
        actRow.addView(runButton)
        actRow.addView(appliedButton)
        column.addView(actRow)

        // Targets and DNS inputs
        fun label(t: String) = TextView(this).apply {
            text = t
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(8), 0, dp(3))
        }
        column.addView(label("Test hedefleri (her satıra bir tane):"))
        targets = EditText(this).apply {
            setText(state?.getString(KEY_TARGETS) ?: "discord.com\nroblox.com")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 12f
            setTextColor(Color.WHITE)
            background = createCardShape("#162032", cornerDp = 8f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            minLines = 2
        }
        column.addView(targets)

        column.addView(label("Karşılaştırılacak DNS (isteğe bağlı):"))
        altDns = EditText(this).apply {
            setText(state?.getString(KEY_ALT) ?: "")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 12f
            setTextColor(Color.WHITE)
            background = createCardShape("#162032", cornerDp = 8f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            hint = "örn. 1.1.1.1"
            setHintTextColor(Color.parseColor("#475569"))
        }
        column.addView(altDns)

        column.addView(label("Şifreli DoH adresleri (isteğe bağlı, boş bırakılırsa dahili DoH kullanılır):"))
        dohEndpoints = EditText(this).apply {
            setText(state?.getString(KEY_DOH) ?: "")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 12f
            setTextColor(Color.WHITE)
            background = createCardShape("#162032", cornerDp = 8f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            hint = "örn. https://1.1.1.1/dns-query"
            setHintTextColor(Color.parseColor("#475569"))
        }
        column.addView(dohEndpoints)

        auto = CheckBox(this).apply {
            text = "Ağ değişince yeniden tanıla (ölçülü ağlarda çalışmaz)"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            isChecked = state?.getBoolean(KEY_AUTO) ?: false
        }
        column.addView(auto)

        status = TextView(this).apply {
            textSize = 11.5f
            setTextColor(Color.parseColor("#38BDF8"))
            setPadding(0, dp(6), 0, dp(6))
        }
        column.addView(status)

        output = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11.5f
            setTextColor(Color.parseColor("#E2E8F0"))
            background = createCardShape("#0D131F", borderColor = "#1E293B", cornerDp = 10f)
            setPadding(dp(10), dp(10), dp(10), dp(10))
            setTextIsSelectable(true)
            text = state?.getString(KEY_OUTPUT) ?: ""
        }
        column.addView(output)

        val logInfo = TextView(this).apply {
            text = "📁 Dahili Debugger & Günlük:\n/Android/data/com.the.dpi/files/thedpi_debug.log\n(Çökmeler: thedpi_crash.log dosyasına kaydedilir)"
            textSize = 10f
            setTextColor(Color.parseColor("#64748B"))
            setPadding(0, dp(10), 0, dp(12))
        }
        column.addView(logInfo)

        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#0A0E17"))
            addView(column)
            isFillViewport = true
        }
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            val b = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime() or WindowInsets.Type.displayCutout())
            v.setPadding(b.left, b.top, b.right, b.bottom)
            WindowInsets.CONSUMED
        }
        return scroll
    }

    private fun updateDashboardCards(isVpn: Boolean, p: ProxyStatus?, b: TunBridge?) {
        val tcp = b?.tcpFlows?.get() ?: 0
        val desync = b?.desyncedFlows?.get() ?: 0
        val vision = b?.visionSplicedFlows?.get() ?: 0
        cardTcpVal.text = "$tcp Akış"
        cardTcpSub.text = "Desync: $desync · Splice: $vision"

        val tlsFrag = b?.tlsRecordFragmented?.get() ?: 0
        val tlsSplit = p?.tlsSplit ?: 0
        cardTlsVal.text = "$tlsFrag Kayıt"
        cardTlsSub.text = "TLS Bölme: $tlsSplit · RST Kalkanı: ${p?.rstDropped ?: 0}"

        val udp = b?.udpFlows?.get() ?: 0
        val quicFall = b?.quicFallbacks?.get() ?: 0
        cardUdpVal.text = "$udp Akış"
        cardUdpSub.text = "NAT Ses/Oyun · QUIC Geçiş: $quicFall"

        val dns = b?.dnsQueries?.get() ?: 0
        val doh = b?.dohResolved?.get() ?: 0
        val poison = b?.poisonedDnsBlocked?.get() ?: 0
        cardDnsVal.text = "$dns Sorgu"
        cardDnsSub.text = "DoH: $doh · Zehir Engeli: $poison"

        val upKb = (b?.bytesUp?.get() ?: 0L) / 1024
        val downKb = (b?.bytesDown?.get() ?: 0L) / 1024
        txTraffic.text = if (isVpn) {
            "🛡️ VPN Tüneli: ⬆ $upKb KB  ⬇ $downKb KB · IPv6 Reddedildi: ${b?.ipv6Rejected?.get() ?: 0}"
        } else {
            "⚡ Ağ Trafiği: ⬆ $upKb KB  ⬇ $downKb KB"
        }
    }

    override fun onStart() {
        super.onStart()
        main.post(tickerRunnable)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = scheduleCheck()
            override fun onLost(network: Network) = scheduleCheck()
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = scheduleCheck()
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = scheduleCheck()
        }
        cm.registerDefaultNetworkCallback(cb, main)
        callback = cb
    }

    override fun onStop() {
        main.removeCallbacks(tickerRunnable)
        callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        callback = null
        main.removeCallbacks(networkCheck)
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_TARGETS, targets.text.toString())
        outState.putString(KEY_ALT, altDns.text.toString())
        outState.putString(KEY_DOH, dohEndpoints.text.toString())
        outState.putBoolean(KEY_AUTO, auto.isChecked)
        outState.putString(KEY_OUTPUT, output.text.toString().take(64 * 1024))
    }

    override fun onDestroy() {
        main.removeCallbacksAndMessages(null)
        worker.shutdownNow()
        session?.close()
        session = null
        super.onDestroy()
    }

    private fun scheduleCheck() {
        main.removeCallbacks(networkCheck)
        main.postDelayed(networkCheck, 1000)
    }

    private fun fingerprint(env: EnvironmentInfo) = env.fingerprint() + "|" + (cm.activeNetwork?.toString() ?: "-")

    private fun checkNetwork() {
        val s = session ?: return
        val env = AndroidPlatform.environment(cm)
        val fp = fingerprint(env)
        val prev = lastFingerprint
        lastFingerprint = fp
        if (prev == null || prev == fp) return
        s.networkChanged()
        s.setEnvironment(env)
        ui {
            status.text = "Ağ değişti (${Text.networkType(env.networkType)}); önceki sonuçlar geçersiz."
            appliedButton.isEnabled = false
            if (auto.isChecked && env.metered != YES && !busy.get()) startRun(verifyRuns = 0)
        }
    }

    private fun startRun(verifyRuns: Int) {
        val s = session ?: return
        if (!busy.compareAndSet(false, true)) return
        val targetList = split(targets.text.toString())
        val altList = split(altDns.text.toString())
        val dohList = split(dohEndpoints.text.toString()).ifEmpty { TunBridge.DEFAULT_DOH_ENDPOINTS }
        runButton.isEnabled = false
        appliedButton.isEnabled = false
        status.text = "Tanılanıyor (Poison-Free DoH & TLS)..."
        worker.execute {
            try {
                var text = ""
                var remaining = verifyRuns + 1
                while (remaining-- > 0) {
                    val env = AndroidPlatform.environment(cm)
                    val fp = fingerprint(env)
                    if (lastFingerprint != null && lastFingerprint != fp) s.networkChanged()
                    lastFingerprint = fp
                    s.setEnvironment(env)
                    val net = cm.activeNetwork
                    val dohClient = AndroidDohClient(applicationContext, net)
                    val report = s.run(
                        targetList, altList,
                        net?.let { AndroidPlatform.prober(it, dohClient, dohList) },
                        dohClient, dohList,
                    )
                    lastDecision = report.evaluation?.decision
                    text = Text.environment(env) + "\n" + Text.report(report)
                }
                ui {
                    output.text = text
                    status.text = "Tamamlandı"
                    val d = lastDecision
                    appliedButton.isEnabled = d != null && d.state == 2 && d.action != 0 && d.action != 8
                    if (appliedButton.isEnabled) {
                        appliedButton.setTextColor(Color.WHITE)
                        appliedButton.background = createCardShape("#10B981", cornerDp = 10f)
                    }
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
        val s = session ?: run {
            CrashLogger.log("MainActivity", "toggleDesync: session null!")
            return
        }
        val vpnActive = TheDpiVpnService.isRunning.get()
        val proxyActive = s.proxyStats().active
        CrashLogger.log("MainActivity", "toggleDesync tıklandı: vpnActive=$vpnActive, proxyActive=$proxyActive")
        if (vpnActive || proxyActive) {
            runCatching {
                startService(Intent(this, TheDpiVpnService::class.java).setAction(TheDpiVpnService.ACTION_STOP))
            }
            worker.execute {
                try {
                    s.stopProxy()
                    val next = s.proxyStats()
                    val text = Text.vpnStatus(false, next)
                    ui {
                        output.text = text + "\n" + output.text.toString()
                        desyncButton.text = "⚡ ENGELSİZ MODU BAŞLAT (Sistem Geneli VPN + DPI Aşma)"
                        desyncButton.setTextColor(Color.parseColor("#0A0E17"))
                        desyncButton.background = createCardShape("#00E676", cornerDp = 14f)
                        radarView.isActive = false
                        status.text = "Engelsiz Mod durduruldu"
                    }
                    CrashLogger.log("MainActivity", "Engelsiz Mod durduruldu.")
                } catch (t: Throwable) {
                    CrashLogger.log("MainActivity", "stopProxy hatası", t)
                }
            }
            return
        }
        val prepIntent = try {
            VpnService.prepare(this)
        } catch (t: Throwable) {
            CrashLogger.log("MainActivity", "VpnService.prepare hatası: ${t.message}", t)
            null
        }
        if (prepIntent != null) {
            CrashLogger.log("MainActivity", "VPN hazırlık intent'i başlatılıyor...")
            status.text = "Sistem geneli DPI aşma için VPN izni bekleniyor…"
            @Suppress("DEPRECATION")
            startActivityForResult(prepIntent, REQ_VPN)
        } else {
            CrashLogger.log("MainActivity", "VPN hazırlık intent'i null (izin zaten var).")
            activateEngelsizMod(vpnGranted = true)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        CrashLogger.log("MainActivity", "onActivityResult: requestCode=$requestCode, resultCode=$resultCode")
        if (requestCode == REQ_VPN) {
            activateEngelsizMod(vpnGranted = (resultCode == RESULT_OK))
        }
    }

    private fun activateEngelsizMod(vpnGranted: Boolean) {
        val s = session ?: run {
            CrashLogger.log("MainActivity", "activateEngelsizMod: session null!")
            return
        }
        CrashLogger.log("MainActivity", "activateEngelsizMod çağrıldı (vpnGranted=$vpnGranted)")
        val dohList = ArrayList(split(dohEndpoints.text.toString()))
        val dnsList = ArrayList(split(altDns.text.toString()))
        if (vpnGranted) {
            runCatching {
                val vpnIntent = Intent(this, TheDpiVpnService::class.java)
                    .putStringArrayListExtra(TheDpiVpnService.EXTRA_DOH, dohList)
                    .putStringArrayListExtra(TheDpiVpnService.EXTRA_DNS, dnsList)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(vpnIntent)
                } else {
                    startService(vpnIntent)
                }
                CrashLogger.log("MainActivity", "TheDpiVpnService startForegroundService çağrıldı")
            }.onFailure {
                CrashLogger.log("MainActivity", "TheDpiVpnService başlatılamadı!", it)
            }
        }
        worker.execute {
            try {
                val next = s.startProxy(DesyncConfig(mode = DesyncMode.REALITY_VISION, port = 0))
                CrashLogger.log("MainActivity", "startProxy tamamlandı: active=${next.active}, port=${next.port}")
                val b = ActiveBridgeHolder.current
                val text = Text.vpnStatus(
                    vpnActive = vpnGranted,
                    p = next,
                    tcpFlows = b?.tcpFlows?.get() ?: 0,
                    udpFlows = b?.udpFlows?.get() ?: 0,
                    dnsQueries = b?.dnsQueries?.get() ?: 0,
                    dohResolved = b?.dohResolved?.get() ?: 0,
                    desyncedFlows = b?.desyncedFlows?.get() ?: 0,
                    visionSplicedFlows = b?.visionSplicedFlows?.get() ?: 0,
                    poisonedBlocked = b?.poisonedDnsBlocked?.get() ?: 0,
                    quicFallbacks = b?.quicFallbacks?.get() ?: 0,
                    tlsFragmented = b?.tlsRecordFragmented?.get() ?: 0,
                    bytesUp = b?.bytesUp?.get() ?: 0L,
                    bytesDown = b?.bytesDown?.get() ?: 0L,
                )
                ui {
                    output.text = text + "\n" + output.text.toString()
                    radarView.isActive = true
                    if (vpnGranted) {
                        desyncButton.text = "🛡️ ENGELSİZ MOD ETKİN (Sistem Geneli VPN + 127.0.0.1:${next.port})"
                        desyncButton.setTextColor(Color.WHITE)
                        desyncButton.background = createCardShape("#DC2626", cornerDp = 14f)
                        status.text = "Engelsiz Mod etkin: Sistem Geneli VPN (Discord/Roblox TCP+UDP+DoH) + 127.0.0.1:${next.port}"
                    } else {
                        desyncButton.text = "🛡️ YEREL PROXY ETKİN (127.0.0.1:${next.port})"
                        desyncButton.setTextColor(Color.WHITE)
                        desyncButton.background = createCardShape("#D97706", cornerDp = 14f)
                        status.text = "VPN izni verilmedi; yalnızca yerel proxy etkin (127.0.0.1:${next.port})"
                    }
                }
            } catch (t: Throwable) {
                CrashLogger.log("MainActivity", "activateEngelsizMod worker hatası", t)
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

    private fun split(s: String) = s.split('\n', ',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }

    private companion object {
        const val REQ_VPN = 1001
        const val REQ_NOTIF = 1002
        const val KEY_TARGETS = "targets"
        const val KEY_ALT = "alt"
        const val KEY_DOH = "doh"
        const val KEY_AUTO = "auto"
        const val KEY_OUTPUT = "output"
    }
}
