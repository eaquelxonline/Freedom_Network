// Freedom Network — Android 11–17 application (Kotlin, native Android SDK Views, Rust .so via JNI).
//
// Self-contained: the JNI boundary (class com.freedom.network.Native), the wire codec mirrored
// from Native/Core.rs, typed models, the platform-TLS prober, the diagnostic session
// orchestrator, the Turkish text catalogue, and this platform's integration.
// The shared section below is kept byte-identical with the other platform module.

package com.freedom.network

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
import android.app.AlertDialog
import android.view.HapticFeedbackConstants
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
import android.graphics.Path
import android.graphics.LinearGradient
import android.graphics.RadialGradient
import android.graphics.SweepGradient
import android.graphics.Shader
import android.graphics.DashPathEffect
import android.view.MotionEvent
import android.widget.Toast
import android.content.ClipboardManager
import android.content.ClipData
import android.widget.FrameLayout
import android.view.ViewGroup
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
import android.widget.Switch
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.channels.DatagramChannel
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
    fun sanitizePlainHttpHeaders(
        payload: ByteArray,
        persona: DevicePersona? = null,
        stripGeoHeaders: Boolean = true,
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
        kept.add(lines[0])
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
) {
    fun privateKeyBytes(): ByteArray? = runCatching {
        java.util.Base64.getDecoder().decode(privateKeyB64).takeIf { it.size == 32 }
    }.getOrNull()

    fun peerPublicKeyBytes(): ByteArray? = runCatching {
        java.util.Base64.getDecoder().decode(peerPublicKeyB64).takeIf { it.size == 32 }
    }.getOrNull()

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
        for (p in intArrayOf(2408, 500, 4500, 1701, 894, 854)) {
            list.add(identity.endpointHost to p)
        }
        list.add("162.159.192.1" to 2408)
        list.add("162.159.193.1" to 2408)
        list.add("162.159.192.1" to 500)
        list.add("162.159.193.1" to 4500)
        list.add("162.159.195.1" to 2408)
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
                    lastRxMs = now
                    lastTxMs = now
                    sendIpPacket(ByteArray(0))
                    logger?.invoke(
                        "WarpTunnel",
                        "WARP WireGuard el sıkışması tamamlandı -> ${activeEndpoint?.hostString}:${activeEndpoint?.port}",
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
            while (!closed.get() && established) {
                try {
                    Thread.sleep(22_000L)
                } catch (_: InterruptedException) {
                    break
                }
                if (closed.get() || !established) break
                if (System.currentTimeMillis() - lastTxMs >= 20_000L) {
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
    private val dnsCache = ConcurrentHashMap<String, Pair<Long, ByteArray>>()
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
        dnsCache[cacheKey]?.let { (expiry, msg) ->
            if (expiry > now) {
                dnsCacheHits.incrementAndGet()
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
            dnsCache[cacheKey] = (now + ttl * 1000L) to msg
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
                            )
                            if (cleanData !== data) {
                                leaksBlocked.incrementAndGet()
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
// ANDROID PLATFORM SECTION
// ==================================================================================

/**
 * CrashLogger & Dahili Debugger:
 * Uygulamanın Android 11–17 cihazlardaki tüm adımlarını, çökmelerini ve hata yığınlarını
 * doğrudan yerel depolama dizinine (`/Android/data/com.freedom.network/files/`) kaydeder.
 *
 * Scoped Storage kuralları gereğince getExternalFilesDir(null) dizini (`/Android/data/com.freedom.network/files`)
 * için herhangi bir özel çalışma zamanı izni (READ/WRITE_EXTERNAL_STORAGE) gerekmez.
 * Kullanıcı telefonundaki Dosya Yöneticisi ile doğrudan bu klasöre girip logları inceleyebilir.
 */
object CrashLogger {
    private const val TAG = "FreedomCrashLogger"
    private const val CRASH_FILE_NAME = "freedom_crash.log"
    private const val DEBUG_FILE_NAME = "freedom_debug.log"
    private const val MAX_DEBUG_LOG_BYTES = 1024 * 1024 // 1 MB döner günlük
    private const val MAX_MEM_LOGS = 240

    @Volatile private var appContext: Context? = null
    @Volatile private var isInitialized = false
    private val logLock = Any()
    private val memLogs = ArrayDeque<String>(MAX_MEM_LOGS)
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

        val ctx = appContext
        try {
            synchronized(logLock) {
                if (memLogs.size >= MAX_MEM_LOGS) memLogs.removeFirst()
                memLogs.addLast(if (throwable != null) "$line (${throwable.javaClass.simpleName}: ${throwable.message})" else line)

                if (ctx != null) {
                    val targetDir = ctx.getExternalFilesDir(null) ?: ctx.filesDir
                    if (!targetDir.exists()) targetDir.mkdirs()
                    val debugFile = java.io.File(targetDir, DEBUG_FILE_NAME)
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
            }
        } catch (_: Throwable) {}
    }

    fun getRecentLogs(limit: Int = 150): String {
        val fromFile = runCatching {
            val ctx = appContext ?: return@runCatching null
            val candidates = listOfNotNull(
                ctx.getExternalFilesDir(null)?.let { java.io.File(it, DEBUG_FILE_NAME) },
                java.io.File(ctx.filesDir, DEBUG_FILE_NAME),
            )
            val existing = candidates.firstOrNull { it.exists() && it.length() > 0 } ?: return@runCatching null
            synchronized(logLock) {
                existing.readLines(Charsets.UTF_8).takeLast(limit).joinToString("\n")
            }
        }.getOrNull()
        if (!fromFile.isNullOrBlank()) return fromFile
        synchronized(logLock) {
            if (memLogs.isNotEmpty()) return memLogs.takeLast(limit).joinToString("\n")
        }
        return "Henüz günlük kaydı oluşturulmadı."
    }

    private fun handleUncaughtException(thread: Thread, throwable: Throwable) {
        val nowStr = synchronized(dateFormat) { dateFormat.format(java.util.Date()) }
        val ctx = appContext
        val sb = java.lang.StringBuilder()
        sb.append("================================================================================\n")
        sb.append("FREEDOM NETWORK (com.freedom.network) — ÇÖKME / HATA RAPORU (CRASH DUMP)\n")
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

        // 1. Harici /Android/data/com.freedom.network/files/freedom_crash.log
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

        // 2. Dahili context.filesDir/freedom_crash.log
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
class FreedomApp : Application() {
    override fun onCreate() {
        super.onCreate()
        CrashLogger.init(this)
        CrashLogger.log("FreedomApp", "==================================================")
        CrashLogger.log("FreedomApp", "Freedom Network (com.freedom.network) v1.0.0 Başlatıldı")
        CrashLogger.log("FreedomApp", "Cihaz: ${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE}, SDK ${Build.VERSION.SDK_INT}, ABI ${Build.SUPPORTED_ABIS.joinToString(", ")})")
        if (Native.available) {
            try {
                CrashLogger.log("FreedomApp", "Native Rust motoru yüklendi: v${Native.engineVersion()} (API ${Native.apiVersion()})")
            } catch (t: Throwable) {
                CrashLogger.log("FreedomApp", "Native motor sürüm sorgusunda hata: ${t.message}", t)
            }
        } else {
            CrashLogger.log("FreedomApp", "UYARI: Native Rust motoru yüklenemedi: ${Native.loadError?.message}", Native.loadError)
        }
        CrashLogger.log("FreedomApp", "==================================================")
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
 * NullIslandLocationShield:
 * When enabled and selected as the system Mock Location app in Android Developer Options,
 * injects Null Island (0.0°, 0.0°) synthetic coordinates across GPS, Network, and API 31+ Fused
 * providers every 2 seconds so location-seeking apps cannot read real GNSS/Wi-Fi coordinates.
 * Fails cleanly (without crashing) if Developer Options mock permission has not yet been granted.
 */
object NullIslandLocationShield {
    private val active = AtomicBoolean(false)
    @Volatile var lastStatusText: String = "Kapalı (gerçek konum sistem kontrolünde)"
        private set
    @Volatile var needsDeveloperPermission: Boolean = false
        private set
    private var workerThread: Thread? = null

    val isActive: Boolean get() = active.get()

    @Suppress("DEPRECATION")
    @android.annotation.SuppressLint("WrongConstant")
    private fun addAndPushProviderLegacy(lm: android.location.LocationManager, provider: String) {
        runCatching { lm.removeTestProvider(provider) }
        lm.addTestProvider(
            provider,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            android.location.Criteria.POWER_LOW,
            android.location.Criteria.ACCURACY_FINE,
        )
        lm.setTestProviderEnabled(provider, true)
    }

    private fun pushNullIsland(lm: android.location.LocationManager, provider: String) {
        val loc = android.location.Location(provider).apply {
            latitude = 0.0
            longitude = 0.0
            altitude = 0.0
            accuracy = 1.0f
            bearing = 0.0f
            speed = 0.0f
            time = System.currentTimeMillis()
            elapsedRealtimeNanos = android.os.SystemClock.elapsedRealtimeNanos()
        }
        lm.setTestProviderLocation(provider, loc)
    }

    fun start(context: Context): Boolean {
        if (active.get()) return true
        val lm = context.getSystemService(android.location.LocationManager::class.java) ?: run {
            lastStatusText = "Konum servisi bulunamadı"
            return false
        }
        val providers = if (Build.VERSION.SDK_INT >= 31) {
            listOf(
                android.location.LocationManager.GPS_PROVIDER,
                android.location.LocationManager.NETWORK_PROVIDER,
                "fused",
            )
        } else {
            listOf(
                android.location.LocationManager.GPS_PROVIDER,
                android.location.LocationManager.NETWORK_PROVIDER,
            )
        }
        var registeredAny = false
        var securityDenied = false
        for (p in providers) {
            try {
                if (Build.VERSION.SDK_INT >= 31) {
                    val props = android.location.provider.ProviderProperties.Builder()
                        .setHasAltitudeSupport(true)
                        .setHasBearingSupport(true)
                        .setHasSpeedSupport(true)
                        .setPowerUsage(android.location.provider.ProviderProperties.POWER_USAGE_LOW)
                        .setAccuracy(android.location.provider.ProviderProperties.ACCURACY_FINE)
                        .build()
                    runCatching { lm.removeTestProvider(p) }
                    lm.addTestProvider(p, props)
                    lm.setTestProviderEnabled(p, true)
                } else {
                    addAndPushProviderLegacy(lm, p)
                }
                pushNullIsland(lm, p)
                registeredAny = true
            } catch (_: SecurityException) {
                securityDenied = true
            } catch (t: Throwable) {
                CrashLogger.log("NullIslandLocationShield", "Sağlayıcı ($p) uyarısı: ${t.message}")
            }
        }
        if (!registeredAny) {
            needsDeveloperPermission = securityDenied
            lastStatusText = if (securityDenied) {
                "Geliştirici Seçenekleri'nden 'Sahte Konum Uygulaması' olarak Freedom Network seçin"
            } else {
                "Konum kalkanı başlatılamadı"
            }
            return false
        }
        needsDeveloperPermission = false
        active.set(true)
        lastStatusText = "Aktif · 0.0000°, 0.0000° (Null Island)"
        CrashLogger.log("NullIslandLocationShield", "Null Island (0.0, 0.0) konum kalkanı başlatıldı")
        workerThread = Thread({
            while (active.get()) {
                for (p in providers) {
                    runCatching { pushNullIsland(lm, p) }
                }
                try {
                    Thread.sleep(2000L)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }, "freedom-null-island").apply {
            isDaemon = true
            start()
        }
        return true
    }

    fun stop(context: Context) {
        if (!active.compareAndSet(true, false)) {
            if (!needsDeveloperPermission) {
                lastStatusText = "Kapalı (gerçek konum sistem kontrolünde)"
            }
            return
        }
        runCatching { workerThread?.interrupt() }
        workerThread = null
        val lm = context.getSystemService(android.location.LocationManager::class.java)
        val providers = if (Build.VERSION.SDK_INT >= 31) {
            listOf(
                android.location.LocationManager.GPS_PROVIDER,
                android.location.LocationManager.NETWORK_PROVIDER,
                "fused",
            )
        } else {
            listOf(
                android.location.LocationManager.GPS_PROVIDER,
                android.location.LocationManager.NETWORK_PROVIDER,
            )
        }
        for (p in providers) {
            runCatching { lm?.removeTestProvider(p) }
        }
        lastStatusText = "Kapalı (gerçek konum sistem kontrolünde)"
        CrashLogger.log("NullIslandLocationShield", "Null Island konum kalkanı durduruldu")
    }

    fun openDeveloperOptions(activity: Activity) {
        val devIntent = Intent(android.provider.Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
        val fallbackIntent = Intent(android.provider.Settings.ACTION_SETTINGS)
        runCatching { activity.startActivity(devIntent) }.onFailure {
            runCatching { activity.startActivity(fallbackIntent) }
        }
    }
}

/**
 * Local on-device Android VpnService that captures system-wide device traffic (`0.0.0.0/0` + `::/0`)
 * via a local TUN interface and bridges it through [TunBridge]:
 * - Built-in zero-config Cloudflare WARP WireGuard (auto-fallback to local Tor SOCKS5 `:9050` or Direct DPI+DoH3)
 * - Happy Eyeballs Encrypted DNS (DoH3/DoH) + DNS-Rebinding Filter + AAAA Suppression + Privacy Tracker Guard + Strict Kill Switch
 * - Universal TCP/TLS 1.3 & ECH Active Desync + HTTP DevicePersona / Geo-Header Sanitization
 * - Low-latency UDP NAT forwarding over `protect()`ed `DatagramSocket`s with WebRTC/STUN leak protection.
 */
class FreedomVpnService : VpnService() {
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var session: DiagnosticSession? = null
    @Volatile private var bridge: TunBridge? = null
    @Volatile private var roamingCallback: ConnectivityManager.NetworkCallback? = null
    private val running = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        CrashLogger.log("FreedomVpnService", "onCreate çağrıldı")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        CrashLogger.log("FreedomVpnService", "onStartCommand çağrıldı (action=${intent?.action})")
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        val customDoh = intent?.getStringArrayListExtra(EXTRA_DOH)?.filter { it.isNotBlank() }.orEmpty()
        val customDns = intent?.getStringArrayListExtra(EXTRA_DNS)?.filter { it.isNotBlank() }.orEmpty()
        val killSwitch = intent?.getBooleanExtra(EXTRA_KILL_SWITCH, true) ?: true
        val blockTrackers = intent?.getBooleanExtra(EXTRA_BLOCK_TRACKERS, true) ?: true
        val stunShield = intent?.getBooleanExtra(EXTRA_STUN_SHIELD, true) ?: true
        val quicPassthrough = intent?.getBooleanExtra(EXTRA_QUIC_PASSTHROUGH, false) ?: false
        val exitRelay = intent?.getStringExtra(EXTRA_EXIT_RELAY)?.trim().orEmpty()
        val mockLocation = intent?.getBooleanExtra(EXTRA_MOCK_LOCATION, false) ?: false
        val personaId = intent?.getStringExtra(EXTRA_PERSONA).orEmpty()
        if (running.compareAndSet(false, true)) {
            startTunnel(
                customDoh = customDoh,
                customDns = customDns,
                killSwitch = killSwitch,
                blockTrackers = blockTrackers,
                stunShield = stunShield,
                quicPassthrough = quicPassthrough,
                exitRelay = exitRelay,
                mockLocation = mockLocation,
                persona = DevicePersona.fromId(personaId),
            )
        }
        return START_STICKY
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "Freedom Network Özgür Ağ Tüneli",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Freedom Network sistem geneli şifreli TUN köprüsü ve gizlilik kalkanı"
            setShowBadge(false)
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm?.createNotificationChannel(channel)
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
            Intent(this, FreedomVpnService::class.java).apply {
                action = ACTION_STOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Freedom Network — Koruma Aktif")
            .setContentText(statusText)
            .setContentIntent(pendingIntent)
            .addAction(Notification.Action.Builder(null, "Durdur", stopIntent).build())
            .setOngoing(true)
            .build()
    }

    private fun updateRouteNotification(routeLabel: String, masked: Boolean) {
        if (!running.get()) return
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val msg = if (masked) {
            "IP Gizli ($routeLabel) · DoH3 + Kalkan"
        } else {
            "$routeLabel · Sansür Kalkanı Aktif"
        }
        runCatching {
            val nm = getSystemService(NotificationManager::class.java)
            nm?.notify(NOTIFICATION_ID, buildNotification(msg))
        }
    }

    @android.annotation.SuppressLint("InlinedApi")
    private fun startTunnel(
        customDoh: List<String>,
        customDns: List<String>,
        killSwitch: Boolean,
        blockTrackers: Boolean,
        stunShield: Boolean,
        quicPassthrough: Boolean,
        exitRelay: String,
        mockLocation: Boolean,
        persona: DevicePersona,
    ) {
        val parsedRelay = ExitRelayConfig.parse(exitRelay)
        val useAutoWarp = parsedRelay == null
        val prefs = getSharedPreferences("freedom_prefs", Context.MODE_PRIVATE)
        val savedWarp = WarpIdentity.deserialize(prefs.getString(PREF_WARP_IDENTITY, null))

        CrashLogger.log(
            "FreedomVpnService",
            "startTunnel başlatılıyor... (autoWarp=$useAutoWarp, cachedWarp=${savedWarp != null}, persona=${persona.id}, mockLoc=$mockLocation, killSwitch=$killSwitch, trackers=$blockTrackers, stunShield=$stunShield, relay=${parsedRelay?.label() ?: "yok"})",
        )
        createNotificationChannel()
        val notifText = when {
            parsedRelay != null -> "Çıkış IP Gizli (${parsedRelay.label()}) + DoH3"
            useAutoWarp -> "WARP WireGuard Tüneli Bağlanıyor + DoH3"
            else -> "Sistem Geneli DPI & DoH3 Tüneli Aktif"
        }
        val notif = buildNotification(notifText)
        try {
            if (Build.VERSION.SDK_INT >= 34) { // Android 14+ (UPSIDE_DOWN_CAKE)
                startForeground(NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notif)
            }
            CrashLogger.log("FreedomVpnService", "startForeground başarıyla çağrıldı (Foreground Service aktif).")
        } catch (e: Throwable) {
            CrashLogger.log("FreedomVpnService", "startForeground uyarı/hata: ${e.message}", e)
        }

        if (mockLocation) {
            NullIslandLocationShield.start(this)
        } else {
            NullIslandLocationShield.stop(this)
        }

        try {
            val s = DiagnosticSession()
            session = s
            s.startProxy(DesyncConfig(mode = DesyncMode.REALITY_VISION, port = 0))
            val builder = Builder()
                .setSession("Freedom Network")
                .setMtu(1500)
                .addAddress(TunBridge.VPN_CLIENT_IP, 30)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(TunBridge.VPN_DNS_IP)
            if (!killSwitch) {
                builder.allowBypass()
            }
            val disResult = runCatching { builder.addDisallowedApplication(packageName) }
            CrashLogger.log("FreedomVpnService", "addDisallowedApplication($packageName) -> ${if (disResult.isSuccess) "başarılı" else disResult.exceptionOrNull()?.message}")
            if (parsedRelay?.isLoopback() == true || useAutoWarp) {
                runCatching { builder.addDisallowedApplication("org.torproject.android") }
                runCatching { builder.addDisallowedApplication("org.torproject.android.beta") }
            }
            // Route IPv6 into TUN so TunBridge answers with immediate ICMPv6 unreachable,
            // preventing dual-stack apps from leaking past the VPN to the ISP.
            runCatching {
                builder.addAddress("fd00:6672:6565:646f::1", 64)
                builder.addRoute("::", 0)
            }
            val pfd = builder.EstablishSafe()
            tun = pfd
            if (pfd != null) {
                CrashLogger.log("FreedomVpnService", "TUN arabirimi başarıyla açıldı (fd=${pfd.fd})")
                // Sockets inside DirectDohClient, WarpProvisioner, WarpTunnel, and TunBridge are explicitly
                // protected with protect(), and com.freedom.network is excluded via addDisallowedApplication.
                val doh = DirectDohClient(
                    protectSocket = { sock ->
                        val ok = protect(sock)
                        if (!ok) CrashLogger.log("FreedomVpnService", "protectSocket(doh) false döndü!")
                        ok
                    },
                )
                val b = TunBridge(
                    session = s,
                    tunInput = FileInputStream(pfd.fileDescriptor),
                    tunOutput = FileOutputStream(pfd.fileDescriptor),
                    protectSocket = { sock ->
                        val ok = protect(sock)
                        if (!ok) CrashLogger.log("FreedomVpnService", "protectSocket(tun) false döndü!")
                        ok
                    },
                    protectDatagram = { ds ->
                        val ok = protect(ds)
                        if (!ok) CrashLogger.log("FreedomVpnService", "protectDatagram(tun) false döndü!")
                        ok
                    },
                    dohClient = doh,
                    dohEndpoints = customDoh.ifEmpty { TunBridge.DEFAULT_DOH_ENDPOINTS },
                    upstreamDnsServers = customDns.ifEmpty { TunBridge.DEFAULT_DNS_SERVERS },
                    desyncConfig = DesyncConfig(
                        mode = DesyncMode.REALITY_VISION,
                        fakeTtl = 5,
                        splitPos = 2,
                        dropRst = true,
                    ),
                    blockQuic = !quicPassthrough,
                    strictKillSwitch = killSwitch,
                    blockTrackers = blockTrackers,
                    hardenStunLeaks = stunShield,
                    logger = { tag, msg -> CrashLogger.log(tag, msg) },
                    exitRelayUri = exitRelay,
                    autoWarp = useAutoWarp,
                    initialWarpIdentity = savedWarp,
                    devicePersona = persona,
                    suppressIpv6Dns = true,
                    onWarpIdentityReady = { newId ->
                        prefs.edit().putString(PREF_WARP_IDENTITY, newId.serialize()).apply()
                    },
                    onRouteChanged = { label, masked ->
                        updateRouteNotification(label, masked)
                    },
                )
                bridge = b
                ActiveBridgeHolder.current = b
                isRunning.set(true)
                b.start()
                CrashLogger.log("FreedomVpnService", "TunBridge döngüsü başlatıldı.")
                val cm = getSystemService(ConnectivityManager::class.java)
                cm?.activeNetwork?.let { activeNet ->
                    runCatching { setUnderlyingNetworks(arrayOf(activeNet)) }
                }
                registerRoamingCallback()
            } else {
                CrashLogger.log("FreedomVpnService", "TUN arabirimi açılamadı (pfd == null)!")
                stopTunnel()
            }
        } catch (e: Throwable) {
            CrashLogger.log("FreedomVpnService", "startTunnel kritik hata: ${e.message}", e)
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
            CrashLogger.log("FreedomVpnService", "Builder.establish() başarısız: ${t.message}", t)
            null
        }

    private fun stopTunnel() {
        CrashLogger.log("FreedomVpnService", "stopTunnel çağrıldı.")
        running.set(false)
        isRunning.set(false)
        ActiveBridgeHolder.current = null
        NullIslandLocationShield.stop(this)
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
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (t: Throwable) {
            CrashLogger.log("FreedomVpnService", "stopForeground hatası: ${t.message}", t)
        }
    }

    override fun onRevoke() {
        CrashLogger.log("FreedomVpnService", "VPN izni kullanıcı veya sistem tarafından geri çekildi (onRevoke).")
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        CrashLogger.log("FreedomVpnService", "onDestroy çağrıldı.")
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.freedom.network.STOP_TUNNEL"
        const val EXTRA_DOH = "com.freedom.network.EXTRA_DOH"
        const val EXTRA_DNS = "com.freedom.network.EXTRA_DNS"
        const val EXTRA_KILL_SWITCH = "com.freedom.network.EXTRA_KILL_SWITCH"
        const val EXTRA_BLOCK_TRACKERS = "com.freedom.network.EXTRA_BLOCK_TRACKERS"
        const val EXTRA_STUN_SHIELD = "com.freedom.network.EXTRA_STUN_SHIELD"
        const val EXTRA_QUIC_PASSTHROUGH = "com.freedom.network.EXTRA_QUIC_PASSTHROUGH"
        const val EXTRA_EXIT_RELAY = "com.freedom.network.EXTRA_EXIT_RELAY"
        const val EXTRA_MOCK_LOCATION = "com.freedom.network.EXTRA_MOCK_LOCATION"
        const val EXTRA_PERSONA = "com.freedom.network.EXTRA_PERSONA"
        private const val PREF_WARP_IDENTITY = "pref_warp_identity"
        const val NOTIFICATION_CHANNEL_ID = "freedom_vpn_channel"
        const val NOTIFICATION_ID = 2026
        val isRunning = AtomicBoolean(false)
    }
}

internal object ActiveBridgeHolder {
    @Volatile var current: TunBridge? = null
}

// Modern Vector Icon Renderer (Pure Canvas Path - Standard 24x24 Lucide / Feather + Freedom Emblem Geometry)
internal object AndroidVectorIcons {
    // 24x24 standard vector paths
    // Preallocated once — zero memory allocations during Canvas onDraw!
    private val shieldPath = Path().apply {
        moveTo(12f, 2f)
        lineTo(20f, 5f)
        lineTo(20f, 12f)
        cubicTo(20f, 18f, 12f, 22f, 12f, 22f)
        cubicTo(12f, 22f, 4f, 18f, 4f, 12f)
        lineTo(4f, 5f)
        close()
    }

    // Faceted 24x24 Freedom Network Cyber Shield outer polygon & ascending wings
    private val freedomOuterShield = Path().apply {
        moveTo(12f, 1.8f)
        lineTo(20.6f, 5.2f)
        lineTo(19.4f, 13.8f)
        lineTo(12f, 22.2f)
        lineTo(4.6f, 13.8f)
        lineTo(3.4f, 5.2f)
        close()
    }

    private val freedomInnerCore = Path().apply {
        moveTo(12f, 4.4f)
        lineTo(17.9f, 6.8f)
        lineTo(17.0f, 13.0f)
        lineTo(12f, 19.2f)
        lineTo(7.0f, 13.0f)
        lineTo(6.1f, 6.8f)
        close()
    }

    private val freedomUpperWing = Path().apply {
        moveTo(7.8f, 11.4f)
        lineTo(12f, 7.2f)
        lineTo(16.2f, 11.4f)
    }

    private val freedomLowerWing = Path().apply {
        moveTo(8.8f, 14.4f)
        lineTo(12f, 11.2f)
        lineTo(15.2f, 14.4f)
    }

    private val boltPath = Path().apply {
        moveTo(13f, 2f)
        lineTo(3f, 14f)
        lineTo(12f, 14f)
        lineTo(11f, 22f)
        lineTo(21f, 10f)
        lineTo(12f, 10f)
        close()
    }

    private val lockShacklePath = Path().apply {
        moveTo(7f, 11f)
        lineTo(7f, 7f)
        cubicTo(7f, 4.24f, 9.24f, 2f, 12f, 2f)
        cubicTo(14.76f, 2f, 17f, 4.24f, 17f, 7f)
        lineTo(17f, 11f)
    }
    private val lockBodyRect = RectF(4f, 11f, 20f, 22f)

    private val radarOuterCircle = RectF(3f, 3f, 21f, 21f)
    private val radarInnerCircle = RectF(7.5f, 7.5f, 16.5f, 16.5f)

    private val globeOvalRect = RectF(2f, 2f, 22f, 22f)
    private val globeMeridianPath = Path().apply {
        moveTo(12f, 2f)
        cubicTo(6.5f, 2f, 5.5f, 6.5f, 5.5f, 12f)
        cubicTo(5.5f, 17.5f, 6.5f, 22f, 12f, 22f)
        cubicTo(17.5f, 22f, 18.5f, 17.5f, 18.5f, 12f)
        cubicTo(18.5f, 6.5f, 17.5f, 2f, 12f, 2f)
        close()
    }

    private val pulsePath = Path().apply {
        moveTo(2f, 12f)
        lineTo(6f, 12f)
        lineTo(9f, 3f)
        lineTo(15f, 21f)
        lineTo(18f, 12f)
        lineTo(22f, 12f)
    }

    private val powerArcRect = RectF(4f, 4f, 20f, 20f)

    private val terminalChevron = Path().apply {
        moveTo(4f, 17f)
        lineTo(10f, 12f)
        lineTo(4f, 7f)
    }

    private val copyFrontRect = RectF(8f, 8f, 21f, 21f)
    private val copyBackPath = Path().apply {
        moveTo(4f, 16f)
        lineTo(4f, 5f)
        cubicTo(4f, 4.45f, 4.45f, 4f, 5f, 4f)
        lineTo(16f, 4f)
    }

    private val checkPath = Path().apply {
        moveTo(20f, 6f)
        lineTo(9f, 17f)
        lineTo(4f, 12f)
    }

    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }

    private inline fun withMatrix(canvas: Canvas, cx: Float, cy: Float, size: Float, block: () -> Unit) {
        canvas.save()
        canvas.translate(cx, cy)
        val s = size / 24f
        canvas.scale(s, s)
        canvas.translate(-12f, -12f)
        block()
        canvas.restore()
    }

    fun drawFreedomShieldEmblem(canvas: Canvas, cx: Float, cy: Float, size: Float, primaryColor: Int, accentColor: Int) {
        withMatrix(canvas, cx, cy, size) {
            fillPaint.color = Color.argb(46, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor))
            canvas.drawPath(freedomOuterShield, fillPaint)

            fillPaint.color = Color.argb(62, Color.red(accentColor), Color.green(accentColor), Color.blue(accentColor))
            canvas.drawPath(freedomInnerCore, fillPaint)

            strokePaint.color = primaryColor
            strokePaint.strokeWidth = 1.9f
            canvas.drawPath(freedomOuterShield, strokePaint)

            strokePaint.color = accentColor
            strokePaint.strokeWidth = 2.2f
            canvas.drawPath(freedomUpperWing, strokePaint)

            strokePaint.color = Color.WHITE
            strokePaint.strokeWidth = 2.0f
            canvas.drawPath(freedomLowerWing, strokePaint)
        }
    }

    fun drawShield(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int, fill: Boolean = true) {
        withMatrix(canvas, cx, cy, size) {
            if (fill) {
                fillPaint.color = Color.argb(38, Color.red(color), Color.green(color), Color.blue(color))
                canvas.drawPath(shieldPath, fillPaint)
            }
            strokePaint.color = color
            strokePaint.strokeWidth = 2f
            canvas.drawPath(shieldPath, strokePaint)
        }
    }

    fun drawBolt(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            fillPaint.color = Color.argb(45, Color.red(color), Color.green(color), Color.blue(color))
            canvas.drawPath(boltPath, fillPaint)
            strokePaint.color = color
            strokePaint.strokeWidth = 2f
            canvas.drawPath(boltPath, strokePaint)
        }
    }

    fun drawLock(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            fillPaint.color = Color.argb(35, Color.red(color), Color.green(color), Color.blue(color))
            canvas.drawRoundRect(lockBodyRect, 2.5f, 2.5f, fillPaint)
            strokePaint.color = color
            strokePaint.strokeWidth = 2f
            canvas.drawPath(lockShacklePath, strokePaint)
            canvas.drawRoundRect(lockBodyRect, 2.5f, 2.5f, strokePaint)
            canvas.drawLine(12f, 15f, 12f, 18f, strokePaint)
        }
    }

    fun drawRadar(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            fillPaint.color = Color.argb(30, Color.red(color), Color.green(color), Color.blue(color))
            canvas.drawOval(radarOuterCircle, fillPaint)
            strokePaint.color = color
            strokePaint.strokeWidth = 1.9f
            canvas.drawOval(radarOuterCircle, strokePaint)
            canvas.drawArc(radarInnerCircle, -45f, 250f, false, strokePaint)
            canvas.drawLine(12f, 12f, 18.2f, 5.8f, strokePaint)
            fillPaint.color = color
            canvas.drawCircle(12f, 12f, 1.8f, fillPaint)
        }
    }

    fun drawGlobe(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            strokePaint.color = color
            strokePaint.strokeWidth = 2f
            canvas.drawOval(globeOvalRect, strokePaint)
            canvas.drawLine(2f, 12f, 22f, 12f, strokePaint)
            canvas.drawPath(globeMeridianPath, strokePaint)
        }
    }

    fun drawPulse(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            strokePaint.color = color
            strokePaint.strokeWidth = 2.2f
            canvas.drawPath(pulsePath, strokePaint)
        }
    }

    fun drawPower(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            strokePaint.color = color
            strokePaint.strokeWidth = 2.5f
            canvas.drawArc(powerArcRect, 55f, 250f, false, strokePaint)
            canvas.drawLine(12f, 3f, 12f, 11f, strokePaint)
        }
    }

    fun drawTerminal(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            strokePaint.color = color
            strokePaint.strokeWidth = 2f
            canvas.drawPath(terminalChevron, strokePaint)
            canvas.drawLine(12f, 19f, 20f, 19f, strokePaint)
        }
    }

    fun drawCopy(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            strokePaint.color = color
            strokePaint.strokeWidth = 2f
            canvas.drawPath(copyBackPath, strokePaint)
            canvas.drawRoundRect(copyFrontRect, 2f, 2f, strokePaint)
        }
    }

    fun drawCheck(canvas: Canvas, cx: Float, cy: Float, size: Float, color: Int) {
        withMatrix(canvas, cx, cy, size) {
            strokePaint.color = color
            strokePaint.strokeWidth = 2.5f
            canvas.drawPath(checkPath, strokePaint)
        }
    }
}

/**
 * ModernPowerShieldView:
 * High-contrast 2026-2027 Freedom Network Hero Control Disc with:
 * - Cached RadialGradient ambient cyber aura & obsidian glass fill
 * - SweepGradient rotating rim arc
 * - Counter-rotating orbital dash halo & 12-tick azimuth precision bezel
 * - Faceted Freedom Shield Emblem inside a luminous badge
 * - High-legibility label and rounded status pill inside the disc
 */
class ModernPowerShieldView(context: Context) : View(context) {
    var isActive = false
        set(value) {
            if (field != value) {
                field = value
                cachedActive = null
                postInvalidateOnAnimation()
            }
        }
    var onToggleListener: (() -> Unit)? = null

    private var pulseFraction = 0f
    private var orbitAngle = 0f
    private var pressScale = 1.0f

    private var cachedW = -1
    private var cachedH = -1
    private var cachedActive: Boolean? = null
    private var auraShader: RadialGradient? = null
    private var discShader: LinearGradient? = null
    private var rimSweepShader: SweepGradient? = null

    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val auraPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val buttonPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val badgeFillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }
    private val pillTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }
    private val pillRect = RectF()
    private val orbitalRect = RectF()
    private val density by lazy { resources.displayMetrics.density }
    private val orbitalDash by lazy { DashPathEffect(floatArrayOf(10f * density, 7f * density), 0f) }
    private val outerOrbitDash by lazy { DashPathEffect(floatArrayOf(4f * density, 9f * density), 0f) }

    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 2400L
        repeatCount = ValueAnimator.INFINITE
        repeatMode = ValueAnimator.RESTART
        addUpdateListener {
            pulseFraction = it.animatedValue as Float
            orbitAngle = (orbitAngle + 1.15f) % 360f
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

    override fun performClick(): Boolean {
        super.performClick()
        playSoundEffect(android.view.SoundEffectConstants.CLICK)
        performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
        onToggleListener?.invoke()
        return true
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                val cx = width / 2f
                val cy = height / 2f
                val maxR = minOf(cx, cy) * 0.94f
                val btnR = maxR * 0.62f
                val dx = event.x - cx
                val dy = event.y - cy
                if (dx * dx + dy * dy <= (btnR * 1.35f) * (btnR * 1.35f)) {
                    isPressed = true
                    pressScale = 0.94f
                    parent?.requestDisallowInterceptTouchEvent(true)
                    invalidate()
                    return true
                }
                return false
            }
            MotionEvent.ACTION_MOVE -> {
                if (isPressed) {
                    val cx = width / 2f
                    val cy = height / 2f
                    val maxR = minOf(cx, cy) * 0.94f
                    val btnR = maxR * 0.62f
                    val dx = event.x - cx
                    val dy = event.y - cy
                    if (dx * dx + dy * dy > (btnR * 1.65f) * (btnR * 1.65f)) {
                        isPressed = false
                        pressScale = 1.0f
                        parent?.requestDisallowInterceptTouchEvent(false)
                        invalidate()
                    }
                }
            }
            MotionEvent.ACTION_UP -> {
                if (isPressed) {
                    isPressed = false
                    pressScale = 1.0f
                    parent?.requestDisallowInterceptTouchEvent(false)
                    invalidate()
                    performClick()
                    return true
                }
            }
            MotionEvent.ACTION_CANCEL -> {
                isPressed = false
                pressScale = 1.0f
                parent?.requestDisallowInterceptTouchEvent(false)
                invalidate()
            }
        }
        return super.onTouchEvent(event)
    }

    private fun ensureShaders(cx: Float, cy: Float, btnR: Float) {
        if (cachedW == width && cachedH == height && cachedActive == isActive) return
        cachedW = width
        cachedH = height
        cachedActive = isActive

        val auraColor = if (isActive) Color.argb(105, 16, 185, 129) else Color.argb(45, 56, 189, 248)
        auraShader = RadialGradient(cx, cy, btnR * 1.48f, auraColor, Color.TRANSPARENT, Shader.TileMode.CLAMP)

        discShader = if (isActive) {
            LinearGradient(
                cx - btnR * 0.4f, cy - btnR, cx + btnR * 0.4f, cy + btnR,
                Color.parseColor("#042F2E"), Color.parseColor("#065F46"),
                Shader.TileMode.CLAMP,
            )
        } else {
            LinearGradient(
                cx - btnR * 0.4f, cy - btnR, cx + btnR * 0.4f, cy + btnR,
                Color.parseColor("#0A1222"), Color.parseColor("#132038"),
                Shader.TileMode.CLAMP,
            )
        }

        val sweepColors = if (isActive) {
            intArrayOf(
                Color.parseColor("#10B981"),
                Color.parseColor("#34D399"),
                Color.parseColor("#22D3EE"),
                Color.parseColor("#059669"),
                Color.parseColor("#10B981"),
            )
        } else {
            intArrayOf(
                Color.parseColor("#1E3A5F"),
                Color.parseColor("#38BDF8"),
                Color.parseColor("#0EA5E9"),
                Color.parseColor("#1E293B"),
                Color.parseColor("#1E3A5F"),
            )
        }
        rimSweepShader = SweepGradient(cx, cy, sweepColors, null)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val maxR = minOf(cx, cy) * 0.94f
        if (maxR <= 0f) return

        val btnR = maxR * 0.62f
        ensureShaders(cx, cy, btnR)

        val primaryColor = if (isActive) Color.parseColor("#10B981") else Color.parseColor("#38BDF8")
        val accentColor = if (isActive) Color.parseColor("#22D3EE") else Color.parseColor("#818CF8")
        val r = Color.red(primaryColor)
        val g = Color.green(primaryColor)
        val b = Color.blue(primaryColor)

        // 1) Concentric expanding cyber radar waves
        if (isActive) {
            val waveCount = 3
            for (i in 0 until waveCount) {
                val phase = (pulseFraction + i * (1f / waveCount)) % 1f
                val ringR = btnR * 1.06f + (maxR - btnR * 1.06f) * phase
                val alpha = ((1f - phase) * 145).toInt().coerceIn(0, 255)
                ringPaint.color = Color.argb(alpha, r, g, b)
                ringPaint.strokeWidth = (2.4f - phase * 1.3f) * density
                canvas.drawCircle(cx, cy, ringR, ringPaint)
            }
        } else {
            val breathe = btnR * 1.06f + (maxR - btnR * 1.06f) * 0.42f * pulseFraction
            val alpha = ((1f - pulseFraction) * 65).toInt().coerceIn(0, 255)
            ringPaint.color = Color.argb(alpha, r, g, b)
            ringPaint.strokeWidth = 1.6f * density
            canvas.drawCircle(cx, cy, breathe, ringPaint)
        }

        // 2) Counter-rotating double orbital reticles
        val innerReticleR = btnR * 1.13f
        ringPaint.color = Color.argb(if (isActive) 180 else 95, r, g, b)
        ringPaint.strokeWidth = 2.0f * density
        ringPaint.pathEffect = orbitalDash
        orbitalRect.set(cx - innerReticleR, cy - innerReticleR, cx + innerReticleR, cy + innerReticleR)
        canvas.save()
        canvas.rotate(orbitAngle, cx, cy)
        canvas.drawArc(orbitalRect, 0f, 360f, false, ringPaint)
        canvas.restore()

        val outerReticleR = btnR * 1.24f
        ringPaint.color = Color.argb(if (isActive) 115 else 55, Color.red(accentColor), Color.green(accentColor), Color.blue(accentColor))
        ringPaint.strokeWidth = 1.4f * density
        ringPaint.pathEffect = outerOrbitDash
        orbitalRect.set(cx - outerReticleR, cy - outerReticleR, cx + outerReticleR, cy + outerReticleR)
        canvas.save()
        canvas.rotate(-orbitAngle * 0.7f, cx, cy)
        canvas.drawArc(orbitalRect, 0f, 360f, false, ringPaint)
        canvas.restore()
        ringPaint.pathEffect = null

        // 3) Center Hero Disc with pressScale
        canvas.save()
        canvas.scale(pressScale, pressScale, cx, cy)

        auraPaint.shader = auraShader
        canvas.drawCircle(cx, cy, btnR * 1.45f, auraPaint)
        auraPaint.shader = null

        buttonPaint.shader = discShader
        canvas.drawCircle(cx, cy, btnR, buttonPaint)
        buttonPaint.shader = null

        // Subtle inner azimuth ticks (12 precision marks)
        ringPaint.color = Color.argb(if (isActive) 75 else 45, 226, 232, 240)
        ringPaint.strokeWidth = 1.2f * density
        for (tick in 0 until 12) {
            val deg = tick * 30.0
            val rad = Math.toRadians(deg)
            val cosA = kotlin.math.cos(rad).toFloat()
            val sinA = kotlin.math.sin(rad).toFloat()
            val rIn = btnR * 0.87f
            val rOut = btnR * 0.93f
            canvas.drawLine(cx + cosA * rIn, cy + sinA * rIn, cx + cosA * rOut, cy + sinA * rOut, ringPaint)
        }

        // Rotating SweepGradient Glowing Rim
        ringPaint.shader = rimSweepShader
        ringPaint.strokeWidth = (if (isActive) 3.0f else 2.2f) * density
        canvas.save()
        canvas.rotate(orbitAngle * 0.5f, cx, cy)
        canvas.drawCircle(cx, cy, btnR, ringPaint)
        canvas.restore()
        ringPaint.shader = null

        // Inner circular halo badge + Freedom Shield Emblem
        val badgeCx = cx
        val badgeCy = cy - btnR * 0.25f
        val badgeR = btnR * 0.30f
        badgeFillPaint.color = if (isActive) Color.argb(65, 16, 185, 129) else Color.argb(40, 56, 189, 248)
        canvas.drawCircle(badgeCx, badgeCy, badgeR, badgeFillPaint)
        ringPaint.color = Color.argb(130, r, g, b)
        ringPaint.strokeWidth = 1.2f * density
        canvas.drawCircle(badgeCx, badgeCy, badgeR, ringPaint)

        AndroidVectorIcons.drawFreedomShieldEmblem(
            canvas = canvas,
            cx = badgeCx,
            cy = badgeCy,
            size = badgeR * 1.45f,
            primaryColor = if (isActive) Color.parseColor("#34D399") else Color.parseColor("#38BDF8"),
            accentColor = if (isActive) Color.parseColor("#22D3EE") else Color.parseColor("#7DD3FC"),
        )

        // Bold Hero Title inside Disc
        textPaint.textSize = (btnR * 0.145f).coerceIn(11f * density, 15f * density)
        textPaint.color = Color.WHITE
        val statusText = if (isActive) "KORUMA AKTİF" else "DOKUN VE BAĞLAN"
        canvas.drawText(statusText, cx, cy + btnR * 0.25f, textPaint)

        // Compact Status Pill inside Disc
        pillTextPaint.textSize = (btnR * 0.095f).coerceIn(7.5f * density, 10f * density)
        val subText = if (isActive) "SİSTEM GENELİ · DoH3 + ECH" else "AĞ KORUMASI HAZIR"
        val textW = pillTextPaint.measureText(subText)
        val pillPadH = 10f * density
        val pillH = 17f * density
        val pillCy = cy + btnR * 0.49f
        pillRect.set(cx - textW / 2f - pillPadH, pillCy - pillH / 2f, cx + textW / 2f + pillPadH, pillCy + pillH / 2f)

        badgeFillPaint.color = if (isActive) Color.argb(160, 6, 78, 59) else Color.argb(180, 15, 23, 42)
        canvas.drawRoundRect(pillRect, pillH / 2f, pillH / 2f, badgeFillPaint)
        ringPaint.color = if (isActive) Color.argb(180, 52, 211, 153) else Color.argb(110, 56, 189, 248)
        ringPaint.strokeWidth = 1.0f * density
        canvas.drawRoundRect(pillRect, pillH / 2f, pillH / 2f, ringPaint)

        pillTextPaint.color = if (isActive) Color.parseColor("#A7F3D0") else Color.parseColor("#93C5FD")
        val textBaseline = pillCy - (pillTextPaint.descent() + pillTextPaint.ascent()) / 2f
        canvas.drawText(subText, cx, textBaseline, pillTextPaint)

        canvas.restore()
    }
}

/**
 * ThroughputSparklineView:
 * Real-time network speed & throughput waveform graph with smooth cubic Bezier spline
 * and semi-transparent area fill.
 */
class ThroughputSparklineView(context: Context) : View(context) {
    private val maxSamples = 32
    private val rxHistory = FloatArray(maxSamples)
    private val txHistory = FloatArray(maxSamples)
    private var writeIdx = 0
    private var currentRxKbps = 0f
    private var currentTxKbps = 0f
    private var totalRxKb = 0L
    private var totalTxKb = 0L

    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#1E293B")
        strokeWidth = 1f * resources.displayMetrics.density
        style = Paint.Style.STROKE
    }
    private val rxStrokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#10B981")
        strokeWidth = 2.2f * resources.displayMetrics.density
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val rxFillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val txStrokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#38BDF8")
        strokeWidth = 1.6f * resources.displayMetrics.density
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 10f * resources.displayMetrics.density
        color = Color.parseColor("#94A3B8")
    }
    private val rxBadgePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 10.5f * resources.displayMetrics.density
        color = Color.parseColor("#10B981")
    }
    private val txBadgePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 10.5f * resources.displayMetrics.density
        color = Color.parseColor("#38BDF8")
    }
    private val subTextPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textSize = 9.5f * resources.displayMetrics.density
        color = Color.parseColor("#64748B")
    }
    private val rxPath = Path()
    private val txPath = Path()
    private val rxFill = Path()

    fun updateMetrics(rxKbps: Float, txKbps: Float, totalRx: Long, totalTx: Long) {
        currentRxKbps = rxKbps
        currentTxKbps = txKbps
        totalRxKb = totalRx / 1024L
        totalTxKb = totalTx / 1024L
        rxHistory[writeIdx] = rxKbps
        txHistory[writeIdx] = txKbps
        writeIdx = (writeIdx + 1) % maxSamples
        postInvalidateOnAnimation()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0f || h <= 0f) return
        val density = resources.displayMetrics.density

        // Header line
        val headerY = 14f * density
        AndroidVectorIcons.drawPulse(canvas, 12f * density, headerY - 3f * density, 12f * density, Color.parseColor("#94A3B8"))
        canvas.drawText("CANLI TRAFİK AKIŞI", 24f * density, headerY, labelPaint)

        // Speed badges on right
        val rxStr = "⬇ %.1f KB/s".format(java.util.Locale.US, currentRxKbps)
        val txStr = "⬆ %.1f KB/s".format(java.util.Locale.US, currentTxKbps)
        val txW = txBadgePaint.measureText(txStr)
        val rxW = rxBadgePaint.measureText(rxStr)
        canvas.drawText(txStr, w - txW - 10f * density, headerY, txBadgePaint)
        canvas.drawText(rxStr, w - txW - rxW - 20f * density, headerY, rxBadgePaint)

        // Graph area
        val graphTop = 24f * density
        val graphBottom = h - 18f * density
        val graphH = graphBottom - graphTop
        val graphLeft = 10f * density
        val graphRight = w - 10f * density
        val graphW = graphRight - graphLeft
        if (graphH <= 0f || graphW <= 0f) return

        // Grid lines
        canvas.drawLine(graphLeft, graphTop + graphH * 0.5f, graphRight, graphTop + graphH * 0.5f, gridPaint)
        canvas.drawLine(graphLeft, graphBottom, graphRight, graphBottom, gridPaint)

        var maxVal = 20f
        for (i in 0 until maxSamples) {
            if (rxHistory[i] > maxVal) maxVal = rxHistory[i]
            if (txHistory[i] > maxVal) maxVal = txHistory[i]
        }

        rxPath.reset()
        txPath.reset()
        rxFill.reset()
        val stepX = graphW / (maxSamples - 1).toFloat()

        for (i in 0 until maxSamples) {
            val sampleIdx = (writeIdx + i) % maxSamples
            val x = graphLeft + i * stepX
            val rxNorm = (rxHistory[sampleIdx] / maxVal).coerceIn(0f, 1f)
            val txNorm = (txHistory[sampleIdx] / maxVal).coerceIn(0f, 1f)
            val rxY = graphBottom - rxNorm * (graphH * 0.9f)
            val txY = graphBottom - txNorm * (graphH * 0.9f)

            if (i == 0) {
                rxPath.moveTo(x, rxY)
                txPath.moveTo(x, txY)
                rxFill.moveTo(x, graphBottom)
                rxFill.lineTo(x, rxY)
            } else {
                rxPath.lineTo(x, rxY)
                txPath.lineTo(x, txY)
                rxFill.lineTo(x, rxY)
            }
        }
        rxFill.lineTo(graphRight, graphBottom)
        rxFill.close()

        rxFillPaint.shader = LinearGradient(
            0f, graphTop, 0f, graphBottom,
            Color.argb(55, 16, 185, 129), Color.argb(0, 16, 185, 129),
            Shader.TileMode.CLAMP
        )
        canvas.drawPath(rxFill, rxFillPaint)
        rxFillPaint.shader = null

        canvas.drawPath(rxPath, rxStrokePaint)
        canvas.drawPath(txPath, txStrokePaint)

        // Footer volume info
        val footerY = h - 4f * density
        val volStr = "Toplam Aktarım: ⬆ $totalTxKb KB  ⬇ $totalRxKb KB"
        canvas.drawText(volStr, graphLeft, footerY, subTextPaint)
    }
}

/**
 * ModernMetricCard:
 * Sleek glassmorphic card with vector icon, bold metric value, and subtle secondary detail.
 */
@android.annotation.SuppressLint("ViewConstructor")
class ModernMetricCard(context: Context, val iconType: Int, val titleText: String, val heroColor: Int) : LinearLayout(context) {
    val valView = TextView(context).apply {
        text = "0"
        textSize = 17f
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        setTextColor(heroColor)
        setPadding(0, dp(2), 0, dp(1))
    }
    val subView = TextView(context).apply {
        text = "Hazır"
        textSize = 9.5f
        setTextColor(Color.parseColor("#64748B"))
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    init {
        orientation = VERTICAL
        val shape = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            setColor(Color.parseColor("#0E1626"))
            cornerRadius = 14f * resources.displayMetrics.density
            setStroke(dp(1), Color.parseColor("#1E293B"))
        }
        background = shape
        setPadding(dp(12), dp(10), dp(12), dp(10))
        layoutParams = LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f).apply {
            setMargins(dp(4), dp(4), dp(4), dp(4))
        }

        val header = LinearLayout(context).apply {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val iconView = object : View(context) {
            init {
                layoutParams = LayoutParams(dp(18), dp(18)).apply {
                    setMargins(0, 0, dp(6), 0)
                }
            }
            override fun onDraw(c: Canvas) {
                super.onDraw(c)
                val s = minOf(width, height).toFloat()
                when (iconType) {
                    0 -> AndroidVectorIcons.drawBolt(c, s / 2, s / 2, s, heroColor)
                    1 -> AndroidVectorIcons.drawLock(c, s / 2, s / 2, s, heroColor)
                    2 -> AndroidVectorIcons.drawRadar(c, s / 2, s / 2, s, heroColor)
                    else -> AndroidVectorIcons.drawGlobe(c, s / 2, s / 2, s, heroColor)
                }
            }
        }
        val titleLabel = TextView(context).apply {
            text = titleText
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#94A3B8"))
        }
        header.addView(iconView)
        header.addView(titleLabel)

        addView(header)
        addView(valView)
        addView(subView)
    }

    fun update(mainText: String, detailText: String) {
        valView.text = mainText
        subView.text = detailText
    }
}

/**
 * MainActivity:
 * Freedom Network — Complete 2026–2027 Android 11–17 architecture with 3 segmented tabs:
 * 1. KONTROL (Freedom Hero Shield, Throughput Waveform, 4 Live Metric Cards, Security & Speed Shield Switches)
 * 2. TEŞHİS (ISP Out-of-Tunnel Diagnostic Runner, Probes, Real-time Censorship Report)
 * 3. GÜNLÜK (Integrated Debugger, Log Viewer, Clipboard Copy, Crash Dump Inspector)
 */
class MainActivity : Activity() {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "freedom-worker").apply { isDaemon = true } }
    private val main = Handler(Looper.getMainLooper())
    private val busy = AtomicBoolean(false)
    @Volatile private var session: DiagnosticSession? = null
    @Volatile private var lastFingerprint: String? = null
    @Volatile private var lastDecision: Decision? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private lateinit var cm: ConnectivityManager
    private var activeTabIndex = 0
    private var backCallback: Any? = null

    // UI Elements
    private lateinit var powerShieldView: ModernPowerShieldView
    private lateinit var statusPill: TextView
    private lateinit var sparklineView: ThroughputSparklineView
    private lateinit var heroActionButton: Button

    private lateinit var cardTcp: ModernMetricCard
    private lateinit var cardTls: ModernMetricCard
    private lateinit var cardUdp: ModernMetricCard
    private lateinit var cardDns: ModernMetricCard

    // 2026-2027 Simplified Privacy Cards & Collapsible Advanced Controls
    private lateinit var ipCardStatus: TextView
    private lateinit var switchMockLocation: Switch
    private lateinit var locationStatusView: TextView
    private lateinit var btnDevOptions: Button
    private lateinit var btnPersonaCycle: Button
    private lateinit var personaDescView: TextView
    private var selectedPersona: DevicePersona = DevicePersona.IPHONE_19_BETA
    private lateinit var advancedToggleBtn: TextView
    private lateinit var advancedContainer: LinearLayout
    private var advancedExpanded = false

    private lateinit var switchKillSwitch: Switch
    private lateinit var switchTrackerGuard: Switch
    private lateinit var switchQuicPassthrough: Switch
    private lateinit var exitRelayInput: EditText
    private lateinit var ipPrivacyResult: TextView
    private lateinit var btnCheckPublicIp: Button

    // Tab buttons & containers
    private lateinit var tabBtnControl: TextView
    private lateinit var tabBtnDiag: TextView
    private lateinit var tabBtnLog: TextView
    private lateinit var panelControl: LinearLayout
    private lateinit var panelDiag: LinearLayout
    private lateinit var panelLog: LinearLayout
    private lateinit var tabSwitcher: (Int) -> Unit

    // Diag tab elements
    private lateinit var targets: EditText
    private lateinit var altDns: EditText
    private lateinit var dohEndpoints: EditText
    private lateinit var auto: CheckBox
    private lateinit var runButton: Button
    private lateinit var appliedButton: Button
    private lateinit var diagStatus: TextView
    private lateinit var diagOutput: TextView

    // Log tab elements
    private lateinit var logOutput: TextView
    private lateinit var logStatus: TextView

    // Speed tracking
    private var lastBytesUp = 0L
    private var lastBytesDown = 0L
    private var lastTickTimeMs = 0L

    private val tickerRunnable = object : Runnable {
        override fun run() {
            val isVpn = FreedomVpnService.isRunning.get()
            val s = session
            val p = s?.proxyStats()
            val b = ActiveBridgeHolder.current
            val isFreedomActive = isVpn || (p?.active == true)

            powerShieldView.isActive = isFreedomActive

            val now = System.currentTimeMillis()
            val currentUp = b?.bytesUp?.get() ?: 0L
            val currentDown = b?.bytesDown?.get() ?: 0L

            var rxRate = 0f
            var txRate = 0f
            if (lastTickTimeMs > 0L) {
                val dtSec = ((now - lastTickTimeMs) / 1000f).coerceAtLeast(0.1f)
                val dDown = (currentDown - lastBytesDown).coerceAtLeast(0L)
                val dUp = (currentUp - lastBytesUp).coerceAtLeast(0L)
                rxRate = (dDown / 1024f) / dtSec
                txRate = (dUp / 1024f) / dtSec
            }
            lastBytesUp = currentUp
            lastBytesDown = currentDown
            lastTickTimeMs = now

            sparklineView.updateMetrics(rxRate, txRate, currentDown, currentUp)
            updateDashboardMetrics(isVpn, p, b)

            main.postDelayed(this, 1000)
        }
    }

    private val networkCheck = Runnable { if (!worker.isShutdown) worker.execute { checkNetwork() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        CrashLogger.log("MainActivity", "onCreate başladı")
        try {
            cm = getSystemService(ConnectivityManager::class.java)
            setContentView(buildModernUi(savedInstanceState))

            // Android 11-17 Edge-to-Edge & Dark Cyber Theme System Bar Integration
            // Must run after setContentView(...) so PhoneWindow.mDecor is initialized (avoids Android 17 PhoneWindow.getInsetsController NPE).
            window.setDecorFitsSystemWindows(false)
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT < 35) {
                window.statusBarColor = Color.TRANSPARENT
                window.navigationBarColor = Color.TRANSPARENT
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                window.isNavigationBarContrastEnforced = false
            }
            runCatching {
                window.insetsController?.setSystemBarsAppearance(
                    0,
                    android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                        android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
                )
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
                }
            }
        } catch (t: Throwable) {
            CrashLogger.log("MainActivity", "buildModernUi hatası!", t)
            throw t
        }

        refreshLogViewer()
        worker.execute {
            try {
                CrashLogger.log("MainActivity", "DiagnosticSession oluşturuluyor...")
                val created = DiagnosticSession()
                session = created
                val initialEnv = runCatching { AndroidPlatform.environment(cm) }.getOrNull()
                if (initialEnv != null) {
                    runCatching { created.setEnvironment(initialEnv) }
                    lastFingerprint = fingerprint(initialEnv)
                }
                val initialSummary = buildString {
                    if (initialEnv != null) {
                        append(Text.environment(initialEnv))
                        appendLine()
                    }
                    appendLine("FREEDOM NETWORK — HAZIR DURUM ÖZETİ")
                    appendLine("• Şifreli DNS : Çoklu DoH3/DoH (1.1.1.1, 8.8.8.8, 9.9.9.9) + Zehirli Yanıt Filtresi")
                    appendLine("• Sansür Aşma : TLS 1.3 ECH / SNI Record Parçalama + REALITY Vision Desync")
                    appendLine("• Gizlilik    : STUN/WebRTC/mDNS/IPv6/TCP-53 Sızıntı Kalkanı + İzleyici Engeli")
                    appendLine("• Çıkış IP    : Çıkış Rölesi girilmezse doğrudan yerel DPI; röle (Tor/SOCKS5/HTTPS) ile maskelenir")
                    appendLine()
                    appendLine("Detaylı sansür ve hat testi için yukarıdaki 'Ağ Tanıla' düğmesine dokunun.")
                }
                CrashLogger.log("MainActivity", "DiagnosticSession hazır: v${Native.engineVersion()}")
                ui {
                    diagStatus.text = "Motor ${Native.engineVersion()} hazır · Freedom Network 2026–2027"
                    runButton.isEnabled = true
                    if (diagOutput.text.toString().startsWith("Tanılama henüz")) {
                        diagOutput.text = initialSummary
                    }
                    refreshLogViewer()
                }
            } catch (e: NativeException) {
                CrashLogger.log("MainActivity", "NativeException: ${e.message}", e)
                ui { diagStatus.text = "Yerel motor başlatılamadı: ${e.message}" }
            } catch (t: Throwable) {
                CrashLogger.log("MainActivity", "DiagnosticSession başlatma hatası: ${t.message}", t)
                ui { diagStatus.text = "Yerel motor hatası: ${t.message}" }
            }
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun ui(block: () -> Unit) {
        main.post { if (!isDestroyed) block() }
    }

    private fun createCardShape(bgColor: String, borderColor: String = "#1E293B", cornerDp: Float = 14f): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            setColor(Color.parseColor(bgColor))
            cornerRadius = cornerDp * resources.displayMetrics.density
            setStroke(dp(1), Color.parseColor(borderColor))
        }
    }

    @android.annotation.SuppressLint("UseSwitchCompatOrMaterialCode")
    private fun createToggleSwitch(initialChecked: Boolean, onChanged: (Boolean) -> Unit): Switch {
        val states = arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf())
        val thumbColors = android.content.res.ColorStateList(
            states,
            intArrayOf(Color.parseColor("#34D399"), Color.parseColor("#CBD5E1")),
        )
        val trackColors = android.content.res.ColorStateList(
            states,
            intArrayOf(Color.parseColor("#065F46"), Color.parseColor("#334155")),
        )
        return Switch(this).apply {
            isChecked = initialChecked
            thumbTintList = thumbColors
            trackTintList = trackColors
            setOnCheckedChangeListener { _, checked -> onChanged(checked) }
        }
    }

    private fun updatePredictiveBackRegistration(shouldIntercept: Boolean) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        runCatching {
            val dispatcher = onBackInvokedDispatcher
            val existing = backCallback as? android.window.OnBackInvokedCallback
            if (shouldIntercept && existing == null) {
                val cb = android.window.OnBackInvokedCallback {
                    tabSwitcher.invoke(0)
                }
                dispatcher.registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, cb)
                backCallback = cb
            } else if (!shouldIntercept && existing != null) {
                dispatcher.unregisterOnBackInvokedCallback(existing)
                backCallback = null
            }
        }
    }

    private fun buildModernUi(state: Bundle?): View {
        val prefs = getSharedPreferences("freedom_prefs", Context.MODE_PRIVATE)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#070B14"))
            setPadding(dp(14), dp(10), dp(14), dp(10))
        }

        // Top Header with Freedom Shield Emblem Badge
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(2), 0, dp(10))
        }
        val brandIcon = object : View(this) {
            init {
                layoutParams = LinearLayout.LayoutParams(dp(26), dp(26)).apply {
                    setMargins(0, 0, dp(8), 0)
                }
            }
            override fun onDraw(c: Canvas) {
                super.onDraw(c)
                val s = minOf(width, height).toFloat()
                AndroidVectorIcons.drawFreedomShieldEmblem(
                    c, s / 2f, s / 2f, s * 0.92f,
                    Color.parseColor("#10B981"), Color.parseColor("#38BDF8"),
                )
            }
        }
        val appTitle = TextView(this).apply {
            text = "FREEDOM NETWORK"
            textSize = 18.5f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#F8FAFC"))
        }
        val versionBadge = TextView(this).apply {
            text = "  2026–2027 · v2.0"
            textSize = 10.5f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#38BDF8"))
        }
        header.addView(brandIcon)
        header.addView(appTitle)
        header.addView(versionBadge)
        root.addView(header)

        // Segmented Tab Bar (KONTROL · TEŞHİS · GÜNLÜK)
        val tabBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = createCardShape("#0C1322", borderColor = "#1E293B", cornerDp = 12f)
            setPadding(dp(4), dp(4), dp(4), dp(4))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, 0, 0, dp(10))
            }
        }

        fun createTabBtn(label: String): TextView {
            return TextView(this).apply {
                text = label
                textSize = 11.5f
                gravity = Gravity.CENTER
                typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
                setPadding(0, dp(9), 0, dp(9))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
        }

        tabBtnControl = createTabBtn("KONTROL")
        tabBtnDiag = createTabBtn("TEŞHİS")
        tabBtnLog = createTabBtn("GÜNLÜK")

        tabBar.addView(tabBtnControl)
        tabBar.addView(tabBtnDiag)
        tabBar.addView(tabBtnLog)
        root.addView(tabBar)

        // Content Area Container
        val contentFrame = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        }

        // ---------------- TAB 0: KONTROL PANELİ ----------------
        panelControl = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        // Animated Freedom Hero Shield Button
        powerShieldView = ModernPowerShieldView(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(224)).apply {
                setMargins(0, dp(2), 0, dp(4))
            }
            onToggleListener = { toggleDesync() }
        }
        panelControl.addView(powerShieldView)

        // Connection State Pill Badge
        statusPill = TextView(this).apply {
            text = "KORUMA DEVRE DIŞI · DOKUNARAK BAĞLANIN"
            textSize = 10.5f
            gravity = Gravity.CENTER
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#94A3B8"))
            background = createCardShape("#0E1626", borderColor = "#1E293B", cornerDp = 20f)
            setPadding(dp(14), dp(7), dp(14), dp(7))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setMargins(0, dp(2), 0, dp(10))
            }
        }
        panelControl.addView(statusPill)

        // 1) IP Gizliliği Kartı (Otomatik WARP WireGuard -> Tor -> Doğrudan)
        val ipPrivacyCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#0B1220", borderColor = "#1E293B", cornerDp = 14f)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), dp(2), dp(4), dp(6))
            }
        }
        val ipCardTitle = TextView(this).apply {
            text = "IP GİZLİLİĞİ (OTOMATİK WARP WIREGUARD)"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#10B981"))
        }
        ipCardStatus = TextView(this).apply {
            text = "Hazır · Başlatıldığında otomatik WARP WireGuard şifreli çıkışı + AAAA/WebRTC/STUN koruması devreye girer."
            textSize = 11f
            setTextColor(Color.parseColor("#E2E8F0"))
            setPadding(0, dp(3), 0, 0)
        }
        ipPrivacyCard.addView(ipCardTitle)
        ipPrivacyCard.addView(ipCardStatus)
        panelControl.addView(ipPrivacyCard)

        // 2) Konum Gizliliği Kartı (0.0000°, 0.0000° Null Island + Tek Dokunuş Geliştirici Ayarı)
        val locCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#0B1220", borderColor = "#1E293B", cornerDp = 14f)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), 0, dp(4), dp(6))
            }
        }
        val locTopRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val locTextCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(0, 0, dp(8), 0)
            }
        }
        val locTitle = TextView(this).apply {
            text = "KONUM GİZLİLİĞİ (NULL ISLAND · 0.0°, 0.0°)"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#38BDF8"))
        }
        locationStatusView = TextView(this).apply {
            text = "Açıldığında GPS, Ağ ve Fused sağlayıcılara 0.0°, 0.0° (hiçbir yerde olmayan koordinat) bildirir."
            textSize = 10.5f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(2), 0, 0)
        }
        locTextCol.addView(locTitle)
        locTextCol.addView(locationStatusView)

        btnDevOptions = Button(this).apply {
            text = "Sahte Konum Ayarını Aç"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#FDE68A"))
            background = createCardShape("#451A03", borderColor = "#D97706", cornerDp = 8f)
            setPadding(dp(8), dp(6), dp(8), dp(6))
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, dp(6), 0, 0)
            }
            setOnClickListener {
                NullIslandLocationShield.openDeveloperOptions(this@MainActivity)
            }
        }

        switchMockLocation = createToggleSwitch(prefs.getBoolean(PREF_MOCK_LOCATION, false)) { v ->
            prefs.edit().putBoolean(PREF_MOCK_LOCATION, v).apply()
            if (v) {
                val ok = NullIslandLocationShield.start(applicationContext)
                locationStatusView.text = NullIslandLocationShield.lastStatusText
                btnDevOptions.visibility = if (!ok && NullIslandLocationShield.needsDeveloperPermission) View.VISIBLE else View.GONE
            } else {
                NullIslandLocationShield.stop(applicationContext)
                locationStatusView.text = NullIslandLocationShield.lastStatusText
                btnDevOptions.visibility = View.GONE
            }
        }
        locTopRow.addView(locTextCol)
        locTopRow.addView(switchMockLocation)
        locCard.addView(locTopRow)
        locCard.addView(btnDevOptions)
        panelControl.addView(locCard)

        // 3) Cihaz Gizliliği Kartı (iPhone 19 Beta / Android 19 Quantum / Pixel 14 Ultra)
        selectedPersona = DevicePersona.fromId(
            state?.getString(KEY_PERSONA) ?: prefs.getString(PREF_PERSONA, DevicePersona.IPHONE_19_BETA.id),
        )
        val deviceCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#0B1220", borderColor = "#1E293B", cornerDp = 14f)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), 0, dp(4), dp(8))
            }
        }
        val devTopRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val devTextCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(0, 0, dp(8), 0)
            }
        }
        val devTitle = TextView(this).apply {
            text = "CİHAZ GİZLİLİĞİ (GELECEK KİMLİK)"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#A78BFA"))
        }
        personaDescView = TextView(this).apply {
            text = if (selectedPersona == DevicePersona.OFF) {
                "Kapalı · Yalnızca temel IP sızıntı başlıkları temizlenir."
            } else {
                "Aktif Kimlik: ${selectedPersona.shortLabel} (Ağ başlıkları + OEM/telemetri engel; yerel Build.MODEL root olmadan değişmez)."
            }
            textSize = 10f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(2), 0, 0)
        }
        devTextCol.addView(devTitle)
        devTextCol.addView(personaDescView)

        btnPersonaCycle = Button(this).apply {
            text = selectedPersona.shortLabel
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#DDD6FE"))
            background = createCardShape("#2E1065", borderColor = "#7C3AED", cornerDp = 8f)
            setPadding(dp(10), dp(6), dp(10), dp(6))
            setOnClickListener {
                val all = DevicePersona.entries
                val nextIdx = (all.indexOf(selectedPersona) + 1) % all.size
                selectedPersona = all[nextIdx]
                prefs.edit().putString(PREF_PERSONA, selectedPersona.id).apply()
                text = selectedPersona.shortLabel
                personaDescView.text = if (selectedPersona == DevicePersona.OFF) {
                    "Kapalı · Yalnızca temel IP sızıntı başlıkları temizlenir."
                } else {
                    "Aktif Kimlik: ${selectedPersona.shortLabel} (Ağ başlıkları + OEM/telemetri engel; yerel Build.MODEL root olmadan değişmez)."
                }
            }
        }
        devTopRow.addView(devTextCol)
        devTopRow.addView(btnPersonaCycle)
        deviceCard.addView(devTopRow)
        panelControl.addView(deviceCard)

        // Tek Dokunuş Genel Çıkış IP & Sızıntı Testi
        val leakCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#0B1220", borderColor = "#1E293B", cornerDp = 12f)
            setPadding(dp(12), dp(8), dp(12), dp(8))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), 0, dp(4), dp(8))
            }
        }
        btnCheckPublicIp = Button(this).apply {
            text = "Gizlilik & Sızıntı Testini Çalıştır"
            textSize = 11f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#38BDF8"))
            background = createCardShape("#0F1B2E", borderColor = "#1D4ED8", cornerDp = 8f)
            setPadding(dp(8), dp(8), dp(8), dp(8))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            setOnClickListener { runPublicIpLeakCheck() }
        }
        ipPrivacyResult = TextView(this).apply {
            text = "IPv6/AAAA Red · STUN/WebRTC Engel · DNS-Rebinding Filtre · HTTP Kimlik Koruma hazır"
            textSize = 9.5f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(5), 0, 0)
        }
        leakCard.addView(btnCheckPublicIp)
        leakCard.addView(ipPrivacyResult)
        panelControl.addView(leakCard)

        // Quick Hero Action Button
        heroActionButton = Button(this).apply {
            text = "ÖZGÜR AĞI BAŞLAT (WARP + Tam Gizlilik)"
            textSize = 13.5f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#070B14"))
            background = createCardShape("#10B981", cornerDp = 14f)
            setPadding(dp(16), dp(14), dp(16), dp(14))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), dp(2), dp(4), dp(8))
            }
            setOnClickListener {
                it.performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
                toggleDesync()
            }
        }
        panelControl.addView(heroActionButton)

        // Collapsible "Gelişmiş Ayarlar & Canlı Trafik" Accordion
        advancedToggleBtn = TextView(this).apply {
            text = "Gelişmiş Ayarlar & Canlı Trafik ▾"
            textSize = 11f
            gravity = Gravity.CENTER
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#94A3B8"))
            background = createCardShape("#0C1322", borderColor = "#1E293B", cornerDp = 10f)
            setPadding(dp(12), dp(9), dp(12), dp(9))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), dp(2), dp(4), dp(6))
            }
            setOnClickListener {
                advancedExpanded = !advancedExpanded
                advancedContainer.visibility = if (advancedExpanded) View.VISIBLE else View.GONE
                text = if (advancedExpanded) "Gelişmiş Ayarlar & Canlı Trafik ▴" else "Gelişmiş Ayarlar & Canlı Trafik ▾"
            }
        }
        panelControl.addView(advancedToggleBtn)

        advancedContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }

        // Real-Time Network Speed & Throughput Waveform
        sparklineView = ThroughputSparklineView(this).apply {
            background = createCardShape("#0A101D", borderColor = "#1E293B", cornerDp = 12f)
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(84)).apply {
                setMargins(dp(4), 0, dp(4), dp(8))
            }
        }
        advancedContainer.addView(sparklineView)

        // 4 Live Metric Cards (2x2 Grid — Universal Censorship Bypass, Privacy & Speed)
        val row1 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        cardTcp = ModernMetricCard(this, iconType = 0, titleText = "WARP / TCP DESYNC", heroColor = Color.parseColor("#10B981"))
        cardTls = ModernMetricCard(this, iconType = 1, titleText = "TLS / KİMLİK KALKAN", heroColor = Color.parseColor("#38BDF8"))
        row1.addView(cardTcp)
        row1.addView(cardTls)
        advancedContainer.addView(row1)

        val row2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        cardUdp = ModernMetricCard(this, iconType = 2, titleText = "UDP / SIZINTI KORUMA", heroColor = Color.parseColor("#A78BFA"))
        cardDns = ModernMetricCard(this, iconType = 3, titleText = "ŞİFRELİ DoH3 / AAAA", heroColor = Color.parseColor("#FBBF24"))
        row2.addView(cardUdp)
        row2.addView(cardDns)
        advancedContainer.addView(row2)

        // 2026-2027 Security & Speed Shield Switches Card
        val shieldCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#0B1220", borderColor = "#1E293B", cornerDp = 14f)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), dp(8), dp(4), dp(4))
            }
        }
        val shieldHeader = TextView(this).apply {
            text = "2026–2027 GİZLİLİK, IP SIZINTI & HIZ KALKANI"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#38BDF8"))
            setPadding(0, 0, 0, dp(6))
        }
        shieldCard.addView(shieldHeader)

        fun buildSwitchRow(title: String, subtitle: String, sw: Switch, addBottomDivider: Boolean) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(5), 0, dp(5))
            }
            val textCol = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    setMargins(0, 0, dp(8), 0)
                }
            }
            val tView = TextView(this).apply {
                text = title
                textSize = 11.5f
                typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.parseColor("#E2E8F0"))
            }
            val sView = TextView(this).apply {
                text = subtitle
                textSize = 9.5f
                setTextColor(Color.parseColor("#64748B"))
            }
            textCol.addView(tView)
            textCol.addView(sView)
            row.addView(textCol)
            row.addView(sw)
            shieldCard.addView(row)
            if (addBottomDivider) {
                val div = View(this).apply {
                    setBackgroundColor(Color.parseColor("#1E293B"))
                    layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
                }
                shieldCard.addView(div)
            }
        }

        switchKillSwitch = createToggleSwitch(prefs.getBoolean(PREF_KILL_SWITCH, true)) { v ->
            prefs.edit().putBoolean(PREF_KILL_SWITCH, v).apply()
        }
        switchTrackerGuard = createToggleSwitch(prefs.getBoolean(PREF_BLOCK_TRACKERS, true)) { v ->
            prefs.edit().putBoolean(PREF_BLOCK_TRACKERS, v).apply()
        }
        switchQuicPassthrough = createToggleSwitch(prefs.getBoolean(PREF_QUIC_PASSTHROUGH, false)) { v ->
            prefs.edit().putBoolean(PREF_QUIC_PASSTHROUGH, v).apply()
        }

        buildSwitchRow(
            "Sıkı Kill Switch & WebRTC IP Kalkanı",
            "Şifresiz DNS geri düşüşünü ve STUN/mDNS/SSDP sızıntılarını engeller",
            switchKillSwitch,
            addBottomDivider = true,
        )
        buildSwitchRow(
            "İzleyici, OEM & Telemetri DNS Filtresi",
            "Reklam, OEM parmak izi ve konum telemetri alan adlarını engeller",
            switchTrackerGuard,
            addBottomDivider = true,
        )
        buildSwitchRow(
            "HTTP/3 QUIC Doğrudan Geçiş (Düşük Gecikme)",
            "WARP kapalıyken QUIC engellenmeyen ağlarda doğrudan UDP/443 akışı",
            switchQuicPassthrough,
            addBottomDivider = false,
        )
        advancedContainer.addView(shieldCard)

        // Optional Manual Exit Relay Override Card
        val relayCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#0B1220", borderColor = "#1E293B", cornerDp = 14f)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(dp(4), dp(8), dp(4), dp(8))
            }
        }
        val relayHeader = TextView(this).apply {
            text = "İSTEĞE BAĞLI MANUEL RÖLE GEÇERSİZ KILMA"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#A78BFA"))
            setPadding(0, 0, 0, dp(4))
        }
        relayCard.addView(relayHeader)

        val relayHintDesc = TextView(this).apply {
            text = "Boş bırakıldığında dahili Cloudflare WARP WireGuard (yedek: yerel Tor :9050 -> Doğrudan DPI) otomatik seçilir."
            textSize = 9.5f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, 0, 0, dp(6))
        }
        relayCard.addView(relayHintDesc)

        exitRelayInput = EditText(this).apply {
            setText(state?.getString(KEY_EXIT_RELAY) ?: prefs.getString(PREF_EXIT_RELAY, "") ?: "")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 11.5f
            setTextColor(Color.WHITE)
            hint = "Boş = Otomatik WARP · Örn: socks5://127.0.0.1:9050"
            setHintTextColor(Color.parseColor("#475569"))
            background = createCardShape("#070B14", borderColor = "#1E293B", cornerDp = 8f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    prefs.edit().putString(PREF_EXIT_RELAY, s?.toString()?.trim().orEmpty()).apply()
                }
            })
        }
        relayCard.addView(exitRelayInput)

        val presetRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, dp(6), 0, 0)
            }
        }
        val btnPresetDirect = Button(this).apply {
            text = "Otomatik (WARP)"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#E2E8F0"))
            background = createCardShape("#131D31", borderColor = "#1E293B", cornerDp = 8f)
            setPadding(dp(6), dp(6), dp(6), dp(6))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(0, 0, dp(4), 0)
            }
            setOnClickListener {
                exitRelayInput.setText("")
                prefs.edit().putString(PREF_EXIT_RELAY, "").apply()
                ipPrivacyResult.text = "Mod: Otomatik WARP WireGuard (boş röle)"
            }
        }
        val btnPresetTor = Button(this).apply {
            text = "Tor / Orbot (:9050)"
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#DDD6FE"))
            background = createCardShape("#2E1065", borderColor = "#7C3AED", cornerDp = 8f)
            setPadding(dp(6), dp(6), dp(6), dp(6))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(dp(4), 0, 0, 0)
            }
            setOnClickListener {
                exitRelayInput.setText("socks5://127.0.0.1:9050")
                prefs.edit().putString(PREF_EXIT_RELAY, "socks5://127.0.0.1:9050").apply()
                ipPrivacyResult.text = "127.0.0.1:9050 (Tor/Orbot) portu kontrol ediliyor..."
                worker.execute {
                    val reachable = runCatching {
                        java.net.Socket().use { sock ->
                            sock.connect(java.net.InetSocketAddress("127.0.0.1", 9050), 900)
                        }
                        true
                    }.getOrDefault(false)
                    ui {
                        ipPrivacyResult.text = if (reachable) {
                            "Tor/Orbot (127.0.0.1:9050) dinlemede ve hazır! Korumayı (yeniden) başlatın."
                        } else {
                            "127.0.0.1:9050 kapalı — önce cihazda Orbot/Tor'u çalıştırın veya Otomatik WARP'a geçin."
                        }
                    }
                }
            }
        }
        presetRow.addView(btnPresetDirect)
        presetRow.addView(btnPresetTor)
        relayCard.addView(presetRow)
        advancedContainer.addView(relayCard)
        panelControl.addView(advancedContainer)

        val scrollControl = ScrollView(this).apply {
            isFillViewport = true
            layoutParams = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT)
            addView(panelControl)
        }
        contentFrame.addView(scrollControl)

        // ---------------- TAB 1: TEŞHİS PANELİ ----------------
        panelDiag = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val noticeCard = TextView(this).apply {
            text = "Bilgi: Bu sekmedeki ağ tanılaması, operatörünüzün (ISP) genel sansür ve DPI durumunu doğrudan ölçmek için tünel dışından ham hat üzerinden yapılır."
            textSize = 10.5f
            setTextColor(Color.parseColor("#94A3B8"))
            background = createCardShape("#0E182A", borderColor = "#1E293B", cornerDp = 10f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, 0, 0, dp(6))
            }
        }
        panelDiag.addView(noticeCard)

        val android17Notice = TextView(this).apply {
            text = "Android 16 QPR1+ / 17 Ağ Koruması: Ani ağ geçişlerinde QUIC soket kapanışı ve Wi-Fi ↔ 5G otomatik oturum + WireGuard soket koruması desteklenir."
            textSize = 10f
            setTextColor(Color.parseColor("#7DD3FC"))
            background = createCardShape("#0A1A2F", borderColor = "#1D4ED8", cornerDp = 10f)
            setPadding(dp(10), dp(7), dp(10), dp(7))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, 0, 0, dp(8))
            }
        }
        panelDiag.addView(android17Notice)

        fun inputLabel(t: String) = TextView(this).apply {
            text = t
            textSize = 10.5f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(6), 0, dp(2))
        }

        panelDiag.addView(inputLabel("Test hedefleri (her satıra bir tane):"))
        targets = EditText(this).apply {
            setText(state?.getString(KEY_TARGETS) ?: "cloudflare.com\nwikipedia.org\nietf.org")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 12f
            setTextColor(Color.WHITE)
            background = createCardShape("#0E1626", cornerDp = 8f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            minLines = 2
        }
        panelDiag.addView(targets)

        panelDiag.addView(inputLabel("Karşılaştırılacak DNS (isteğe bağlı):"))
        altDns = EditText(this).apply {
            setText(state?.getString(KEY_ALT) ?: "")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 12f
            setTextColor(Color.WHITE)
            background = createCardShape("#0E1626", cornerDp = 8f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            hint = "örn. 1.1.1.1"
            setHintTextColor(Color.parseColor("#475569"))
        }
        panelDiag.addView(altDns)

        panelDiag.addView(inputLabel("Şifreli DoH3/DoH adresleri (isteğe bağlı, boşsa çoklu DoH3 yarışı kullanılır):"))
        dohEndpoints = EditText(this).apply {
            setText(state?.getString(KEY_DOH) ?: "")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 12f
            setTextColor(Color.WHITE)
            background = createCardShape("#0E1626", cornerDp = 8f)
            setPadding(dp(10), dp(8), dp(10), dp(8))
            hint = "örn. https://1.1.1.1/dns-query"
            setHintTextColor(Color.parseColor("#475569"))
        }
        panelDiag.addView(dohEndpoints)

        auto = CheckBox(this).apply {
            text = "Ağ değişince yeniden tanıla (ölçülü ağlarda durur)"
            textSize = 11f
            setTextColor(Color.parseColor("#94A3B8"))
            isChecked = state?.getBoolean(KEY_AUTO) ?: false
            setPadding(dp(4), dp(6), 0, dp(6))
        }
        panelDiag.addView(auto)

        val actRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, dp(6), 0, dp(8))
            }
        }
        runButton = Button(this).apply {
            text = "Ağ Tanıla"
            isEnabled = false
            textSize = 12.5f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
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
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#94A3B8"))
            background = createCardShape("#1E293B", cornerDp = 10f)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(dp(4), 0, 0, 0)
            }
            setOnClickListener { applied() }
        }
        actRow.addView(runButton)
        actRow.addView(appliedButton)
        panelDiag.addView(actRow)

        diagStatus = TextView(this).apply {
            text = "Teşhis motoru başlatılıyor..."
            textSize = 11.5f
            setTextColor(Color.parseColor("#38BDF8"))
            setPadding(0, dp(2), 0, dp(6))
        }
        panelDiag.addView(diagStatus)

        val diagOutHeader = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        val outTitle = TextView(this).apply {
            text = "Ölçüm Raporu & Sansür Teşhisi"
            textSize = 11f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#94A3B8"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val btnCopyDiag = TextView(this).apply {
            text = "Panoya Kopyala"
            textSize = 10.5f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#38BDF8"))
            background = createCardShape("#131D31", borderColor = "#1E293B", cornerDp = 6f)
            setPadding(dp(8), dp(4), dp(8), dp(4))
            setOnClickListener {
                copyToClipboard("Freedom Network Raporu", diagOutput.text.toString())
            }
        }
        diagOutHeader.addView(outTitle)
        diagOutHeader.addView(btnCopyDiag)
        panelDiag.addView(diagOutHeader)

        diagOutput = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextColor(Color.parseColor("#E2E8F0"))
            background = createCardShape("#090D16", borderColor = "#1E293B", cornerDp = 10f)
            setPadding(dp(10), dp(10), dp(10), dp(10))
            minLines = 6
            setTextIsSelectable(true)
            text = state?.getString(KEY_OUTPUT) ?: "Tanılama henüz çalıştırılmadı."
        }
        panelDiag.addView(diagOutput)

        val scrollDiag = ScrollView(this).apply {
            isFillViewport = true
            layoutParams = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT)
            addView(panelDiag)
        }
        contentFrame.addView(scrollDiag)

        // ---------------- TAB 2: GÜNLÜK & DEBUGGER ----------------
        panelLog = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val logPathCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = createCardShape("#0E1626", borderColor = "#1E293B", cornerDp = 12f)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, 0, 0, dp(10))
            }
        }
        val logPathTitle = TextView(this).apply {
            text = "Freedom Network Dahili Debugger & Günlük Yolu"
            textSize = 11f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#10B981"))
        }
        val logPathVal = TextView(this).apply {
            text = CrashLogger.getDebugLogPath()
            textSize = 10f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(3), 0, dp(6))
        }
        logPathCard.addView(logPathTitle)
        logPathCard.addView(logPathVal)

        val logBtnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        fun createLogBtn(label: String, colorStr: String): Button {
            return Button(this).apply {
                text = label
                textSize = 11f
                typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.WHITE)
                background = createCardShape(colorStr, cornerDp = 8f)
                setPadding(dp(8), dp(6), dp(8), dp(6))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    setMargins(dp(2), 0, dp(2), 0)
                }
            }
        }

        val btnCopyLog = createLogBtn("Kopyala", "#2563EB").apply {
            setOnClickListener { copyToClipboard("Freedom Network Log", logOutput.text.toString()) }
        }
        val btnCrashCheck = createLogBtn("Çökme Raporu", "#475569").apply {
            setOnClickListener { readCrashLog() }
        }
        val btnRefreshLog = createLogBtn("Yenile", "#059669").apply {
            setOnClickListener { refreshLogViewer() }
        }
        logBtnRow.addView(btnCopyLog)
        logBtnRow.addView(btnCrashCheck)
        logBtnRow.addView(btnRefreshLog)
        logPathCard.addView(logBtnRow)
        panelLog.addView(logPathCard)

        logStatus = TextView(this).apply {
            text = "Canlı Uygulama Günlüğü (Son Olaylar)"
            textSize = 10.5f
            setTextColor(Color.parseColor("#94A3B8"))
            setPadding(0, dp(4), 0, dp(4))
        }
        panelLog.addView(logStatus)

        logOutput = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 10.5f
            setTextColor(Color.parseColor("#A7F3D0"))
            background = createCardShape("#080C14", borderColor = "#1E293B", cornerDp = 10f)
            setPadding(dp(10), dp(10), dp(10), dp(10))
            minLines = 8
            setTextIsSelectable(true)
            text = CrashLogger.getRecentLogs(150)
        }
        panelLog.addView(logOutput)

        val scrollLog = ScrollView(this).apply {
            isFillViewport = true
            layoutParams = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT)
            addView(panelLog)
        }
        contentFrame.addView(scrollLog)

        root.addView(contentFrame)

        // Setup tab switching + Predictive Back hook
        tabSwitcher = { index ->
            activeTabIndex = index
            val activeBg = createCardShape("#1E293B", borderColor = "#334155", cornerDp = 8f)
            val inactiveBg = GradientDrawable().apply { setColor(Color.TRANSPARENT) }

            tabBtnControl.background = if (index == 0) activeBg else inactiveBg
            tabBtnControl.setTextColor(if (index == 0) Color.WHITE else Color.parseColor("#64748B"))

            tabBtnDiag.background = if (index == 1) activeBg else inactiveBg
            tabBtnDiag.setTextColor(if (index == 1) Color.WHITE else Color.parseColor("#64748B"))

            tabBtnLog.background = if (index == 2) activeBg else inactiveBg
            tabBtnLog.setTextColor(if (index == 2) Color.WHITE else Color.parseColor("#64748B"))

            scrollControl.visibility = if (index == 0) View.VISIBLE else View.GONE
            scrollDiag.visibility = if (index == 1) View.VISIBLE else View.GONE
            scrollLog.visibility = if (index == 2) View.VISIBLE else View.GONE

            updatePredictiveBackRegistration(index != 0)
            if (index == 2) refreshLogViewer()
        }

        tabBtnControl.setOnClickListener { tabSwitcher(0) }
        tabBtnDiag.setOnClickListener { tabSwitcher(1) }
        tabBtnLog.setOnClickListener { tabSwitcher(2) }
        tabSwitcher(state?.getInt(KEY_TAB) ?: 0)

        root.setOnApplyWindowInsetsListener { v, insets ->
            val b = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime() or WindowInsets.Type.displayCutout())
            v.setPadding(b.left + dp(14), b.top + dp(10), b.right + dp(14), b.bottom + dp(10))
            WindowInsets.CONSUMED
        }
        return root
    }

    private fun updateDashboardMetrics(isVpn: Boolean, p: ProxyStatus?, b: TunBridge?) {
        val tcp = b?.tcpFlows?.get() ?: 0
        val desync = b?.desyncedFlows?.get() ?: 0
        val warpOut = b?.warpPacketsOut?.get() ?: 0L
        val warpIn = b?.warpPacketsIn?.get() ?: 0L
        if (b?.isWarpActive == true) {
            cardTcp.update("${warpOut + warpIn} WARP", "Şifreli TX/RX: $warpOut/$warpIn")
        } else {
            cardTcp.update("$tcp Akış", "Desync: $desync · Splice: ${b?.visionSplicedFlows?.get() ?: 0}")
        }

        val tlsFrag = b?.tlsRecordFragmented?.get() ?: 0
        val spoofed = b?.httpHeadersSpoofed?.get() ?: 0
        cardTls.update("$tlsFrag Kayıt", "Kimlik Başlık: $spoofed · RST: ${p?.rstDropped ?: 0}")

        val udp = b?.udpFlows?.get() ?: 0
        val quicFall = b?.quicFallbacks?.get() ?: 0
        val leaks = b?.leaksBlocked?.get() ?: 0
        cardUdp.update("$leaks Sızıntı", "UDP: $udp · QUIC: $quicFall")

        val dns = b?.dnsQueries?.get() ?: 0
        val doh = b?.dohResolved?.get() ?: 0
        val aaaa = b?.aaaaSuppressed?.get() ?: 0
        val trackers = b?.trackersBlocked?.get() ?: 0
        cardDns.update("$dns Sorgu", "DoH3: $doh · AAAA: $aaaa · İz: $trackers")

        val isFreedomActive = isVpn || (p?.active == true)
        if (isFreedomActive) {
            if (isVpn) {
                when {
                    b?.isWarpActive == true -> {
                        statusPill.text = "WARP WIREGUARD AKTİF · IP GİZLİ + DoH3"
                        statusPill.setTextColor(Color.parseColor("#10B981"))
                        statusPill.background = createCardShape("#064E3B", borderColor = "#059669", cornerDp = 20f)
                        ipCardStatus.text = "Aktif Rota: ${b.activeExitRelayLabel} — Tüm cihaz trafiği Cloudflare WireGuard üzerinden şifrelenir."
                    }
                    b?.isIpMasked == true -> {
                        statusPill.text = "IP GİZLİ (${b.activeExitRelayLabel}) · DoH3 + KALKAN"
                        statusPill.setTextColor(Color.parseColor("#A78BFA"))
                        statusPill.background = createCardShape("#2E1065", borderColor = "#7C3AED", cornerDp = 20f)
                        ipCardStatus.text = "Aktif Rota: ${b.activeExitRelayLabel} (Genel çıkış IP maskeleniyor)."
                    }
                    else -> {
                        val lbl = b?.activeExitRelayLabel ?: "WARP Bağlanıyor..."
                        statusPill.text = lbl.uppercase(java.util.Locale.US)
                        statusPill.setTextColor(Color.parseColor("#38BDF8"))
                        statusPill.background = createCardShape("#0B2942", borderColor = "#0284C7", cornerDp = 20f)
                        ipCardStatus.text = "Aktif Rota: $lbl · Şifreli DoH3 + TLS/ECH kalkanı açık."
                    }
                }
            } else {
                statusPill.text = "YEREL VEKİL AKTİF (127.0.0.1:${p?.port ?: 0})"
                statusPill.setTextColor(Color.parseColor("#10B981"))
                statusPill.background = createCardShape("#064E3B", borderColor = "#059669", cornerDp = 20f)
            }

            if (switchMockLocation.isChecked) {
                locationStatusView.text = NullIslandLocationShield.lastStatusText
                btnDevOptions.visibility = if (NullIslandLocationShield.needsDeveloperPermission) View.VISIBLE else View.GONE
            }

            heroActionButton.text = "KORUMAYI DURDUR (Özgür Ağ Tünelini Kapat)"
            heroActionButton.setTextColor(Color.WHITE)
            heroActionButton.background = createCardShape("#DC2626", cornerDp = 12f)
        } else {
            statusPill.text = "KORUMA DEVRE DIŞI · DOKUNARAK BAĞLANIN"
            statusPill.setTextColor(Color.parseColor("#94A3B8"))
            statusPill.background = createCardShape("#0E1626", borderColor = "#1E293B", cornerDp = 20f)
            ipCardStatus.text = "Hazır · Başlatıldığında otomatik WARP WireGuard şifreli çıkışı + AAAA/WebRTC/STUN koruması devreye girer."

            heroActionButton.text = "ÖZGÜR AĞI BAŞLAT (WARP + Tam Gizlilik)"
            heroActionButton.setTextColor(Color.parseColor("#070B14"))
            heroActionButton.background = createCardShape("#10B981", cornerDp = 12f)
        }
    }

    private fun copyToClipboard(label: String, text: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(this, "$label panoya kopyalandı", Toast.LENGTH_SHORT).show()
    }

    private fun refreshLogViewer() {
        worker.execute {
            val text = CrashLogger.getRecentLogs(150)
            ui {
                logOutput.text = text
                logStatus.text = "Canlı Günlük: ${java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())} itibarıyla güncellendi"
            }
        }
    }

    private fun readCrashLog() {
        val crash = CrashLogger.getCrashLogContent()
        if (crash.isNullOrBlank()) {
            Toast.makeText(this, "Kayıtlı çökme raporu bulunamadı (Sistem Kararlı)", Toast.LENGTH_LONG).show()
            logOutput.text = "SİSTEM KARARLI: Kayıtlı çökme (crash dump) bulunamadı.\nDosya: ${CrashLogger.getCrashLogPath()}"
        } else {
            logOutput.text = crash
            Toast.makeText(this, "Çökme raporu yüklendi", Toast.LENGTH_SHORT).show()
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
        outState.putInt(KEY_TAB, activeTabIndex)
        outState.putString(KEY_TARGETS, targets.text.toString())
        outState.putString(KEY_ALT, altDns.text.toString())
        outState.putString(KEY_DOH, dohEndpoints.text.toString())
        outState.putString(KEY_EXIT_RELAY, exitRelayInput.text.toString())
        outState.putString(KEY_PERSONA, selectedPersona.id)
        outState.putBoolean(KEY_AUTO, auto.isChecked)
        outState.putString(KEY_OUTPUT, diagOutput.text.toString().take(64 * 1024))
    }

    override fun onDestroy() {
        updatePredictiveBackRegistration(false)
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
            diagStatus.text = "Ağ değişti (${Text.networkType(env.networkType)}); önceki sonuçlar geçersiz."
            appliedButton.isEnabled = false
            if (auto.isChecked && env.metered != YES && !busy.get()) startRun(verifyRuns = 0)
        }
    }

    private fun readHeaderLineAscii(input: InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 4096) {
            val c = input.read()
            if (c < 0) throw IOException("EOF")
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun readFixedBytes(input: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = input.read(buf, got, n - got)
            if (r < 0) throw IOException("EOF")
            got += r
        }
        return buf
    }

    private fun fetchPublicIpDirect(): String {
        val conn = (URL("https://api.ipify.org").openConnection() as HttpsURLConnection).apply {
            connectTimeout = 4000
            readTimeout = 4000
            instanceFollowRedirects = false
        }
        return try {
            val code = conn.responseCode
            if (code !in 200..299) throw IOException("HTTP $code")
            conn.inputStream.bufferedReader(Charsets.UTF_8).readText().trim()
        } finally {
            conn.disconnect()
        }
    }

    private fun fetchPublicIpViaRelay(relay: ExitRelayConfig): String {
        val raw = Socket()
        var ssl: SSLSocket? = null
        try {
            raw.connect(InetSocketAddress(InetAddress.getByName(relay.host), relay.port), 5000)
            raw.soTimeout = 5500
            val tunnel: Socket = if (relay.scheme == "https") {
                val fac = SSLSocketFactory.getDefault() as SSLSocketFactory
                (fac.createSocket(raw, relay.host, relay.port, true) as SSLSocket).apply {
                    sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    startHandshake()
                }
            } else {
                raw
            }
            val input = tunnel.getInputStream()
            val out = tunnel.getOutputStream()
            if (relay.scheme == "socks5") {
                val hasAuth = relay.username.isNotEmpty() || relay.password.isNotEmpty()
                out.write(if (hasAuth) byteArrayOf(0x05, 0x02, 0x00, 0x02) else byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val choice = readFixedBytes(input, 2)
                val method = choice[1].toInt() and 0xFF
                if (method == 0x02) {
                    val u = relay.username.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val p = relay.password.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val auth = ByteArray(3 + u.size + p.size)
                    auth[0] = 0x01; auth[1] = u.size.toByte()
                    System.arraycopy(u, 0, auth, 2, u.size)
                    auth[2 + u.size] = p.size.toByte()
                    System.arraycopy(p, 0, auth, 3 + u.size, p.size)
                    out.write(auth); out.flush()
                    if (readFixedBytes(input, 2)[1].toInt() != 0) throw IOException("SOCKS5 kimlik doğrulama hatası")
                } else if (method != 0x00) {
                    throw IOException("SOCKS5 yöntem desteklenmiyor: $method")
                }
                val hostB = "api.ipify.org".toByteArray(Charsets.US_ASCII)
                val req = ByteArray(7 + hostB.size)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03; req[4] = hostB.size.toByte()
                System.arraycopy(hostB, 0, req, 5, hostB.size)
                req[5 + hostB.size] = ((443 ushr 8) and 0xFF).toByte()
                req[6 + hostB.size] = (443 and 0xFF).toByte()
                out.write(req); out.flush()
                val hdr = readFixedBytes(input, 4)
                if (hdr[1].toInt() != 0) throw IOException("SOCKS5 CONNECT hatası (${hdr[1].toInt() and 0xFF})")
                when (hdr[3].toInt() and 0xFF) {
                    0x01 -> readFixedBytes(input, 6)
                    0x03 -> readFixedBytes(input, (readFixedBytes(input, 1)[0].toInt() and 0xFF) + 2)
                    0x04 -> readFixedBytes(input, 18)
                }
            } else {
                val sb = StringBuilder("CONNECT api.ipify.org:443 HTTP/1.1\r\nHost: api.ipify.org:443\r\n")
                if (relay.username.isNotEmpty() || relay.password.isNotEmpty()) {
                    val b64 = java.util.Base64.getEncoder().encodeToString("${relay.username}:${relay.password}".toByteArray(Charsets.UTF_8))
                    sb.append("Proxy-Authorization: Basic ").append(b64).append("\r\n")
                }
                sb.append("\r\n")
                out.write(sb.toString().toByteArray(Charsets.US_ASCII)); out.flush()
                val statusLine = readHeaderLineAscii(input)
                val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                if (code !in 200..299) throw IOException("CONNECT başarısız: $statusLine")
                while (readHeaderLineAscii(input).isNotEmpty()) { /* drain */ }
            }
            val sslFac = SSLSocketFactory.getDefault() as SSLSocketFactory
            ssl = sslFac.createSocket(tunnel, "api.ipify.org", 443, true) as SSLSocket
            ssl.sslParameters = ssl.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            ssl.soTimeout = 5500
            ssl.startHandshake()
            ssl.outputStream.write("GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
            ssl.outputStream.flush()
            val sIn = ssl.inputStream
            readHeaderLineAscii(sIn)
            while (readHeaderLineAscii(sIn).isNotEmpty()) { /* drain headers */ }
            return sIn.bufferedReader(Charsets.UTF_8).readText().trim()
        } finally {
            runCatching { ssl?.close() }
            runCatching { raw.close() }
        }
    }

    private fun runPublicIpLeakCheck() {
        val relayRaw = exitRelayInput.text.toString().trim()
        val relay = ExitRelayConfig.parse(relayRaw)
        btnCheckPublicIp.isEnabled = false
        ipPrivacyResult.text = "Çıkış IP, DNS sızıntı ve kimlik kalkanı test ediliyor..."
        CrashLogger.log("MainActivity", "Genel Çıkış IP & Sızıntı testi başlatıldı (relay=${relay?.label() ?: "otomatik"})")
        worker.execute {
            val directRes = runCatching { fetchPublicIpDirect() }
            val relayRes = if (relay != null) runCatching { fetchPublicIpViaRelay(relay) } else null
            val b = ActiveBridgeHolder.current
            val summary = buildString {
                if (relay != null && relayRes != null) {
                    val maskedIp = relayRes.getOrNull()
                    if (maskedIp != null) {
                        append("GİZLİ ÇIKIŞ IP (Röle): $maskedIp")
                    } else {
                        append("Röle Hatası (${relay.label()}): ${relayRes.exceptionOrNull()?.message ?: "bağlanılamadı"}")
                    }
                    directRes.getOrNull()?.let { append(" · Ham Hat IP: $it") }
                } else if (b?.isWarpActive == true) {
                    val dirIp = directRes.getOrNull() ?: "ölçülemedi"
                    append("WARP WIREGUARD AKTİF (${b.activeExitRelayLabel}) · Cihaz trafiği Cloudflare çıkışı ile maskelenir (Ham ISP hat IP: $dirIp)")
                } else {
                    val dirIp = directRes.getOrNull() ?: "ölçülemedi (${directRes.exceptionOrNull()?.message})"
                    append("Rota: ${b?.activeExitRelayLabel ?: "Koruma Kapalı"} · Ham Hat IP: $dirIp")
                }
                append("\nKonum: ${if (NullIslandLocationShield.isActive) "0.0°, 0.0° Aktif" else "Kapalı"} · Kimlik: ${selectedPersona.shortLabel}")
                if (b != null) {
                    append("\nKalkan: IPv6=${b.ipv6Rejected.get()} · AAAA=${b.aaaaSuppressed.get()} · Sızıntı/STUN=${b.leaksBlocked.get()} · Zehir=${b.poisonedDnsBlocked.get()} · Başlık=${b.httpHeadersSpoofed.get()}")
                }
            }
            CrashLogger.log("MainActivity", "Gizlilik & Sızıntı Test Sonucu: $summary")
            ui {
                btnCheckPublicIp.isEnabled = true
                ipPrivacyResult.text = summary
            }
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
        diagStatus.text = "Tanılanıyor (Çoklu DoH3 Yarışı + TLS/ECH Kalkanı)..."
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
                    diagOutput.text = text
                    diagStatus.text = "Tamamlandı"
                    val d = lastDecision
                    appliedButton.isEnabled = d != null && d.state == 2 && d.action != 0 && d.action != 8
                    if (appliedButton.isEnabled) {
                        appliedButton.setTextColor(Color.WHITE)
                        appliedButton.background = createCardShape("#10B981", cornerDp = 10f)
                    }
                }
            } catch (e: Exception) {
                ui { diagStatus.text = "Hata: ${e.message}" }
            } finally {
                busy.set(false)
                ui { runButton.isEnabled = true }
            }
        }
    }

    private fun checkVpnConsentAndProceed(onConsent: () -> Unit) {
        val prefs = getSharedPreferences("freedom_prefs", Context.MODE_PRIVATE)
        val consent = prefs.getBoolean("vpn_prominent_disclosure_accepted", false)
        if (consent) {
            onConsent()
            return
        }

        // Google Play VpnService Prominent Disclosure & Consent Dialog
        val pad = (18 * resources.displayMetrics.density).toInt()
        val dialogView = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            background = createCardShape("#0E1626", borderColor = "#1E293B", cornerDp = 16f)

            val titleRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 0, 0, (10 * resources.displayMetrics.density).toInt())
            }
            val titleText = TextView(context).apply {
                text = "Freedom Network — VpnService ve Gizlilik Bildirimi"
                textSize = 15f
                typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.WHITE)
            }
            titleRow.addView(titleText)
            addView(titleRow)

            val desc = TextView(context).apply {
                text = "Freedom Network, ağınızdaki tüm kısıtlamaları kaldırmak, DPI (Derin Paket İnceleme) engellerini aşmak, izleyici/telemetri trafiğini süzmek ve IP sızıntılarını önlemek için Android VpnService API'sini kullanır.\n\n" +
                        "• Sıfır Kayıt (Strict No-Logs): Gezinme geçmişiniz, DNS sorgularınız ve kişisel verileriniz asla kaydedilmez veya üçüncü taraflara gönderilmez.\n" +
                        "• Cihaz İçi Koruma: Tüm paket desync işlemleri doğrudan cihazınız içinde yapılır.\n" +
                        "• Şifreli DoH3 & Kill Switch: DNS sorguları paralel şifreli DoH3 üzerinden çözülür ve şifresiz sızıntılar engellenir."
                textSize = 11.5f
                setTextColor(Color.parseColor("#94A3B8"))
                setLineSpacing(4f * resources.displayMetrics.density, 1f)
            }
            addView(desc)
        }

        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setView(dialogView)
            .setPositiveButton("Kabul Et ve Başlat") { d, _ ->
                prefs.edit().putBoolean("vpn_prominent_disclosure_accepted", true).apply()
                d.dismiss()
                onConsent()
            }
            .setNegativeButton("İptal") { d, _ ->
                d.dismiss()
            }
            .setCancelable(false)
            .show()
    }

    private fun toggleDesync() {
        val s = session ?: run {
            CrashLogger.log("MainActivity", "toggleDesync: session null!")
            return
        }
        val vpnActive = FreedomVpnService.isRunning.get()
        val proxyActive = s.proxyStats().active
        CrashLogger.log("MainActivity", "toggleDesync tıklandı: vpnActive=$vpnActive, proxyActive=$proxyActive")
        if (vpnActive || proxyActive) {
            runCatching {
                startService(Intent(this, FreedomVpnService::class.java).setAction(FreedomVpnService.ACTION_STOP))
            }
            worker.execute {
                try {
                    s.stopProxy()
                    val next = s.proxyStats()
                    val text = Text.vpnStatus(false, next)
                    ui {
                        diagOutput.text = text + "\n" + diagOutput.text.toString()
                        powerShieldView.isActive = false
                        diagStatus.text = "Freedom Network durduruldu"
                        updateDashboardMetrics(false, next, ActiveBridgeHolder.current)
                    }
                    CrashLogger.log("MainActivity", "Freedom Network durduruldu.")
                } catch (t: Throwable) {
                    CrashLogger.log("MainActivity", "stopProxy hatası", t)
                }
            }
            return
        }

        checkVpnConsentAndProceed {
            val prepIntent = try {
                VpnService.prepare(this)
            } catch (t: Throwable) {
                CrashLogger.log("MainActivity", "VpnService.prepare hatası: ${t.message}", t)
                null
            }
            if (prepIntent != null) {
                CrashLogger.log("MainActivity", "VPN hazırlık intent'i başlatılıyor...")
                diagStatus.text = "Sistem geneli koruma için VPN izni bekleniyor…"
                @Suppress("DEPRECATION")
                startActivityForResult(prepIntent, REQ_VPN)
            } else {
                CrashLogger.log("MainActivity", "VPN hazırlık intent'i null (izin zaten var).")
                activateEngelsizMod(vpnGranted = true)
            }
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
        val killSwitchEnabled = switchKillSwitch.isChecked
        val trackersEnabled = switchTrackerGuard.isChecked
        val quicEnabled = switchQuicPassthrough.isChecked
        val mockLocationEnabled = switchMockLocation.isChecked
        val exitRelayStr = exitRelayInput.text.toString().trim()
        getSharedPreferences("freedom_prefs", Context.MODE_PRIVATE).edit()
            .putString(PREF_EXIT_RELAY, exitRelayStr)
            .putString(PREF_PERSONA, selectedPersona.id)
            .putBoolean(PREF_MOCK_LOCATION, mockLocationEnabled)
            .apply()
        val exitRelayLabel = ExitRelayConfig.parse(exitRelayStr)?.label() ?: ""
        CrashLogger.log(
            "MainActivity",
            "activateEngelsizMod çağrıldı (vpnGranted=$vpnGranted, killSwitch=$killSwitchEnabled, trackers=$trackersEnabled, quic=$quicEnabled, mockLoc=$mockLocationEnabled, persona=${selectedPersona.id}, relay=$exitRelayLabel)",
        )
        val dohList = ArrayList(split(dohEndpoints.text.toString()))
        val dnsList = ArrayList(split(altDns.text.toString()))
        if (vpnGranted) {
            runCatching {
                val vpnIntent = Intent(this, FreedomVpnService::class.java)
                    .putStringArrayListExtra(FreedomVpnService.EXTRA_DOH, dohList)
                    .putStringArrayListExtra(FreedomVpnService.EXTRA_DNS, dnsList)
                    .putExtra(FreedomVpnService.EXTRA_KILL_SWITCH, killSwitchEnabled)
                    .putExtra(FreedomVpnService.EXTRA_BLOCK_TRACKERS, trackersEnabled)
                    .putExtra(FreedomVpnService.EXTRA_STUN_SHIELD, killSwitchEnabled)
                    .putExtra(FreedomVpnService.EXTRA_QUIC_PASSTHROUGH, quicEnabled)
                    .putExtra(FreedomVpnService.EXTRA_EXIT_RELAY, exitRelayStr)
                    .putExtra(FreedomVpnService.EXTRA_MOCK_LOCATION, mockLocationEnabled)
                    .putExtra(FreedomVpnService.EXTRA_PERSONA, selectedPersona.id)
                startForegroundService(vpnIntent)
                CrashLogger.log("MainActivity", "FreedomVpnService startForegroundService çağrıldı")
            }.onFailure {
                CrashLogger.log("MainActivity", "FreedomVpnService başlatılamadı!", it)
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
                    trackersBlocked = b?.trackersBlocked?.get() ?: 0,
                    leaksBlocked = b?.leaksBlocked?.get() ?: 0,
                    killSwitch = killSwitchEnabled,
                    exitRelayLabel = exitRelayLabel,
                    ipMasked = (b?.isIpMasked == true) || exitRelayLabel.isNotEmpty(),
                    maskMethodLabel = b?.activeExitRelayLabel ?: "",
                    devicePersonaLabel = selectedPersona.shortLabel,
                    locationShieldLabel = if (mockLocationEnabled) NullIslandLocationShield.lastStatusText else "Kapalı",
                )
                ui {
                    diagOutput.text = text + "\n" + diagOutput.text.toString()
                    powerShieldView.isActive = true
                    updateDashboardMetrics(vpnGranted, next, b)
                    if (vpnGranted) {
                        diagStatus.text = if (exitRelayLabel.isNotEmpty()) {
                            "Freedom Network etkin: Çıkış IP Gizli ($exitRelayLabel) + DoH3"
                        } else {
                            "Freedom Network etkin: WARP WireGuard Bağlanıyor + DoH3 (${selectedPersona.shortLabel})"
                        }
                    } else {
                        diagStatus.text = "VPN izni verilmedi; yalnızca yerel proxy etkin (127.0.0.1:${next.port})"
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
                    diagStatus.text = "Doğrulama başlatıldı: iki ölçüm yapılacak"
                    startRun(verifyRuns = 1)
                } else {
                    diagStatus.text = "Doğrulama başlatılamadı: ${Text.code(rc)}"
                }
            }
        }
    }

    private fun split(s: String) = s.split('\n', ',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }

    private companion object {
        const val REQ_VPN = 1001
        const val REQ_NOTIF = 1002
        const val KEY_TAB = "tab"
        const val KEY_TARGETS = "targets"
        const val KEY_ALT = "alt"
        const val KEY_DOH = "doh"
        const val KEY_EXIT_RELAY = "exit_relay"
        const val KEY_PERSONA = "device_persona"
        const val KEY_AUTO = "auto"
        const val KEY_OUTPUT = "output"
        const val PREF_KILL_SWITCH = "pref_kill_switch"
        const val PREF_BLOCK_TRACKERS = "pref_block_trackers"
        const val PREF_QUIC_PASSTHROUGH = "pref_quic_passthrough"
        const val PREF_EXIT_RELAY = "pref_exit_relay"
        const val PREF_MOCK_LOCATION = "pref_mock_location"
        const val PREF_PERSONA = "pref_device_persona"
    }
}
