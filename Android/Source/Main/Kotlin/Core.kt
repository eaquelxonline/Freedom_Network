// THE DPI — Android 11–17 application (Kotlin, native Android SDK Views, Rust .so via JNI).
//
// Runs only while the activity is visible: no background service, no foreground service,
// no persistent storage. Probes start on explicit user action (or, if the user opts in,
// after a network change on an unmetered network).

package thedpi

import android.app.Activity
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
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

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
     * platform hostname verifier is applied as well (SSLSocket alone does not verify hostnames
     * on all Android versions).
     */
    fun prober(net: Network): TlsProber = TlsProber(
        SSLSocketFactory.getDefault() as SSLSocketFactory,
        { host, port, timeout ->
            val address = net.getByName(host)
            net.socketFactory.createSocket().apply { connect(InetSocketAddress(address, port), timeout) }
        },
        { host, session -> HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session) },
    )
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
    private lateinit var targets: EditText
    private lateinit var altDns: EditText
    private lateinit var runButton: Button
    private lateinit var appliedButton: Button
    private lateinit var auto: CheckBox
    private lateinit var status: TextView
    private lateinit var output: TextView
    private val networkCheck = Runnable { if (!worker.isShutdown) worker.execute { checkNetwork() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        cm = getSystemService(ConnectivityManager::class.java)
        setContentView(buildUi(savedInstanceState))
        worker.execute {
            try {
                session = DiagnosticSession()
                ui {
                    status.text = "Motor ${Native.engineVersion()} hazır"
                    runButton.isEnabled = true
                }
            } catch (e: NativeException) {
                ui { status.text = "Yerel motor başlatılamadı: ${e.message}" }
            }
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun ui(block: () -> Unit) {
        main.post { if (!isDestroyed) block() }
    }

    private fun buildUi(state: Bundle?): View {
        val pad = dp(16)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        fun label(t: String) = TextView(this).apply {
            text = t
            setPadding(0, dp(8), 0, dp(4))
        }
        column.addView(TextView(this).apply {
            text = "THE DPI"
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
        })
        column.addView(label(DISCLOSURE))
        column.addView(label("Test hedefleri (her satıra bir tane):"))
        targets = EditText(this).apply {
            setText(state?.getString(KEY_TARGETS) ?: "example.com")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_VARIATION_URI
            minLines = 2
        }
        column.addView(targets)
        column.addView(label("Karşılaştırılacak DNS (isteğe bağlı, IP adresi):"))
        altDns = EditText(this).apply {
            setText(state?.getString(KEY_ALT) ?: "")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            hint = "örn. 192.0.2.53"
        }
        column.addView(altDns)
        runButton = Button(this).apply {
            text = "Tanıla"
            isEnabled = false
            setOnClickListener { startRun(verifyRuns = 0) }
        }
        appliedButton = Button(this).apply {
            text = "Öneriyi uyguladım — doğrula"
            isEnabled = false
            setOnClickListener { applied() }
        }
        auto = CheckBox(this).apply {
            text = "Ağ değişince yeniden tanıla (ölçülü ağlarda çalışmaz)"
            isChecked = state?.getBoolean(KEY_AUTO) ?: false
        }
        column.addView(runButton)
        column.addView(appliedButton)
        column.addView(auto)
        status = TextView(this).apply { setPadding(0, dp(8), 0, dp(8)) }
        column.addView(status)
        output = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setTextIsSelectable(true)
            text = state?.getString(KEY_OUTPUT) ?: ""
        }
        column.addView(output)
        val scroll = ScrollView(this).apply {
            addView(column)
            isFillViewport = true
        }
        // Edge-to-edge is enforced for targetSdk ≥ 35: keep content clear of system bars and IME.
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            val b = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime() or WindowInsets.Type.displayCutout())
            v.setPadding(b.left, b.top, b.right, b.bottom)
            WindowInsets.CONSUMED
        }
        return scroll
    }

    override fun onStart() {
        super.onStart()
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
        callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        callback = null
        main.removeCallbacks(networkCheck)
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_TARGETS, targets.text.toString())
        outState.putString(KEY_ALT, altDns.text.toString())
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

    /** Debounces bursts of connectivity callbacks into one environment comparison. */
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
        runButton.isEnabled = false
        appliedButton.isEnabled = false
        status.text = "Tanılanıyor…"
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
                    val report = s.run(targetList, altList, cm.activeNetwork?.let { AndroidPlatform.prober(it) })
                    lastDecision = report.evaluation?.decision
                    text = Text.environment(env) + "\n" + Text.report(report)
                }
                ui {
                    output.text = text
                    status.text = "Tamamlandı"
                    val d = lastDecision
                    appliedButton.isEnabled = d != null && d.state == 2 && d.action != 0 && d.action != 8
                }
            } catch (e: Exception) {
                ui { status.text = "Hata: ${e.message}" }
            } finally {
                busy.set(false)
                ui { runButton.isEnabled = true }
            }
        }
    }

    /** The user reports applying the recommendation; the engine verifies it over two evaluations. */
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
        const val KEY_TARGETS = "targets"
        const val KEY_ALT = "alt"
        const val KEY_AUTO = "auto"
        const val KEY_OUTPUT = "output"
        const val DISCLOSURE =
            "Tanılama yalnızca yazdığınız test hedeflerine ve ağınızın DNS sunucularına düşük hacimli " +
                "bağlantılar kurar. Veriler cihazda kalır, kaydedilmez; sistem ayarları değiştirilmez."
    }
}
