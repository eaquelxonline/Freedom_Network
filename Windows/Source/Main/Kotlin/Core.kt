// THE DPI — Windows 10/11 x64 application (Kotlin/JVM, JDK Swing, Rust DLL via JNI).

package thedpi

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.KeyStore
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
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

/** Windows platform services: native IP Helper detection and the Windows certificate store. */
object WindowsPlatform {
    /**
     * TLS trust anchors from the Windows certificate store via the JDK SunMSCAPI provider
     * ("Windows-ROOT"). Falls back to the JDK trust store when unavailable (non-Windows test host).
     */
    val trust: Pair<SSLSocketFactory, String> by lazy {
        try {
            val ks = KeyStore.getInstance("Windows-ROOT")
            ks.load(null, null)
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(ks)
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, tmf.trustManagers, null)
            ctx.socketFactory to "Windows sertifika deposu"
        } catch (e: Exception) {
            SSLContext.getDefault().socketFactory to "JDK güven deposu"
        }
    }

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

/** Headless mode: `TheDPI --cli example.com [--dns 1.1.1.1] [--alt 9.9.9.9]`. */
fun runCli(args: List<String>): Int {
    val targets = ArrayList<String>()
    val dns = ArrayList<String>()
    val alt = ArrayList<String>()
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--cli" -> {}
            "--dns" -> dns += args.getOrNull(++i) ?: ""
            "--alt" -> alt += args.getOrNull(++i) ?: ""
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
            print(Text.report(session.run(targets, alt.filter { it.isNotEmpty() }, WindowsPlatform.prober())))
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
    private val runButton = JButton("Tanıla")
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
        val buttons = JPanel().apply { add(runButton); add(appliedButton); add(auto) }
        c.gridx = 0; c.gridy = 3; c.gridwidth = 2; form.add(buttons, c)

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
        runButton.isEnabled = false
        appliedButton.isEnabled = false
        status.text = "Tanılanıyor…"
        worker.execute {
            try {
                var remaining = verifyRuns + 1
                var text = ""
                while (remaining-- > 0) {
                    val env = refreshEnvironment(s)
                    val report = s.run(targetList, altList, WindowsPlatform.prober())
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
