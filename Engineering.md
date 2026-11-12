# Freedom Network — Mühendislik Belgesi (0.0 → 2.0)

Durum tarihi: **12 Kasım 2026** · Dal: `The_DPI_Beta` · Paket: **`com.freedom.network`** · Sürüm: **1.0.0 (2026–2027 Evrensel Özgür Ağ Mimari Sürümü)**

Bu belge; araştırma sonuçlarını, uyumluluk matrisini, mimariyi, tehdit modelini, test ve benchmark
raporlarını, bilinen sınırları ve yapılmayanları tek yerde toplar. "Doğrulandı" işareti, iddianın bu
çalışma sırasında resmî kaynaktan veya gerçek bir derleme/test çalıştırmasıyla kontrol edildiği anlamına
gelir. "Doğrulanmadı" olarak işaretli maddeler gerçek donanımda kontrol edilmelidir.

---

## İçindekiler

1. Nihai teknik mimari
2. Araç zinciri uyumluluk matrisi (Kasım 2026)
3. 2027 yükseltme politikası
4. Android 11–17 uyumluluğu
5. Windows 10–11 uyumluluğu
6. Rust yerel çekirdek tasarımı
7. JNI mimarisi
8. Ağ zekâsı mimarisi
9. Teşhis ve adaptif karar algoritması
10. Protokol araştırması (DNS, TCP, UDP, TLS, QUIC, ECH, HTTP/3, MTU, OHTTP/ODoH)
11. Gizlilik ve güvenlik tehdit modeli
12. Performans stratejisi ve benchmark sonuçları
13. Bağımlılık denetimi
14. Dosya yapısı ve bilinçli sapmalar
15. Aşama raporları 0.0 → 1.0
16. Test ve yayın kabul kriterleri + test raporu
17. Teknik riskler ve sabit teknoloji kısıtlarıyla yapılamayanlar
18. Derleme ve test talimatları
19. Windows paket seviyesi katman (WFP) — sürücü yolu
20. Aktif DPI aşma (`desync`), SIMD Assembly ve cihaz içi `TunBridge`
21. Hibrit ağ özgürlüğü mimarisi (`REALITY + X25519MLKEM768 + Kişisel Röle`)
22. Freedom Network 2026–2027 evrensel kısıt kaldırma, gizlilik kalkanı ve arayüz yenilemesi

---

## 1. Nihai teknik mimari

```
┌──────────────────────── Android (Kotlin, SDK Views) ───────┐   ┌──── Windows (Kotlin/JVM, Swing) ────┐
│ ConnectivityManager · VpnService · WindowInsets (API 30-37)│   │ IP Helper (Rust FFI) · Registry       │
│ TunBridge (DoH3 + KillSwitch + TrackerGuard) · Platform TLS│   │ JSSE + Windows-ROOT sertifika deposu  │
└───────────────┬─────────────────────────────────────────────┘   └──────────────┬───────────────────────┘
                │        Core.kt SHARED SECTION (tek JNI sınırı, wire codec,     │
                └────────► TlsProber, TunBridge, IpPackets, DiagnosticSession)◄───┘
                                       │  byte[] (versiyonlu TLV, "DP" v1)
                                       ▼
┌────────────────────────── Native/Core.rs (Rust, yalnızca std, crate: freedom) ───────────┐
│ jni/exports → api → registry(opak handle) → engine                                        │
│ engine: probe → intel → decide → desync → relay → oblivious (OHTTP/ODoH) → wire           │
│ sys: setsockopt(DF), GetAdaptersAddresses, RegGetValueW  (tüm unsafe FFI burada)           │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

Temel ilkeler:

* **Ölçüm Rust'ta, güven platformda.** DNS, TCP, UDP, QUIC ve MTU ölçümleri ile tüm karar, DPI aşma
  (`desync`), röle (`relay`) ve gizlilik (`oblivious`) mantığı Rust çekirdeğinde (`libfreedom.so` /
  `freedom.dll`). TLS ise kriptografi gerektirdiği için doğrulanmış platform yığınında ölçülür
  (Android: platform TLS; Windows: JDK JSSE + Windows sertifika deposu). Rust'a yalnızca sonuçlar gelir.
  Böylece "özel kriptografi yazma" ve "harici TLS kütüphanesi kullanma" yasaklarının ikisi de korunur.
* **Sağlayıcıdan bağımsız.** Hiçbir yerde ISP adı veya uygulama bazlı ayrıcalık/sert kodlama yoktur.
  Kararlar ve aktif DPI aşma yalnızca ölçülen özelliklere ve evrensel ağ standartlarına dayanır.
* **Açıklanabilirlik.** Her teşhis `kategori + güven (0–100) + gözlemler` biçimindedir. Kanıt yoksa
  "Yetersiz kanıt" döner; belirli bir neden uydurulmaz.
* **Sessiz değişiklik yok.** Sistem ayarı gerektiren her eylem kullanıcıya **öneri** veya açıkça
  onaylanmış ("Engelsiz Mod" / Google Play VpnService açıklamalı) yerel tünel olarak sunulur.

## 2. Araç zinciri uyumluluk matrisi (Kasım 2026)

| Bileşen | Seçilen | En yeni kararlı | Karar gerekçesi | Kaynak / durum |
|---|---|---|---|---|
| Rust | **1.99.1** (kanal 2026-10-15) | 1.99.1 | Edition 2024, `as_chunks`, `if let` zincirleri | static.rust-lang.org kanal manifesti — doğrulandı |
| Rust edition | **2024** | 2024 | `unsafe extern`, `#[unsafe(no_mangle)]` zorunlu sözdizimi | doc.rust-lang.org/edition-guide — doğrulandı (derleme) |
| Kotlin | **2.5.0-RC** | 2.5.0-RC (en yeni kararlı: 2.4.21) | Kullanıcı kararı: en yeni sürüm. Aday sürüm olduğu için kararlı 2.5.0 çıkınca ona geçilmeli | Maven Central meta verisi — doğrulandı; derleme ve testler geçti |
| Gradle | **9.9.1** (2026-11-10) | 9.9.1 | En yeni kararlı (`Gradle/gradle-wrapper.jar`) | services.gradle.org — doğrulandı; derleme geçti |
| Android Gradle Plugin | **9.5.1** | 9.5.1 | En yeni kararlı; API 37 desteği, en düşük Gradle 9.6.0 | AGP 9.5 sürüm notu — doğrulandı; derleme ve lint geçti |
| JDK (derleme) | **21** | 25/26/27 (toolchain) | Gradle 9 en az JDK 17 ister; AGP 9.3 JDK 17 ister; JDK 21 LTS | docs.gradle.org compatibility — doğrulandı |
| Android compileSdk / targetSdk | **37** (`android-37.0`) | 37.2 (küçük SDK) | Android 17 = API 37 | Android Developers Blog "Android 17 is here", SDK repository2-3.xml — doğrulandı |
| Android minSdk | **30** (Android 11) | — | Kapsam gereği | — |
| Android NDK | **30.0.16248370** | 30.0.16248370 | En yeni; `libfreedom.so` 16 KB hizalı (`0x4000`) | SDK repository — doğrulandı |
| Build-Tools | **36.0.0** | 37.0.0 | AGP 9.3'ün varsayılanı ve en düşük sürümü | AGP 9.3 sürüm notu — doğrulandı |
| Gradle Wrapper | 9.9.1, `distributionSha256Sum` sabitlenmiş | — | Tedarik zinciri bütünlüğü (`Gradle/`) | services.gradle.org .sha256 — doğrulandı |

**Sürüm politikası (kullanıcı kararı, 12.11.2026):** Kullanılan tüm araçların en yeni sürümü kullanılır.
Bu kombinasyon (Gradle 9.9.1 + AGP 9.5.1 + Kotlin 2.5.0-RC + NDK 30) Kotlin'in resmî "tam desteklenen"
tablosunun dışında, ama bu projede derleme, testler ve lint gerçekten çalıştırılarak doğrulandı. Kotlin
2.5.0 kararlı sürümü yayımlandığında RC'den ona geçilmelidir.

## 3. 2027 yükseltme politikası

1. **Her yayından önce** bölüm 2'deki tabloyu yeniden doğrulayın: Rust kanal manifesti, Maven meta
   verisi, Gradle sürüm API'si, Kotlin uyumluluk tablosu, AGP sürüm notları.
2. **Kotlin yükseltmesi önce gelir.** Yeni KGP'nin tam destek aralığı Gradle 9.9 ve AGP 9.5 gibi
   sürümleri kapsadığında Gradle ve AGP birlikte yükseltilir. Sıra her zaman Kotlin → Gradle → AGP.
3. **Rust yeni kararlı sürümleri** (6 haftada bir) yalnızca `cargo test` + clippy (4 hedef) + Wine/QEMU
   testleri yeşilse `rust-toolchain.toml` üzerinden alınır. Güvenlik duyuruları doğrudan uygulanır.
4. **Android 18 (API 38)** yayımlandığında: targetSdk 38 davranış değişiklikleri ayrı bir dalda
   incelenir. compileSdk ancak AGP desteği doğrulandıktan sonra yükseltilir.
5. **Yayımlanmamış hiçbir özelliğe** (örn. AGP 9.6 önizleme) dayanılmaz.
6. **Windows 10:** ESU durumu her yayında gözden geçirilir (bkz. bölüm 5).

## 4. Android 11–17 uyumluluğu

| Konu | Uygulama | Kaynak / durum |
|---|---|---|
| API aralığı | minSdk 30, targetSdk 37, yalnızca `arm64-v8a` | — |
| Ağ bilgisi | `ConnectivityManager.activeNetwork`, `NetworkCapabilities` (transport, `VALIDATED`, `CAPTIVE_PORTAL`, `NOT_METERED`), `LinkProperties` (DNS, rotalar, `mtu` API 29, `isPrivateDnsActive` API 28), `restrictBackgroundStatus` | Android SDK referansı — derleme doğrulandı |
| Ağ değişimi | Etkinlik görünürken `registerDefaultNetworkCallback` + `FreedomVpnService` ağ geçiş callback'i (`rebindActiveSessions`) | Android SDK referansı |
| Arka plan / pil | Tanılama yalnızca kullanıcı eylemiyle çalışır; VPN etkinken `FreedomVpnService` `foregroundServiceType="specialUse"` (`android.permission.FOREGROUND_SERVICE_SPECIAL_USE`) kullanır | Google Play API 34+ uyumlu |
| Platform TLS | Probu ağa bağlı soket (`Network.socketFactory`) üzerinde `SSLSocketFactory` ile yapılır; `endpointIdentificationAlgorithm=HTTPS` ve ek olarak platform `HostnameVerifier` uygulanır | — |
| Edge-to-edge & Geri Hareket (API 30–37) | `Window.setDecorFitsSystemWindows(false)`, şeffaf sistem çubukları, `WindowInsetsController.setSystemBarsAppearance` (koyu tema sistem ikonları), iç boşluğu koruyan `WindowInsets` (`systemBars + displayCutout + ime`) ve API 33–37 Öngörülü Geri (`OnBackInvokedCallback`) | Android 11–17 UI standartları — doğrulandı |
| **Android 17: yerel ağ koruması** | targetSdk 37'de yerel ağ trafiği `ACCESS_LOCAL_NETWORK` gerektirir. **İstisna:** cihazın yerel DNS sunucusuna 53 numaralı porttan giden trafik muaftır. Freedom Network izni **istemez**; kullanıcı yerel bir hedef girerse platform reddi `Blocked` durumu olarak raporlanır | developer.android.com/privacy-and-security/local-network-permission — doğrulandı |
| Android 17: yerel kod yükleme | `System.loadLibrary("freedom")` ile `libfreedom.so` doğrudan APK'dan salt-okunur yüklenir | Android 17 davranış değişiklikleri — doğrulandı |
| Android 17: büyük ekranda yön/boyut | Opt-out kaldırıldı. Uygulama yön kısıtlaması koymaz; `configChanges` ile yeniden oluşturmaya dayanıklı | Android 17 blog yazısı — doğrulandı |
| Android 17: ECH | Platform TLS ECH'yi (gerekirse GREASE ile) kendisi yönetir; Network Security Config'e `<domainEncryption>` eklendi | Android 17 davranış değişiklikleri — doğrulandı |
| 16 KB sayfa boyutu | `libfreedom.so` LOAD segmentleri `0x4000` hizalı (`-z max-page-size=16384`); `useLegacyPackaging=false` | `llvm-readelf` ile doğrulandı |
| İzinler | `INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS` | Play Store `VpnService` uyumlu |
| Yedekleme | `allowBackup=false` ve `dataExtractionRules` tüm alanları hariç tutuyor | Lint temiz |
| VpnService | **`FreedomVpnService` (Cihaz İçi Yerel TUN Köprüsü):** Uzak merkezi sunucu olmadan `0.0.0.0/0` + `::/0` trafiğini yakalar; kullanıcıya Google Play `VpnService` Belirgin Bildirimi (`AlertDialog`) ile açıkça açıklanır | — |
| Android Keystore | Yerel kalıcı gizli anahtar tutulmaz; tercihler (`freedom_prefs`) yalnızca arayüz anahtarlarını (Kill Switch, Tracker Kalkanı, QUIC) saklar | — |

## 5. Windows 10–11 uyumluluğu

| Konu | Uygulama | Durum |
|---|---|---|
| Ortam algılama | `GetAdaptersAddresses` (iphlpapi): bağdaştırıcı, `IfType`, `OperStatus`, MTU, DNS, ağ geçidi, metrik. Birincil bağdaştırıcı = çalışır durumda, loopback değil, ağ geçidi var, en düşük IPv4 metriği | Wine altında çalıştırılarak doğrulandı (yapı ofsetleri derleme zamanında `offset_of!` ile kontrol ediliyor) |
| Geri düşüş | `AF_UNSPEC + INCLUDE_GATEWAYS` ile `ERROR_NOT_SUPPORTED` dönerse yalnızca IPv4 görünümüne düşülür ve IPv6 "bilinmiyor" raporlanır (uydurulmaz) | Wine'da tetiklendi ve doğrulandı |
| Sürüm | `RegGetValueW(HKLM\…\CurrentVersion, CurrentBuildNumber/DisplayVersion)`. Build ≥ 22000 → Windows 11 (`GetVersionEx` manifest'e bağlı olduğu için kullanılmadı) | Wine'da doğrulandı (19043) |
| TLS güveni | JSSE + `KeyStore.getInstance("Windows-ROOT")` (SunMSCAPI); başarısız olursa JDK güven deposuna düşülür ve kullanılan depo arayüzde gösterilir | Gerçek Windows'ta doğrulanmadı |
| DF / MTU | Winsock `IP_DONTFRAGMENT` / `IPV6_DONTFRAG`; `WSAEMSGSIZE` yerel sınır olarak ele alınır | Wine'da test edildi |
| Yetki | **Yönetici izni gerekmez.** Hiçbir sistem ayarı değiştirilmez | — |
| DLL sertleştirme | MSVC derlemesi: `+crt-static`, `/DEPENDENTLOADFLAG:0x800` (bağımlı DLL'ler yalnızca System32'den) | CI Windows runner'da derleniyor |
| Paketleme | `jpackage --type app-image` (JDK aracı), `-Djava.library.path=$APPDIR`; ardından `signtool` ile Authenticode imzası (`FreedomNetwork.exe`) | Windows'ta çalıştırılmalı |
| **Windows 10 destek durumu** | Standart Microsoft desteği **14 Ekim 2025'te sona erdi**. Uygulama Windows 10'da çalışır ama build < 22000 algılandığında "Bilgilendirme" olarak uyarı gösterir (Windows 11'e geçiş veya ESU). Windows 10, güvenlik açısından Windows 11 ile eşdeğer kabul edilmez | Uyarı mantığı birim testiyle kapsanıyor |
| **Sistem geneli bağlantılar** | `GetExtendedTcpTable`/`GetExtendedUdpTable` (owner-PID tabloları, IPv4+IPv6) ve `QueryFullProcessImageNameW` ile makinedeki **tüm** TCP/UDP uç noktaları, sahip işlem adıyla birlikte. Kullanıcı modunda çalışır, sürücü ve yönetici izni gerektirmez. Bulgular: el sıkışmada takılan bağlantılar (SYN_SENT), CLOSE_WAIT sızıntısı, TIME_WAIT baskısı, tüm arayüzlerde dinleyen servisler. Tablo ayrıştırma güvenli ve platformdan bağımsız Rust kodu; `unsafe` yalnızca FFI çağrısında | Wine'da gerçek sistem tablosu okundu, testin kendi soketleri doğru ayrıştırıldı |
| Paket seviyesi (WFP) | Sürücü yolu bölüm 19'da | Sürücü imzası gerekiyor |

## 6. Rust yerel çekirdek tasarımı

* Tek crate, `Native/Cargo.toml` (`name = "freedom"`) tek doğruluk kaynağı, `[lib] path = "Core.rs"`, `crate-type = ["cdylib", "rlib"]`.
* **Sıfır üçüncü taraf crate.** `Native/Cargo.lock` yalnızca `freedom` paketini içerir.
* Modüller: `wire`, `dns`, `quic`, `sys`, `probe`, `intel`, `decide`, `desync`, `relay`, `oblivious`, `engine`, `registry`, `api`, `jni`/`exports`.
* **`unsafe` yalnızca `sys` (OS FFI) ve `jni`/`exports` içindedir.** Her blokta `// SAFETY:` gerekçesi
  vardır; clippy `undocumented_unsafe_blocks` ve `missing_safety_doc` kurallarını hata olarak uygular.
* Panik politikası: `panic = "unwind"` ve her JNI giriş noktası `catch_unwind` (`jni::guard`) ile sarılı.
  Panik FFI sınırını asla geçmez.
* Eşzamanlılık: `std::thread::scope` ile **sınırlı** sayıda işçi (1–8, yığın 256 KiB). Paylaşılan iş
  indeksi atomik; sonuçlar indekse göre sıralandığından çıktı zamanlamadan bağımsız ve deterministik.
* Zaman bütçesi: Her çalıştırmanın genel bir son tarihi var (varsayılan 20 sn). Her prob adımı bu son
  tarihe uyar.
* Global durum: Yalnızca motor kayıt defteri (`Mutex<Registry>`). JNI statik fonksiyonlar kullandığı için
  zorunlu. Handle'lar monoton artan ID'dir ve yeniden kullanılmaz, en fazla 16 motor tutulur.
* Bellek: Uzun süreli testte 5000 tanılama döngüsünde RSS farkı 16 KiB (bölüm 12).
* **Assembly:** `Native/x86_64.s` (x86_64, SSE2) ve `Native/Arm64.s` (ARM64, NEON), `core::arch::global_asm!`
  ile derleniyor; harici assembler veya `build.rs` gerekmiyor. x86_64 tarafında `extern "sysv64"`
  çağrı kuralı zorlandığı için tek dosya Linux, Android x86_64 ve Windows x64'te aynı şekilde çalışıyor.
  Diğer hedeflerde `std` yedeği kullanılıyor. Rutinler, `std` ile bayt bayt aynı sonucu verdiği
  x86_64, ARM64 (QEMU) ve Windows (Wine) üzerinde test edildi.

## 7. JNI mimarisi

* Tek sınıf: `com.freedom.network.Native` (Kotlin `object`, `@JvmStatic external`). Rust tarafı: `Java_com_freedom_network_Native_*`
  ve `JNI_OnLoad` (JNI 1.6).
* **Harici JNI crate'i yok.** JNI fonksiyon tablosu indeksleri JNI spesifikasyonundan alındı ve kurulu
  JDK'nın `jni.h` dosyası programla sayılarak doğrulandı: NewStringUTF=167, GetArrayLength=171,
  NewByteArray=176, GetByteArrayRegion=200, SetByteArrayRegion=208, ExceptionCheck=228.
  JVM testleri `-Xcheck:jni` ile çalışıyor.
* API v1 (`apiVersion() == 1`; uyumsuz sürümde oturum açılmaz):

| Fonksiyon | Giriş | Çıkış |
|---|---|---|
| `apiVersion()` | — | `Int` |
| `engineVersion()` | — | `String` |
| `create(config)` | `byte[]?` | `Long` handle (>0) veya hata kodu |
| `destroy(h)` | handle | kod |
| `detectEnvironment()` | — | `byte[]` (Windows: IP Helper; diğer: `UNSUPPORTED`) |
| `setEnvironment(h, env)` | `byte[]` | kod |
| `diagnose(h, request)` | `byte[]` hedefler + isteğe bağlı DNS'ler | `byte[]` ölçüm raporu |
| `submitTls(h, results)` | `byte[]` | kod |
| `evaluate(h)` | — | `byte[]` teşhis + karar |
| `networkChanged(h)` | — | kod |
| `markApplied(h, action)` | `Int` | kod |

* Hata kodları: 0 OK, −1 geçersiz girdi, −2 geçersiz handle, −3 wire, −4 meşgul, −5 sınır, −6 panik,
  −7 ortam yok, −8 veri yok, −9 desteklenmiyor, −10 JNI, −11 iç hata.
* Veri biçimi: "DP" + sürüm 1 + alanlar (`tag u8, kind u8, uzunluk u32 BE`); türler Int/Text/Record;
  en fazla 256 KiB, 4 seviye, 8192 alan, 4096 baytlık metin. Kotlin ve Rust codec'leri aynı testlerle
  doğrulanıyor (bozuk girdi ve fuzz dahil). JSON veya yansıma yok; 8 hedefli bir rapor 3,7 KB.

## 8. Ağ zekâsı mimarisi

**Ortam:** işletim sistemi/sürüm/build, mimari, ağ türü, arayüz, DNS sunucuları, ağ geçitleri, MTU,
IPv4/IPv6 varlığı (genel adres kuralı), captive portal, doğrulanmış ağ, ölçülü ağ, Özel DNS, Veri
Tasarrufu. Her değer üç durumlu tutulur (evet/hayır/**bilinmiyor**); platform bir bilgiyi vermiyorsa
"bilinmiyor" kalır.

**Ölçümler (düşük etkili, sınırlı, yalnızca kullanıcının girdiği hedefler ve sistemin DNS sunucuları):**

| Ölçüm | Yöntem | Maliyet |
|---|---|---|
| Çözümleyici gecikme/kayıp/jitter | Sunucu başına `dns_samples` (varsayılan 5) A sorgusu; kayıp ≥ %50 ise TCP üzerinden doğrulama | ≤ 4 sunucu |
| Hedef DNS | A, AAAA, HTTPS (tip 65) sorguları; EDNS0 1232; TC bitinde TCP'ye düşüş (RFC 7766); ID/soru eşleştirmesi (RFC 5452) | 3 sorgu |
| TCP v4/v6 | Yalnızca bağlantı kurma (üçlü el sıkışma ve kapatma, veri yok), `tcp_samples` (varsayılan 3) | 3+3 SYN |
| TLS | Platform TLS ile tek el sıkışma: sürüm, ALPN, şifre takımı, sertifika sonucu | 1 bağlantı |
| QUIC | Version Negotiation probu (bölüm 10); h3 ilan edilmişse 2, değilse 1 deneme | 1–2 × 1200 B UDP |
| Yol MTU'su | Yalnızca QUIC VN yanıtı alındıysa: DF bayraklı, boyut ikili aramalı VN probları (DPLPMTUD fikri) | ≤ 8 datagram |

## 9. Teşhis ve adaptif karar algoritması

**Sınıflandırma (`intel::classify`)** deterministik kural tabanlıdır. Örnek kurallar:

* Platform "bağlı değil" diyorsa → *Yerel ağ kesintisi* (%95); diğer çıkarımlar durdurulur.
* Tüm çözümleyiciler UDP'de sessiz ama TCP'de yanıtlıyorsa → *UDP erişilebilirlik sorunu* (%75).
  Hiçbiri yanıt vermiyorsa ve platform interneti doğruladıysa → *DNS zaman aşımı* (%80), doğrulamadıysa %55.
* NXDOMAIN → *DNS çözümleme hatası* (%85). Karar motoru, kanıtın tamamı NXDOMAIN ise DNS değişikliği
  değil "**Hedef adını kontrol et**" önerir.
* IPv6 adresi var ve IPv6 TCP başarısız, IPv4 başarılı → *IPv6 bağlantı hatası*. Cihazda genel IPv6 yoksa
  bu bir arıza değil, yalnızca bilgilendirmedir.
* Bir hedefte tüm TCP denemeleri başarısız, diğer hedefler çalışıyor → *Uzak servis hatası* (%70); hiçbir
  hedef çalışmıyor → *TCP bağlantı hatası*.
* TLS sertifika hatası → *Sertifika doğrulama hatası* (%85). Platform ağı doğrulamadıysa ek olarak
  *Captive portal* (%60) değerlendirilir.
* **h3 ilan edilmiş** ve QUIC VN yanıtı yoksa → *QUIC uyumsuzluğu* (%65). h3 ilan edilmemişse sessiz UDP
  hiçbir şey kanıtlamaz ve teşhis üretilmez.
* Yol MTU'su tavanın 8 bayttan fazla altında → *MTU kaynaklı sorun* (%55). TLS takılması da eşlik ediyorsa %70.
* Platform reddi (`PermissionDenied`, ör. Android 17 yerel ağ koruması) → yalnızca bilgilendirme; arıza
  iddiası yok.
* Kullanıcının tanımladığı alternatif DNS tüm sorguları belirgin biçimde daha hızlı yanıtladıysa,
  DNS ile ilgili teşhislerin güveni +10 artırılır ve bu gözlem gerekçeye eklenir.
* Hiçbir sorun yoksa ve kanıt varsa → *Sorun tespit edilmedi*; kanıt yoksa → *Yetersiz kanıt*.

**Puan:** S = (400·C + 250·L + 200·P + 100·T + 50·E) / 1000. Bileşenler 0–1000 aralığında tamsayıdır,
dolayısıyla tüm platformlarda aynı sonucu verir. C: başarı oranı, L: TCP medyan gecikmesi
(≤ 20 ms → 1000, ≥ 1000 ms → 0), P: çözümleyici teslim oranı, T: TLS 1.3 / h2 / QUIC v1 yeteneği,
E: çalışma süresi (radyonun açık kalma süresi için vekil ölçü).

**Karar (`decide::Decider`):**

1. EWMA (α = 1/4) ve son 8 puanın kararlılığı izlenir.
2. **Debounce:** Yüksek etkili eylemler (DNS değiştir, IPv4/IPv6 tercih et, MTU düşür, geri al) en az
   2 ardışık değerlendirmede ve güven ≥ %70 iken önerilir. Tek bir başarısız ölçüm hiçbir zaman sistem
   değişikliği önerisine yol açmaz. Düşük etkili eylemler güven ≥ %90 ise hemen önerilebilir.
3. **Histerezis:** Mevcut öneri yerine başka bir öneriye geçmek için orijinal sorun hâlâ görülüyorsa güven
   farkı en az `hysteresis_pct` (varsayılan 10) olmalıdır.
4. **Cooldown:** Değişiklikler arasında en az 60 sn beklenir. "Mevcut yapılandırmayı koru" önerisine
   dönüş bu süreyle engellenmez.
5. **Doğrulama ve geri alma:** Kullanıcı "uyguladım" dediğinde temel puan kaydedilir. İki değerlendirme
   sonra sorun kalkmışsa ve EWMA tolerans içinde kalmışsa *Doğrulandı*, aksi hâlde *Reddedildi* ve
   "Son değişikliği geri al" önerilir.
6. **Ağ değişimi:** Tüm durum sıfırlanır. Değişimden önce başlamış bir ölçümün sonucu yeni ağa
   uygulanmaz (`NO_DATA`).

## 10. Protokol araştırması

| Protokol | Belge (doğrulandı: rfc-editor.org) | Freedom Network'teki rolü |
|---|---|---|
| DNS | RFC 1035 (Kasım 1987, Internet Standard) | Mesaj kurucu/ayrıştırıcı; sıkıştırma işaretçileri yalnızca geriye ve atlama sayısı sınırlı |
| DNS büyük/küçük harf | RFC 4343 | Ad karşılaştırması ve etiket kaçışları |
| Sahte yanıt dayanıklılığı | RFC 5452 | Rastgele ID, bağlı UDP soketi, soru eşleştirmesi, eşleşmeyen yanıtları yok sayma |
| EDNS(0) | RFC 6891 (Internet Standard) | OPT kaydı, 1232 bayt |
| DNS/TCP | RFC 7766 | TC durumunda düşüş, çözümleyici yedeği |
| DoT / DoH / DoQ / OHTTP / ODoH | RFC 7858 / 8484 / 9250 / 9458 / 9230 | Happy Eyeballs paralel DoH3 (`TunBridge`), Platform DoH/DoH3 probu ve Rust `oblivious` kapsülleyicisi |
| SVCB/HTTPS RR | RFC 9460 (Kasım 2023) | `alpn` (h3 ilanı), `ech`, `port`, ipv4/ipv6 ipuçları; anahtarların artan sırada olması ve sıkıştırılmamış hedef adı denetleniyor |
| TLS 1.3 | **RFC 9846 (Temmuz 2026)**, RFC 8446'nın yerini alıyor | Platform TLS ile ölçülür; yalnızca TLSv1.3/1.2 sunulur |
| ECH | **RFC 9849 (Mart 2026)** | DNS'te ECH ilanı algılanır. ECH'yi uygulamak platform TLS'inin işidir (Android 17 destekliyor) + aktif SNI/ECH bölme |
| QUIC v1 / v2 | RFC 9000 (Mayıs 2021) / RFC 9369 | Version Negotiation probu: ayrılmış sürüm `0x1a2a3a4a` (§15, `0x?a?a?a?a`), 1200 baytlık doldurma (§14.1), CID yankı doğrulaması (§17.2.1) |
| HTTP/2 / HTTP/3 | RFC 9113 / RFC 9114 | h2: TLS ALPN; h3: HTTPS RR ilanı ile QUIC v1 VN yanıtının birleşimi |
| IPv6 | RFC 8200 | Genel adres: 2000::/3 |
| PMTUD | RFC 4821, RFC 8899 | DF bayraklı, boyut ikili aramalı ve yanıtla doğrulanan prob |

### Şifreli DNS (DoH3 / DoH) — 2026 modern yöntem

Araştırma (Kasım 2026): DoH3, DNS'i HTTP/3 üzerinden QUIC ile 443 numaralı portta taşır. DoQ ise
(RFC 9250) DNS'i doğrudan QUIC üzerinden, genellikle UDP 853'te taşır. Tarayıcılar ve uygulamalar
DoH3'ü tercih ediyor; büyük açık çözümleyiciler 2026'da DoH3 ve DoQ'yu yaygın şekilde sunuyor.
Windows 11 ve Android sistem düzeyinde şifreli DNS'i (DoH / Özel DNS-DoT) yerel olarak destekliyor.

Freedom Network tasarımı:

1. Sorgu, **Rust DNS kodlayıcısıyla** RFC 8484 biçiminde üretilir (ID 0, önbellek dostu) ve sıfır parmak izli (`DirectDohClient`) + paralel Happy Eyeballs yarışıyla 2 çözümleyiciye gönderilir.
2. Taşıma **platformun** HTTPS/HTTP3 yığınıyla yapılır; kendi kriptografimiz yok.
   * Android 14+: `android.net.http.HttpEngine` (QUIC açık, etkin ağa bağlı).
   * Android 11–13: `HttpsURLConnection`.
   * Windows: JDK `HttpClient` ve Windows sertifika deposu. Çalışan JDK HTTP/3 sunuyorsa (JEP 517)
     otomatik olarak kullanılır.
   Gerçekte anlaşılan protokol raporlanır; HTTP/2 kullanıldıysa DoH3 iddia edilmez.
   Yönlendirmeler izlenmez ve yalnızca `https://` adresleri kabul edilir.
3. Yanıt, Rust'ın sağlamlaştırılmış ayrıştırıcısıyla doğrulanır. `200 text/html` dönen bir giriş
   sayfası asla DNS yanıtı sayılmaz (test edildi).
4. Sınıflandırma:
   * Şifreli çözümleyici çalışıyor ve sistem DNS'i sorunluysa: teşhis güveni artar, öneri "şifreli DNS kullan".
   * Sistem NXDOMAIN diyor ama bağımsız şifreli çözümleyici adı çözüyorsa: "çözümleyici düzeyinde tutarsızlık".
   * İkisi de NXDOMAIN diyorsa: "hedef adını kontrol et".
   * Sistem DNS'i sağlıklı ama şifreli değilse: gizlilik önerisi.
   * Şifreli çözümleyiciye ulaşılamıyorsa: yalnızca bilgilendirme, arıza iddiası yok.
5. Sistemin şifreli DNS ayarı kullanıcı onayı olmadan sessizce değiştirilmez; cihaz içi TUN açıkken UDP 53 sorguları doğrudan şifreli DoH3/DoH üzerinden çözülür.

Kaynaklar: RFC 8484, RFC 9250, RFC 9114, RFC 9458 (OHTTP), RFC 9230 (ODoH); [dnsbenchmark.app — Quad9 DoQ/DoH3 2026](https://dnsbenchmark.app/blog/dns-over-quic-http3-quad9-2026/),
[tech-insider.org — DoH vs DoT vs DoQ 2026](https://tech-insider.org/doh-vs-dot-vs-doq-vs-dnscrypt-encrypted-dns-2026/),
[pbxscience.com — DoQ adoption](https://pbxscience.com/encrypted-dns-reaches-a-turning-point-as-doq-adoption-accelerates/)
(bunlar ikincil kaynaklardır; normatif tanım RFC'lerdedir).

## 11. Gizlilik ve güvenlik tehdit modeli

**Varlıklar:** kullanıcının ağ bilgileri (DNS, ağ geçidi, adresler), girilen hedef adları, cihaz bütünlüğü.

| Tehdit | Önlem |
|---|---|
| Veri sızıntısı / telemetri | Bulut bağlantısı, analitik ve telemetri yok. Tracker & Telemetri Kalkanı isteğe bağlı olarak reklam/izleyici alan adlarını yerel NXDOMAIN ile durdurur. Android'de otomatik veri yedekleme dışı bırakılmıştır |
| Açıklanmamış bağlantı | Tanılama yalnızca kullanıcının yazdığı hedeflere ve sistem DNS'ine kurulur; `VpnService` Google Play Belirgin Bildirimi ile açıklanır |
| Kötü amaçlı DNS yanıtı (parser saldırısı) | Sınır denetimli ayrıştırıcı, işaretçi döngüsü koruması, 20.000 yinelemeli fuzz testi; `unsafe` kullanılmıyor |
| Sahte DNS yanıtı | RFC 5452 kuralları; eşleşmeyen yanıt ve ISS zehirleme IP'leri yok sayılıyor (testle kanıtlandı) |
| WebRTC/STUN IP Sızıntısı & Düz DNS Düşüşü | `strictKillSwitch` şifreli DNS yanıt veremezse düz DNS'e düşüşü engeller; `hardenStunLeaks` UDP STUN IP keşif sızıntılarını yerel ICMP ile keser |
| Bozuk JNI girdisi | Boyut, derinlik ve alan sınırları; UTF-8 doğrulaması; geçersiz handle güvenli şekilde reddediliyor; panik sınırı geçmiyor |
| Use-after-free (handle) | Opak ve yeniden kullanılmayan ID'ler; çalışan bir çağrı `Arc` tuttuğu için eşzamanlı `destroy` güvenli (testle kanıtlandı) |
| Sertifika atlatma | Hiçbir yerde `TrustManager` veya `HostnameVerifier` gevşetilmiyor; hostname uyuşmazlığı ve güvenilmeyen sertifika testlerle "başarısız" olarak doğrulanıyor |
| DLL planting (Windows) | `java.library.path=$APPDIR`, `/DEPENDENTLOADFLAG:0x800`, Program Files'a kurulum ve imzalama |
| Tedarik zinciri | Sıfır crate, yalnızca Kotlin stdlib (+ JetBrains annotations), wrapper SHA-256 sabitli (`Gradle/`), `--locked` |
| Gizli bilgiler | Depoda gizli bilgi yok. Android imzalama anahtarı yalnızca ortam değişkenlerinden okunuyor. Testteki keystore her derlemede yeniden üretilen bir test fikstürüdür |
| Kötüye kullanım (tarama) | En fazla 8 hedef, 4 DNS sunucusu, bütçe ve oran sınırları; aralık tarama özelliği yok |

## 12. Performans stratejisi ve benchmark sonuçları

Ölçüm komutu: `cd Native && cargo test --release -- --ignored --nocapture --test-threads=1`
(ortam: 4 vCPU x86_64 bulut konteyneri, Rust 1.99.1). Sonuçlar ns/işlem:

| Yol | Release | Debug | Kat |
|---|---:|---:|---:|
| `dns::build_query` | 33 | 688 | 21× |
| `dns::parse_response` (HTTPS + A) | 218 | 2 575 | 12× |
| `quic::build_probe` (1200 B) | 40 | 5 568 | 139× |
| `quic::parse_version_negotiation` | 17 | 183 | 11× |
| `intel::classify` (8 hedef) | 1 147 | 5 577 | 5× |
| `engine::score` (8 hedef) | 111 | 884 | 8× |
| `decide::Decider::step` | 6 | 68 | 11× |
| `wire::encode` (8 hedefli rapor, 3,7 KB) | 1 087 | 30 097 | 28× |
| `wire::decode` (aynı rapor) | 6 199 | 34 126 | 6× |
| `create + destroy` | 116 | 307 | 3× |
| ASCII küçük harf, 253 B — **Assembly** (SSE2) | 43 | — | — |
| ASCII küçük harf, 253 B — `std` (autovektörize) | 39 | — | — |
| Tam tanılama + değerlendirme, 4 hedef, loopback (QUIC kapalı / açık) | 0,45 ms / 0,51 ms | — | — |

Stres testleri:

* 8 iş parçacığında 160.000 oluştur/kullan/yok et döngüsü 0,21 sn sürdü; kayıt defteri sonunda boş.
* 5000 tanılama/değerlendirme döngüsü 1,4 sn sürdü; RSS 3528 → 3544 KiB (+16 KiB, sınır 4 MiB).
* JVM: 5000 JNI oluştur/yok et döngüsü 9 ms sürdü.

Ölçümle yapılan iyileştirmeler:

1. **Test düzeneği hatası düzeltildi.** İlk ölçüm 962 ms/çalıştırma gösterdi. Sebep motor değil, kabul
   edilmeyen (`accept`) loopback bağlantılarının kernel kuyruğunu doldurmasıydı. Düzeltmeden sonra
   0,45 ms. Ders: ölçüm düzeneği de doğrulanmalı.
2. **QUIC denemeleri kanıt değerine bağlandı.** h3 ilan edilmemişse sessiz bir UDP uç noktası teşhisi
   değiştirmez; ikinci deneme kaldırıldı. UDP'nin sessizce düşürüldüğü ağlarda h3 ilan etmeyen hedef
   başına en kötü radyo süresi 2×T'den 1×T'ye indi (T = prob zaman aşımı, varsayılan 1,5 sn).

Reddedilen ve ertelenen optimizasyonlar:

* `wire::decode` 6 µs. Tanılama başına bir kez çalışıyor ve ağ süresinin yanında ihmal edilebilir;
  karmaşıklık eklenmedi.
* **Assembly ölçümü (dürüst sonuç):** 253 baytlık en kötü durumda el yazımı SSE2 rutini 43 ns,
  LLVM'in otomatik vektörize ettiği `std` rutini 39 ns. Gerçek DNS adları ~20 bayt olduğundan fark
  ihmal edilebilir. Assembly, projenin mimariye özgü SIMD bileşeni olarak doğrulanmış biçimde tutuluyor.

İkili boyutları (release, LTO=fat, `codegen-units=1`, strip):

| İkili | Yaklaşık Boyut |
|---|---:|
| `libfreedom.so` arm64-v8a (NDK 30) | ~480 KiB |
| `libfreedom.so` x86_64 | ~520 KiB |
| `freedom.dll` (MinGW / MSVC) | ~1 MiB |
| Release APK (R8) | ~620 KiB |

Ölçülemeyenler (ölçüm planı): Android pil tüketimi ve cihazda başlangıç süresi (Battery Historian /
`adb shell am start -W`), Windows'ta UI yanıt süresi.

## 13. Bağımlılık denetimi

| Tür | Bağımlılık | Gerekçe |
|---|---|---|
| Rust çalışma zamanı | **Yok** (yalnızca `std`) | `Native/Cargo.lock` tek paket (`freedom`) içeriyor |
| Kotlin çalışma zamanı | `org.jetbrains.kotlin:kotlin-stdlib:2.5.0-RC` → `org.jetbrains:annotations:13.0` | Kotlin dilinin çalışma zamanı (spesifikasyonda izin verilen istisna). Android'de R8 ile küçültülüyor |
| Üçüncü taraf Java/Kotlin kütüphanesi | **Yok** (JUnit dahil; testler kendi koşucunu kullanıyor) | Politika |
| Derleme zamanı | Gradle 9.9.1, AGP 9.5.1, KGP 2.5.0-RC, Android SDK 37.0 / NDK 30.0.16248370, JDK 21 (keytool, jpackage), Cargo, LLVM integrated assembler (rustc içinde) | Resmî araçlar |
| Platform API'leri | Windows: `java.net.http` (JDK), iphlpapi tablo API'leri, kernel32 işlem adı. Android: `android.net.http.HttpEngine`, `VpnService`, `WindowInsets`, `OnBackInvokedCallback`. Test: `jdk.httpserver` | Kütüphane değil, işletim sistemi/JDK parçası |
| İşletim sistemi | Android: libc, libdl, platform TLS. Windows: iphlpapi, ws2_32, advapi32, kernel32 | Sistem API'leri |

## 14. Dosya yapısı ve bilinçli sapmalar

```
Freedom Network/
├── .github/
│   ├── workflows/build.yml
│   └── Scrpits/Drive_Backup.gs
├── Gradle/{gradle-wrapper.jar, gradle-wrapper.properties}
├── Android/
│   ├── build.gradle.kts
│   ├── proguard-rules.pro
│   └── Source/Main/
│       ├── AndroidManifest.xml
│       ├── Kotlin/Core.kt
│       └── Resources/{mipmap-anydpi/, mipmap-mdpi..xxxhdpi/, values/colors.xml, xml/}
├── Windows/
│   ├── build.gradle.kts
│   └── Source/{Main/Kotlin/Core.kt, Main/Resources/{icon.ico, icon-*.png}, Test/Kotlin/Tests.kt}
├── Native/{Cargo.toml, Cargo.lock, rust-toolchain.toml, Core.rs, Arm64.s, x86_64.s, Tests.rs}
├── settings.gradle.kts · build.gradle.kts · gradle.properties · gradlew · gradlew.bat · .gitignore
└── Engineering.md
```

| Sapma | Gerekçe |
|---|---|
| `src/main` → `Source/Main`, `kotlin/` → `Kotlin/` | Kullanıcının talebi; Gradle'da kaynak dizinleri açıkça tanımlandı |
| `Gradle/` doğrudan sarıcı dosyalarını içerir | `gradle/wrapper/` yerine kök altında `Gradle/gradle-wrapper.jar` ve `Gradle/gradle-wrapper.properties` |
| `.github/Scrpits/Drive_Backup.gs` | Kullanıcı tanımlı dizin/dosya adlandırması; Google Drive yedekleme betiği |
| Ortak bölüm her iki `Core.kt` içinde | JNI/codec/model/TLS/DoH/`IpPackets`/`TunBridge`/metin bölümü iki dosyada `SHARED SECTION` ile bayt-birebir aynı tutulur |
| `Windows/Source/Test/Kotlin/Tests.kt` | JUnit yerine bağımlılıksız özel test koşucusu |
| `Native/Tests.rs` | Testleri üretim kodundan ayırır; `#[cfg(test)] #[path]` ile tek crate korunur |
| `Native/Arm64.s` & `Native/x86_64.s` | Entegre assembler (`global_asm!`) ile ARM64 NEON ve x86_64 SSE2 SIMD hızlandırması |
| Kökte Cargo.toml yok | Tek crate; workspace gerekmiyor |

## 15. Aşama raporları 0.0 → 1.0

| Aşama | Teslimat | Kabul kanıtı | Durum |
|---|---|---|---|
| 0.0 Araştırma | Bölüm 2–5 ve 10, doğrulanmış uyumluluk matrisi | Resmî kaynaklar ve gerçek derleme | ✅ |
| 0.1 Rust çekirdeği | Yaşam döngüsü, wire, kayıt defteri, hata kodları, JNI | API testleri ve JVM `-Xcheck:jni` | ✅ |
| 0.2 Ağ tanılama | DNS/TCP/UDP/PMTU probları, çözümleyici istatistikleri | Loopback sahte sunucularla uçtan uca testler | ✅ |
| 0.3 Protokol zekâsı | HTTPS RR (ALPN/ECH), QUIC VN, platform TLS | Ayrıştırıcı, fuzz ve TLS 1.3/ALPN testleri | ✅ |
| 0.4 Adaptif motor | Sınıflandırma, puan, debounce, histerezis, cooldown, doğrulama ve geri alma | Karar ve sınıflandırma testleri | ✅ |
| 0.5 Android | API 30–37 arm64 uygulaması, `FreedomVpnService`, DoH3, Edge-to-Edge UI | Debug/release APK, R8, lint 0 bulgu | ✅ |
| 0.6 Windows | Swing arayüzü, CLI, IP Helper, sistem geneli bağlantılar, DoH, Windows-ROOT, jpackage | JVM testleri, GitHub CI Windows x64 | ✅ |
| 0.7 Gizlilik/Güvenlik | Tehdit modeli, OHTTP/ODoH kapsülleyici, Kill Switch, Tracker Guard, STUN Kalkanı | Testler ve inceleme | ✅ |
| 0.8 Optimizasyon | Benchmark'lar, `IPTOS_LOWDELAY`, 64 KiB tampon, Happy Eyeballs DNS yarışı | Bölüm 12 & 22 | ✅ |
| 0.9 Stres/Uyumluluk | Uzun süreli, eşzamanlı ve tekrarlı başlat/kapat testleri | Bölüm 12 ve 16 | ✅ |
| 1.0 Yayın | Sürüm 1.0.0 (`com.freedom.network`) | Otomatik CI kapısı | ✅ |

## 16. Test ve yayın kabul kriterleri + test raporu

**Otomatik kapı:** `./gradlew check :Android:assembleRelease`

| Paket | Sonuç |
|---|---|
| Rust birim ve entegrasyon testleri (`cargo test --release --locked`) | **93/93** ✅ (+4 benchmark/stres testi, `--ignored`) |
| clippy `-D warnings` & `rustfmt --check` | 0 uyarı ✅ |
| JVM/JNI (`-Xcheck:jni`, `Windows/Source/Test/Kotlin/Tests.kt`): wire codec, JNI, TLS, DoH, sistem geneli, stres, aktif desync (`REALITY + X25519MLKEM768 + xtls-rprx-vision`), `ServerManager`, `TunBridge` (Happy Eyeballs DoH3, Tracker NXDOMAIN, STUN leak guard, UDP NAT, TCP Desync, Roaming) | **25/25** ✅ |
| Android lint (uyarılar hata sayılıyor) | 0 bulgu ✅ |

**Yayın kabul kriterleri:**

1. Otomatik GitHub Actions CI kapısı tamamen yeşil olmalı (`Build` + `Drive Yedekle`). ✅
2. Release APK imzası (`FREEDOM_KEYSTORE*` / `THEDPI_KEYSTORE*` ortam değişkenleri) ve Windows Authenticode imzası kullanıcı ortamında sağlanır.

### 17. Teknik riskler ve sabit kısıtlarla yapılamayanlar

| Özellik | Durum | Neden / alternatif |
|---|---|---|
| Sistem geneli görünüm (Windows) | **Yapıldı (kullanıcı modu)** | Tüm bağlantılar sahip işlemiyle birlikte görülüyor, sürücü gerekmiyor. Paket seviyesi WFP katmanı için bölüm 19 |
| Android VPN / TUN modu | **Yapıldı (`FreedomVpnService` + `TunBridge`)** | Uzak VPN sunucusu olmadan cihaz içi `0.0.0.0/0` + `::/0` TUN yakalama, `VpnService.protect()` korumalı soketlerle Happy Eyeballs DoH3 + Kill Switch + Tracker Kalkanı + Evrensel TCP/TLS Desync + Düşük Gecikmeli UDP NAT köprüsü |
| Şifreli DNS | **Happy Eyeballs DoH3/DoH yapıldı** | Platform HTTPS/HTTP3 + `DirectDohClient` üzerinden 2 çözümleyici paralel yarışır, ISS zehirlemesi reddedilir ve isteğe bağlı `strictKillSwitch` düz DNS düşüşünü kapatır |
| QUIC/HTTP3 el sıkışması | Version Negotiation + Initial Scramble + opsiyonel QUIC fallback | `blockQuic` etkinken UDP 443 -> TLS/TCP parçalamaya yönlendirilir; geçit açıksa QUIC Initial paketlerine düşük TTL şaşırtma uygulanır |
| ECH kullanımı | İlan algılama + ECH (`0xfe0d`) segment bölme | Platform TLS'in işi (Android 17 destekliyor) + `desync` motorunda ECH uzantısı ortasından TCP bölme |
| Windows captive portal ve ölçülü bağlantı | "Bilinmiyor" | `INetworkListManager` COM gerektirir; harici crate olmadan Rust'ta COM yazmak büyük bir unsafe yüzey getirir |
| Ağ yöneticisi politikası veya erişim kısıtlarını aşma | **Kullanıcı onaylı yerel DPI aşma + Kişisel Sunucu Rölesi (`PersonalRelayServer`)** | Üçüncü taraf merkezi tünel kullanılmaz; kullanıcı kendi cihazında veya kendi sunucusunda çalıştırır |
| x86_64 Android ve ChromeOS | Kapsam dışı | Talep ölçülürse eklenebilir |
| ICMP tabanlı kayıp ölçümü | Yapılmadı | Ham soket ayrıcalık ister. Kayıp DNS/UDP örneklerinden ölçülüyor |

**Riskler:**

1. Bazı QUIC sunucuları VN'ye oran sınırı uygular. MTU tahmini bu nedenle düşük çıkabilir; MTU teşhisinin
   güveni bu yüzden %55'te tutuldu.
2. NAT/CGNAT arkasında ICMP oran sınırları "Refused" ve "Timeout" ayrımını etkileyebilir.
3. Android OEM farklılıkları (DNS ve MTU raporlama). Cihaz matrisi testi şart.
4. Windows `GetAdaptersAddresses` yapı düzeni yalnızca x64 için doğrulandı (32-bit kapsam dışı).

## 18. Derleme ve test talimatları

Önkoşullar: JDK 21, Rust (`rust-toolchain.toml` 1.99.1'i otomatik kurar), Android SDK (platform
`android-37.0`, NDK 30.0.16248370) ve `local.properties` içinde `sdk.dir=...`
veya `ANDROID_HOME`. Windows paketleme için Visual Studio Build Tools (MSVC) ve WiX gerekmez (app-image).

```bash
./gradlew check                         # Rust test+clippy+fmt, JVM/JNI testleri, Android lint
./gradlew :Android:assembleRelease      # R8, arm64-v8a, 16 KB hizalı libfreedom.so (imza: FREEDOM_KEYSTORE* env)
./gradlew :Windows:run                  # Geliştirme: Swing arayüzü
./gradlew :Windows:packageWindows       # Windows'ta: MSVC freedom.dll + jpackage app-image (sonra signtool)
FreedomNetwork --cli example.com --dns 1.1.1.1 --doh https://dns.example/dns-query --system  # Komut satırı modu

cd Native
cargo test --release -- --ignored --nocapture --test-threads=1   # benchmark ve stres testleri
```

## 19. Windows paket seviyesi katman (WFP) — sürücü yolu

**Dil engel değil.** Bir Windows çekirdek sürücüsü Rust ile yazılabilir; Microsoft'un kendi
`windows-drivers-rs` çalışması bunu gösteriyor. Teorik olarak Assembly ile de yazılabilir. Yani C++
zorunlu değil. Gerçek engeller şunlar:

1. **İmza.** 64-bit Windows yalnızca Microsoft imzalı çekirdek sürücülerini yükler: EV kod imzalama
   sertifikası ve Microsoft Partner Center üzerinden attestation imzası gerekir. Test için "test
   signing" modu yalnızca geliştirici makinesinde kullanılabilir.
2. **Araç zinciri.** WDK (Windows Driver Kit) ve bir Windows derleme makinesi gerekir. Bu Linux ortamında
   çekirdek sürücüsü derlenemez ve test edilemez.
3. **Bağımlılık politikası.** `windows-drivers-rs` üçüncü taraf crate'tir. Sıfır-crate politikasıyla
   WDK başlıklarını Rust'a elle bağlamak (`#![no_std]`, ham FFI) gerekir.
4. **Risk.** Çekirdek kodundaki bir hata sistemi çökertir (BSOD). Ayrı test matrisi ve Driver Verifier
   gerekir.

**Önerilen yol:**

* Kullanıcı modu WFP (`fwpuclnt.dll`, sürücü gerektirmez) ile önce uygulama/port bazlı **izleme ve
  filtreleme kuralları** (güvenlik duvarı benzeri, kullanıcı onaylı).
* Ardından, imza altyapısı hazırsa, Rust `no_std` WFP callout sürücüsü ile paket seviyesi **görünürlük**.

Sınır: Freedom Network kendi cihazının trafiğini görür ve kullanıcının onayıyla filtreler. Şifreli trafiği
çözmez (TLS kırma / MITM yok), başka cihazların trafiğine dokunmaz ve güvenlik politikalarını aldatarak
aşmaz.

---

## 20. Aktif DPI Aşma (`desync`), Yerel Tünel ve SIMD Assembly Mimarisi

Freedom Network, sıfır üçüncü taraf bağımlılık (`std`-only Rust + saf SIMD Assembly) ve gizlilik ilkelerini koruyarak pasif tanılama motorunun yanına **tamamen yerel (on-device) çalışan evrensel aktif DPI aşma (desynchronization) veri düzlemi (`pub mod desync`)** ekler.

### 20.1 SIMD Assembly Çekirdeği (`Native/x86_64.s` & `Native/Arm64.s`)

Sıcak yolda (hot-path) paket başına gecikmeyi nanosaniye seviyesinde tutmak için hem x86_64 (SSE2, `extern "sysv64"`) hem de ARM64 (NEON, `extern "C"`) Assembly dosyalarına dört donanım hızlandırmalı rutin eklendi:

| Sembol | Mimari / Komutlar | Görev | Ölçülen Performans (x86_64) |
|---|---|---|---|
| `freedom_csum_fold` | x86_64 SSE2 (`psrlw`, `psllw`, `punpcklwd`, `paddd`) · ARM64 NEON (`rev16`, `uadalp`, `uaddlv`) | RFC 1071 16-bit tümleyen (one's complement) büyük-sonlu (big-endian) sağlama toplamı katlayıcısı | **72,2 ns** / 1500 B paket (~20,7 GB/sn) |
| `freedom_csum_delta` | x86_64 / ARM64 dallanmasız yazmaç aritmetiği (`not`/`mvn`, `add`, `shr`/`lsr`) | RFC 1624 artımlı sağlama toplamı güncellemesi (`HC' = ~(~HC + ~m + m')`); TTL, Sequence Number ve `BadSum` mutasyonu | **4,3 ns** / işlem |
| `freedom_scan_pattern` | x86_64 SSE2 (`pshufd`, `pcmpeqb`, `pmovmskb`, `bsf`) · ARM64 NEON (`dup`, `cmeq`, `umaxv`) | 1500 B yük içinde TLS `ClientHello` SNI (`0x0000`), ECH (`0xfe0d`) ve HTTP `Host:` başlıklarını vektörize tarama | **12,8 ns** / 1500 B paket |
| `freedom_ascii_lowercase` | x86_64 SSE2 (`pcmpgtb`) · ARM64 NEON (`cmhs`) | DNS ve SNI/Host alan adı normalizasyonu (UTF-8 güvenli) | **43,0 ns** / 253 B |

### 20.2 Aktif DPI Aşma (Desync) Modları (`desync::DesyncMode`)

1. **`Split (1)`:** TLS 1.2/1.3 `ClientHello` paketlerini tam SNI (`0x0000`) ve ECH (`0xfe0d`, RFC 9849) uzantılarının ortasından, HTTP isteklerini ise `Host:` değerinin ortasından geçerli TCP segmentlerine böler.
2. **`Disorder (2)`:** Bölünen TCP segmentlerini **ters Sequence Number sırasıyla (Out-of-Order, RFC 9293)** gönderir.
3. **`FakeBadSum (3)`:** Gerçek segmentlerden önce aynı Sequence numarasına sahip, içinde zararsız `www.iana.org` SNI/Host değeri taşıyan ve TCP sağlama toplamı `freedom_csum_delta` ile kasıtlı olarak bozulmuş (`0xdead`) sahte (decoy) bir TCP segmenti enjekte eder.
4. **`FakeAutoTtl (4)`:** Sahte `www.iana.org` paketini geçerli TCP sağlama toplamı fakat düşürülmüş IPv4 `TTL` / IPv6 `Hop Limit` (varsayılan 5, `2..=16`) ile gönderir.
5. **`QuicScramble (5)`:** UDP 443 üzerindeki QUIC v1 (RFC 9000) ve QUIC v2 (RFC 9369) `Initial` paketlerinden önce düşük TTL'li ayrılmış sürüm (`0x1a2a3a4a`) datagramı gönderir.
6. **`AdaptiveFull (6)`:** Hibrit Post-Kuantum TLS 1.3 (`X25519MLKEM768`, `0x11ec`) ve ECH (`0xfe0d`) çoklu bölme + `FakeAutoTtl` + `FakeBadSum` + `Disorder` + `QuicScramble` + gelen pasif DPI sahte `TCP RST` ve `HTTP 302/403` paketlerini düşüren (`should_drop_inbound`) tam koruma kalkanı.
7. **`RealityVision (7)` (Varsayılan 2026–2027 Modu):** Project X / Xray-core `REALITY` + `X25519MLKEM768` (`0x11ec`) post-kuantum el sıkışması + aktif yoklama savunması + `xtls-rprx-vision` doğrudan TLS akış birleştirme (splice).

### 20.3 Platform Entegrasyonu (Windows & Android)

* **Yerel SOCKS5 + HTTP CONNECT Desync Proxy (`desync::LocalProxy`):** `127.0.0.1` üzerinde çalışır; `TCP_NODELAY` ve `sys::set_tcp_ttl` ile soket düzeyinde düşük TTL'li sahte paket, SNI/ECH bölme ve `xtls-rprx-vision` splice uygular.
* **Android 11–17 Sistem Geneli `FreedomVpnService` + `TunBridge` (`IpPackets` & `TunBridge`):**
  * `addRoute("0.0.0.0", 0)`, `addRoute("::", 0)` ve `addDnsServer("10.215.173.2")` ile tüm cihaz trafiğini yerel `TUN` arayüzüne yönlendirir (`addDisallowedApplication(packageName)` ve `VpnService.protect()` ile kendi dış soketlerini döngüden korur).
  * **Şifreli DNS (Happy Eyeballs DoH3/DoH) Köprüsü:** Cihazdaki tüm uygulamaların UDP 53 DNS sorgularını yakalar ve en hızlı 2 `DirectDohClient` ucunu paralel yarıştırarak (`preferredDoh`) çözer.
  * **Kullanıcı Modu TCP + `REALITY` / `xtls-rprx-vision` Desync:** Tüm TCP/TLS akışlarında ilk `ClientHello` / HTTP yükünü `Native.desyncPacket` ile SNI/ECH/`X25519MLKEM768` ortasından bölerek (`TCP_NODELAY` + `IPTOS_LOWDELAY` + `flush`) iletir; el sıkışma bitince `xtls-rprx-vision` ile doğrudan akışa geçer.
  * **Evrensel UDP NAT Köprüsü:** Tüm gerçek zamanlı ses/video/oyun/QUIC UDP datagramlarını `VpnService.protect()` ile korunmuş soketler ve `IPTOS_LOWDELAY` ile düşük gecikmeli aktarır.
* **Windows CLI ve Swing Arayüzü:** Komut satırında `FreedomNetwork --cli example.com --desync reality --proxy 8880` desteği.

---

## 21. Hibrit Ağ Özgürlüğü Mimarisi ("Senin Ağın. Senin Sunucun. Senin Kontrolün.")

* **`REALITY` + `X25519MLKEM768` (`0x11ec`) + `xtls-rprx-vision`:** `desync::build_reality_mlkem768_client_hello` ve `relay::PersonalRelayServer` ile aktif yoklamaya dayanıklı el sıkışma.
* **Kişisel Sunucu Rölesi (`pub mod relay`) ve `ServerManager`:** Cihaz yetkilendirme (`authorize_device`), anında iptal (`revoke_device`), anahtar yenileme (`rotate_device_key`), kota (`quota_bytes`), otomatik yedek sunucu geçişi (Failover) ve RFC 9298 / RFC 9484 MASQUE tünel kapsülleri.
* **Windows Wintun (`sys::wintun`):** `Freedom Network` (`10.215.173.1/24`, `fd00:6672:6565:646f::1/64`, MTU `1420`) kullanıcı alanı L3 doğrulayıcısı.
* **Kısıtlanmış Ağlar İçin Evrensel Protokol Dayanıklılığı:**
  * **TLS Kayıt Katmanı Çoklu Parçalama (`desync::fragment_tls_client_hello_records`):** Stateful TCP birleştiren DPI kutularına karşı tek `ClientHello`'yu SNI/ECH sınırlarından ≥3 valid TLS `0x16` kaydına böler.
  * **Evrensel Gerçek Zamanlı UDP Koruması:** `PROTO_UDP_STUN_MEDIA (4)` (74/70 B STUN/medya IP keşif paketleri) ve `PROTO_UDP_REALTIME (5)` (`0x05` çerçeveli gerçek zamanlı UDP el sıkışmaları) `desync::inspect_l7` ile tanınır ve düşük TTL şaşırtmasıyla korunur.
  * **Wi-Fi ↔ Mobil Veri (LTE/5G) Roaming (`TunBridge.rebindActiveSessions`):** Ağ geçişinde aktif soketler TUN'u düşürmeden yeniden korunur.

---

## 22. Freedom Network (2026–2027) Evrensel Kısıt Kaldırma, Gizlilik Kalkanı ve Arayüz Yenilemesi

1. **Uygulama Bazlı Kodlamaların Kaldırılması ve Evrensel Ağ Politikası:**
   * Tüm uygulama özel etiketleri ve sabit test alan adları kaldırıldı; anti-DPI parçalama, şifreli DNS ve düşük gecikmeli UDP NAT cihazdaki **tüm ağ trafiğine** varsayılan olarak uygulanır.
2. **Oblivious Privacy, Parmak İzi Temizliği ve Sızıntı Kalkanları:**
   * **Rust `pub mod oblivious`:** RFC 9458 (OHTTP İkili HTTP `message/bhttp`), RFC 9230 (ODoH DNS zarflama), rastgele uzunluk doldurma (`pad_to_block`, trafik analizi önleme) ve tanımlayıcı HTTP başlık temizleyicisi (`strip_identifying_headers`).
   * **`Strict Kill Switch` (`strictKillSwitch`):** Şifreli DoH3/DoH yanıt veremediğinde düz UDP 53 DNS'e düşüşü ve olası ISP DNS sızıntısını keser.
   * **`Tracker & Telemetri Kalkanı` (`blockTrackers`):** İsteğe bağlı olarak bilinen reklam/telemetri alan adlarına ağa çıkmadan yerel `NXDOMAIN` (RCODE 3) yanıtı döndürür (`IpPackets.buildDnsNxdomain`).
   * **`WebRTC / STUN IP Sızıntı Kalkanı` (`hardenStunLeaks`):** Tarayıcı/uygulama STUN `Binding Request` IP keşif sızıntılarını ICMP ile durdurarak kullanıcının gerçek çıkış IP adresinin açığa çıkmasını engeller (`leaksBlocked`).
3. **Yüksek Hızlı İletim ve Happy Eyeballs DNS Yarışı:**
   * `TunBridge` en iyi 2 DoH ucunu paralel yarıştırır ve en düşük gecikmeli çözümü `preferredDoh` olarak öne alır.
   * Tüm korunan soketlerde `TCP_NODELAY`, `trafficClass = 0x10` (`IPTOS_LOWDELAY`) ve `64 KiB` tamponlar kullanılır.
4. **Modern İkonografi ve Android 11–17 UI Uyumluluğu:**
   * Koyu lacivert/gece arka plan üzerinde elektrik camgöbeği → zümrüt geometrik **Freedom Shield** başlatıcı ikonları (`Android/Source/Main/Resources/mipmap-*` ve `Windows/Source/Main/Resources/icon*.png`, `icon.ico`).
   * `ModernPowerShieldView` & `ModernPowerShieldPanel`: Önbellekli `RadialGradient`/`LinearGradient`/`SweepGradient` gölgelendiricileri, zıt yönlü hassas yörüngeler, 12 azimut kadran çizgisi ve yumuşatılmış hap durum göstergesi.
   * **Android 11–17 tam uyum:** `setDecorFitsSystemWindows(false)` + şeffaf sistem çubukları, koyu sistem ikon kontrastı, dış dolguyu koruyan `WindowInsets` dinleyicisi ve API 33–37 `OnBackInvokedCallback` öngörülü geri hareketi.
   * **Google Play `VpnService` uyumu:** `FreedomVpnService` için yerel cihaz içi çalışma beyanı ve belirgin kullanıcı onay penceresi (`AlertDialog`).

