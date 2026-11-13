// Freedom Network — Otomatik Google Drive Yedekleyici (Google Apps Script).
//
// Kullanım (script.google.com):
//   1. Bu dosyanın tamamını Apps Script projenize ("FN Yedek") yapıştırıp Kaydet'e basın.
//   2. Proje Ayarları -> Komut Dosyası Özellikleri içinde GH_TOKEN (repo izinli GitHub PAT)
//      ve HOOK_KEY gizli anahtarlarının tanımlı olduğundan emin olun.
//   3. Dağıt -> Dağıtımları Yönet -> Kalem (Düzenle) -> Sürüm: Yeni Sürüm -> Dağıt.
//
// Özellikler:
//   - Kaynak kodu (.zip) -> Drive "Proje_Yedek" klasörüne (hem Freedom_Network_Beta hem The_DPI_Beta)
//   - Derlenmiş kurulum dosyaları (Windows EXE ZIP + Android APK) -> Drive "Son_Surum" klasörüne
//   - Önce "latest-beta" GitHub Release varlıklarını, yoksa Actions Artifact API çıktılarını indirir
//   - Eski sürümleri çöp kutusuna taşır (30 gün kurtarılabilir); yalnızca en son sürümü tutar.

const DEFAULT_OWNER = 'eaquelxonline';
const DEFAULT_REPO = 'Freedom_Network';
const DEFAULT_BRANCH = 'Freedom_Network_Beta';
const TRACKED_BRANCHES = ['Freedom_Network_Beta', 'The_DPI_Beta'];
const SOURCE_FOLDER = 'Proje_Yedek';
const RELEASE_FOLDER = 'Son_Surum';
const ROLLING_RELEASE_TAG = 'latest-beta';

function ozellik_(ad) {
  const deger = PropertiesService.getScriptProperties().getProperty(ad);
  if (!deger) throw new Error(ad + ' betik ozelligi tanimli degil');
  return deger;
}

function dogrula_(e) {
  const beklenen = ozellik_('HOOK_KEY');
  const gelen = (e && e.parameter && e.parameter.key) || '';
  if (gelen !== beklenen) {
    return ContentService.createTextOutput('YETKISIZ').setMimeType(ContentService.MimeType.TEXT);
  }
  return null;
}

function headerGet_(headers, name) {
  if (!headers) return '';
  const target = name.toLowerCase();
  const keys = Object.keys(headers);
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === target) return headers[keys[i]];
  }
  return '';
}

function apiJson_(url, token) {
  const yanit = UrlFetchApp.fetch(url, {
    headers: {
      'Authorization': 'Bearer ' + token,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'GAS-FreedomNetwork-Backup'
    },
    muteHttpExceptions: true
  });
  const kod = yanit.getResponseCode();
  if (kod !== 200) {
    throw new Error('GitHub API ' + kod + ' (' + url + '): ' + yanit.getContentText().substring(0, 200));
  }
  return JSON.parse(yanit.getContentText());
}

// Yönlendirmelerde (Azure Blob SAS / GitHub CDN) Authorization başlığını sızdırmadan indirir.
function fetchBytes_(url, token, acceptHeader) {
  let currentUrl = url;
  for (let hop = 0; hop < 7; hop++) {
    const isGitHubHost = /^https:\/\/(api\.github\.com|github\.com)\//i.test(currentUrl);
    const headers = { 'User-Agent': 'GAS-FreedomNetwork-Backup' };
    if (isGitHubHost && token) {
      headers['Authorization'] = 'Bearer ' + token;
    }
    if (acceptHeader && isGitHubHost) {
      headers['Accept'] = acceptHeader;
    }
    const resp = UrlFetchApp.fetch(currentUrl, {
      headers: headers,
      followRedirects: false,
      muteHttpExceptions: true
    });
    const code = resp.getResponseCode();
    if (code === 301 || code === 302 || code === 303 || code === 307 || code === 308) {
      const loc = headerGet_(resp.getAllHeaders(), 'location') || headerGet_(resp.getHeaders(), 'location');
      if (!loc) throw new Error('Yonlendirme Location basligi bos (' + code + ')');
      currentUrl = loc;
      continue;
    }
    if (code !== 200) {
      throw new Error('Indirme HTTP ' + code + ' (' + currentUrl.substring(0, 80) + ')');
    }
    return resp.getBlob();
  }
  throw new Error('Cok fazla HTTP yonlendirmesi: ' + url);
}

function klasorAl_(ad) {
  const klasorler = DriveApp.getFoldersByName(ad);
  if (klasorler.hasNext()) return klasorler.next();
  return DriveApp.createFolder(ad);
}

function repoParse_(paramRepo) {
  if (paramRepo && paramRepo.indexOf('/') > 0) {
    const parts = paramRepo.split('/');
    if (parts[0] && parts[1]) {
      const repoName = (parts[1] === 'The_DPI') ? DEFAULT_REPO : parts[1];
      return { owner: parts[0], repo: repoName };
    }
  }
  return { owner: DEFAULT_OWNER, repo: DEFAULT_REPO };
}

function resolveCommit_(owner, repo, branch, shaHint, token) {
  if (shaHint && /^[0-9a-f]{7,40}$/i.test(shaHint)) {
    return { sha: shaHint, shortSha: shaHint.substring(0, 7) };
  }
  const veri = apiJson_(`https://api.github.com/repos/${owner}/${repo}/commits/${encodeURIComponent(branch)}`, token);
  return { sha: veri.sha, shortSha: veri.sha.substring(0, 7) };
}

function dosyaVarMi_(klasor, adBaslangic) {
  const it = klasor.getFiles();
  while (it.hasNext()) {
    const f = it.next();
    if (f.getName().startsWith(adBaslangic)) return true;
  }
  return false;
}

function yedekleKaynak_(owner, repo, branch, shaHint) {
  const token = ozellik_('GH_TOKEN');
  const { sha, shortSha } = resolveCommit_(owner, repo, branch, shaHint, token);
  const klasor = klasorAl_(SOURCE_FOLDER);
  const prefix = `${repo}_${branch}_`;
  const legacyPrefix = `The_DPI_${branch}_`;

  if (dosyaVarMi_(klasor, prefix + shortSha) || dosyaVarMi_(klasor, legacyPrefix + shortSha)) {
    return `ZATEN_GUNCEL (${branch}@${shortSha})`;
  }

  const zipUrl = `https://api.github.com/repos/${owner}/${repo}/zipball/${sha}`;
  const blob = fetchBytes_(zipUrl, token, 'application/vnd.github+json');
  if (blob.getBytes().length < 1000) {
    throw new Error('Indirilen kaynak zip supheli sekilde kucuk (<1KB)');
  }

  const ts = Utilities.formatDate(new Date(), 'UTC', "yyyyMMdd'T'HHmmss'Z'");
  const dosyaAdi = `${prefix}${shortSha}_${ts}.zip`;
  blob.setName(dosyaAdi);
  blob.setContentType('application/zip');
  const yeni = klasor.createFile(blob);

  // Yalnizca bu projenin ve dalin eski yedeklerini cope tasi (30 gun kurtarilabilir)
  const it = klasor.getFiles();
  let silinen = 0;
  while (it.hasNext()) {
    const f = it.next();
    if (f.getId() === yeni.getId()) continue;
    const n = f.getName();
    if ((n.startsWith(prefix) || n.startsWith(legacyPrefix)) && n.endsWith('.zip')) {
      f.setTrashed(true);
      silinen++;
    }
  }
  return `OK Kaynak:${dosyaAdi} (${(blob.getBytes().length / (1024 * 1024)).toFixed(2)} MB, ${silinen} eski silindi)`;
}

function kayitEtIcerik_(klasor, blob, fileName) {
  const lower = fileName.toLowerCase();
  blob.setName(fileName);
  if (lower.endsWith('.apk')) {
    blob.setContentType('application/vnd.android.package-archive');
  } else if (lower.endsWith('.zip')) {
    blob.setContentType('application/zip');
  }
  return klasor.createFile(blob).getId();
}

function temizleEskiSurumler_(klasor, korunacakIdler) {
  const it = klasor.getFiles();
  let silinen = 0;
  while (it.hasNext()) {
    const f = it.next();
    if (korunacakIdler.indexOf(f.getId()) >= 0) continue;
    const n = f.getName();
    if (n.startsWith('FreedomNetwork-') && (n.endsWith('.zip') || n.endsWith('.apk'))) {
      f.setTrashed(true);
      silinen++;
    }
  }
  return silinen;
}

function surumAdiUret_(orijinalAd, shortSha) {
  const base = orijinalAd.split('/').pop();
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return `${base}_${shortSha}`;
  const stem = base.substring(0, dot);
  const ext = base.substring(dot);
  if (stem.endsWith('_' + shortSha)) return base;
  return `${stem}_${shortSha}${ext}`;
}

function yedekleReleaseVarliklari_(owner, repo, shortSha, klasor, token) {
  let rel;
  try {
    rel = apiJson_(`https://api.github.com/repos/${owner}/${repo}/releases/tags/${ROLLING_RELEASE_TAG}`, token);
  } catch (_) {
    return null;
  }
  const assets = rel.assets || [];
  if (!assets.length) return null;

  // Eğer belirli bir SHA istenmişse ve release başka bir SHA içinse artifact yedeğine düş
  const tagSha = (rel.target_commitish || '').substring(0, 7);
  const titleMatch = (rel.name || '').indexOf(shortSha) >= 0;
  if (shortSha && tagSha && tagSha !== shortSha && !titleMatch) {
    return null;
  }

  const effectiveSha = shortSha || tagSha || 'latest';
  if (dosyaVarMi_(klasor, `FreedomNetwork-Windows-x64_${effectiveSha}`)) {
    return { status: `ZATEN_GUNCEL (Son_Surum@${effectiveSha})` };
  }

  const savedIds = [];
  const savedNames = [];
  for (let i = 0; i < assets.length; i++) {
    const a = assets[i];
    const name = a.name || '';
    if (!/\.(zip|apk)$/i.test(name)) continue;
    const targetName = surumAdiUret_(name, effectiveSha);
    const blob = fetchBytes_(a.url, token, 'application/octet-stream');
    if (blob.getBytes().length < 10000) continue;
    savedIds.push(kayitEtIcerik_(klasor, blob, targetName));
    savedNames.push(targetName);
  }

  if (!savedIds.length) return null;
  const silinen = temizleEskiSurumler_(klasor, savedIds);
  return { status: `OK Son_Surum(Release): ${savedNames.join(', ')} (${silinen} eski silindi)` };
}

function yedekleRunArtifactlari_(owner, repo, runId, shortSha, klasor, token) {
  let resolvedRunId = runId;
  let resolvedShort = shortSha;
  if (!resolvedRunId) {
    const runsData = apiJson_(
      `https://api.github.com/repos/${owner}/${repo}/actions/workflows/build.yml/runs?status=completed&per_page=10`,
      token
    );
    const runs = runsData.workflow_runs || [];
    for (let i = 0; i < runs.length; i++) {
      if (runs[i].conclusion === 'success') {
        resolvedRunId = String(runs[i].id);
        resolvedShort = (runs[i].head_sha || '').substring(0, 7) || resolvedShort || 'latest';
        break;
      }
    }
  }
  if (!resolvedRunId) return 'ZATEN_GUNCEL (Henuz tamamlanmis Build yok)';

  const effectiveSha = resolvedShort || 'latest';
  if (dosyaVarMi_(klasor, `FreedomNetwork-Windows-x64_${effectiveSha}`)) {
    return `ZATEN_GUNCEL (Son_Surum@${effectiveSha})`;
  }

  const artData = apiJson_(`https://api.github.com/repos/${owner}/${repo}/actions/runs/${resolvedRunId}/artifacts`, token);
  const arts = artData.artifacts || [];
  const savedIds = [];
  const savedNames = [];

  for (let i = 0; i < arts.length; i++) {
    const art = arts[i];
    if (art.expired) continue;
    if (art.name !== 'FreedomNetwork-Windows-x64' && art.name !== 'FreedomNetwork-Android') continue;
    const zipBlob = fetchBytes_(art.archive_download_url, token, 'application/vnd.github+json');

    if (art.name === 'FreedomNetwork-Android') {
      const entries = Utilities.unzip(zipBlob);
      for (let j = 0; j < entries.length; j++) {
        const entry = entries[j];
        const base = entry.getName().split('/').pop();
        if (!base.toLowerCase().endsWith('.apk')) continue;
        const outName = base.startsWith('FreedomNetwork-') ? surumAdiUret_(base, effectiveSha) : surumAdiUret_(`FreedomNetwork-${base}`, effectiveSha);
        savedIds.push(kayitEtIcerik_(klasor, entry, outName));
        savedNames.push(outName);
      }
    } else if (art.name === 'FreedomNetwork-Windows-x64') {
      let extracted = false;
      try {
        const entries = Utilities.unzip(zipBlob);
        for (let j = 0; j < entries.length; j++) {
          const entry = entries[j];
          const base = entry.getName().split('/').pop();
          if (!base.toLowerCase().endsWith('.zip')) continue;
          const outName = surumAdiUret_(base, effectiveSha);
          savedIds.push(kayitEtIcerik_(klasor, entry, outName));
          savedNames.push(outName);
          extracted = true;
        }
      } catch (_) {
        // Büyük zip bellek sınırına çarparsa dış arşivi doğrudan sakla
      }
      if (!extracted) {
        const outName = `FreedomNetwork-Windows-x64_${effectiveSha}.zip`;
        savedIds.push(kayitEtIcerik_(klasor, zipBlob, outName));
        savedNames.push(outName);
      }
    }
  }

  if (!savedIds.length) {
    throw new Error('Build #' + resolvedRunId + ' icinde yuklenecek artifact bulunamadi');
  }
  const silinen = temizleEskiSurumler_(klasor, savedIds);
  return `OK Son_Surum(Artifact): ${savedNames.join(', ')} (${silinen} eski silindi)`;
}

function yedekleSurumler_(owner, repo, branch, shaHint, runId) {
  const token = ozellik_('GH_TOKEN');
  const { shortSha } = shaHint || !runId
    ? resolveCommit_(owner, repo, branch, shaHint, token)
    : { shortSha: '' };
  const klasor = klasorAl_(RELEASE_FOLDER);

  const relRes = yedekleReleaseVarliklari_(owner, repo, shortSha, klasor, token);
  if (relRes) return relRes.status;

  return yedekleRunArtifactlari_(owner, repo, runId, shortSha, klasor, token);
}

// GitHub Actions tetiklemesi için Web App giriş noktası
function doGet(e) {
  const yetkiHatasi = dogrula_(e);
  if (yetkiHatasi) return yetkiHatasi;

  try {
    const p = (e && e.parameter) || {};
    const { owner, repo } = repoParse_(p.repo || '');
    const branch = p.branch || DEFAULT_BRANCH;
    const sha = p.sha || '';
    const runId = p.run_id || '';
    const mode = (p.mode || 'all').toLowerCase();

    const ozet = [];
    if (mode === 'source' || mode === 'all') {
      ozet.push(yedekleKaynak_(owner, repo, branch, sha));
    }
    if (mode === 'binaries' || mode === 'release' || mode === 'all') {
      ozet.push(yedekleSurumler_(owner, repo, branch, sha, runId));
    }

    const metin = ozet.join(' | ');
    const tumuZaten = ozet.length > 0 && ozet.every(s => s.startsWith('ZATEN_GUNCEL'));
    const sonuc = tumuZaten ? metin : (metin.startsWith('OK') ? metin : 'OK ' + metin);
    return ContentService.createTextOutput(sonuc).setMimeType(ContentService.MimeType.TEXT);
  } catch (err) {
    return ContentService.createTextOutput('HATA: ' + err.message).setMimeType(ContentService.MimeType.TEXT);
  }
}

function doPost(e) {
  return doGet(e);
}

// Saatlik tetikleyici: tüm izlenen dalların kaynaklarını ve en güncel Build ikili dosyalarını eşitler.
function saatlikKontrol() {
  const rapor = [];
  for (let i = 0; i < TRACKED_BRANCHES.length; i++) {
    try {
      rapor.push(yedekleKaynak_(DEFAULT_OWNER, DEFAULT_REPO, TRACKED_BRANCHES[i], ''));
    } catch (err) {
      rapor.push('HATA(' + TRACKED_BRANCHES[i] + '): ' + err.message);
    }
  }
  try {
    rapor.push(yedekleSurumler_(DEFAULT_OWNER, DEFAULT_REPO, DEFAULT_BRANCH, '', ''));
  } catch (err) {
    rapor.push('HATA(Son_Surum): ' + err.message);
  }
  Logger.log(rapor.join(' | '));
}
