// Google Drive yedeği (Google Apps Script, kullanıcının kendi Drive hesabında çalışır).
const OWNER = 'eaquelxonline';
const REPO = 'The_DPI';
const BRANCH = 'The_DPI_Beta';
const FOLDER = 'Proje_Yedek';
const PREFIX = REPO + '_' + BRANCH + '_';

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

function sonCommit_() {
  const token = ozellik_('GH_TOKEN');
  const url = `https://api.github.com/repos/${OWNER}/${REPO}/commits/${BRANCH}`;
  const yanit = UrlFetchApp.fetch(url, {
    headers: {
      'Authorization': 'Bearer ' + token,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'GAS-Drive-Backup'
    },
    muteHttpExceptions: true
  });
  if (yanit.getResponseCode() !== 200) {
    throw new Error('Commit alinamadi: ' + yanit.getResponseCode() + ' ' + yanit.getContentText());
  }
  const veri = JSON.parse(yanit.getContentText());
  return { sha: veri.sha, kisaSha: veri.sha.substring(0, 7) };
}

function yedekKlasoru_() {
  const klasorler = DriveApp.getFoldersByName(FOLDER);
  if (klasorler.hasNext()) return klasorler.next();
  return DriveApp.createFolder(FOLDER);
}

function yedekle() {
  const { sha, kisaSha } = sonCommit_();
  const klasor = yedekKlasoru_();

  // Bu commit zaten yedeklenmiş mi?
  const mevcutlar = klasor.getFiles();
  while (mevcutlar.hasNext()) {
    const dosya = mevcutlar.next();
    if (dosya.getName().startsWith(PREFIX + kisaSha)) {
      return `ZATEN_GUNCEL (${kisaSha})`;
    }
  }

  // zipball indir
  const token = ozellik_('GH_TOKEN');
  const zipUrl = `https://api.github.com/repos/${OWNER}/${REPO}/zipball/${sha}`;
  const zipYanit = UrlFetchApp.fetch(zipUrl, {
    headers: {
      'Authorization': 'Bearer ' + token,
      'User-Agent': 'GAS-Drive-Backup'
    },
    muteHttpExceptions: true
  });
  if (zipYanit.getResponseCode() !== 200) {
    throw new Error('Zip indirilemedi: ' + zipYanit.getResponseCode());
  }

  const blob = zipYanit.getBlob();
  if (blob.getBytes().length < 1000) {
    throw new Error('Indirilen dosya supheli sekilde kucuk (<1KB)');
  }

  const zamanDamgasi = Utilities.formatDate(new Date(), 'UTC', "yyyyMMdd'T'HHmmss'Z'");
  const dosyaAdi = `${PREFIX}${kisaSha}_${zamanDamgasi}.zip`;
  blob.setName(dosyaAdi);
  const yeniDosya = klasor.createFile(blob);

  // Eski yedekleri çöpe taşı (yalnızca bu projenin ve dalın eski yedekleri)
  const temizlenecekler = klasor.getFiles();
  let silinen = 0;
  while (temizlenecekler.hasNext()) {
    const f = temizlenecekler.next();
    if (f.getId() === yeniDosya.getId()) continue;
    if (f.getName().startsWith(PREFIX) && f.getName().endsWith('.zip')) {
      f.setTrashed(true);
      silinen++;
    }
  }

  return `OK ${dosyaAdi} (${(blob.getBytes().length / (1024 * 1024)).toFixed(2)} MB, ${silinen} eski yedek silindi)`;
}

// GitHub Actions tetiklemesi icin Web App giris noktasi
function doGet(e) {
  const yetkiHatasi = dogrula_(e);
  if (yetkiHatasi) return yetkiHatasi;
  try {
    const sonuc = yedekle();
    return ContentService.createTextOutput(sonuc).setMimeType(ContentService.MimeType.TEXT);
  } catch (err) {
    return ContentService.createTextOutput('HATA: ' + err.message).setMimeType(ContentService.MimeType.TEXT);
  }
}

function doPost(e) {
  return doGet(e);
}

// Saatlik tetikleyici manuel olarak da cagirabilsin
function saatlikKontrol() {
  try {
    const sonuc = yedekle();
    Logger.log(sonuc);
  } catch (err) {
    Logger.log('HATA: ' + err.message);
  }
}
