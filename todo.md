# certstream-server-rust — 2026 CT Adaptation TODO

> **Status:** v1.4.0 (May 2, 2026) addresses P0 + P1 items below plus a critical
> tile-parser bug fix discovered during integration testing. P2/P3 polish
> remains for v1.4.1+. See `RELEASE_NOTES.md` for the full v1.4.0 entry.



Mayıs 2026 itibarıyla CT ekosistemindeki değişikliklere uyum için yol haritası.
Audit + static-ct-api v1.0.0-rc.1 spec + Apple/Chrome politika incelemesine dayanır.

## Bağlam (kısa)

- **28 Şub 2026**: Let's Encrypt RFC6962 logları tamamen kapandı. LE artık sadece Sycamore/Willow (static-ct) loglarına yazıyor.
- **5 May 2026 (Chrome 148)**: Stapled OCSP içindeki SCT desteği kaldırıldı. Embedded SCT ana yol.
- **1 Nis 2026**: Chrome'a yeni log inclusion başvuruları static-ct olarak alınıyor.
- **~Ekim 2026 hedefi**: Chrome politikası API-agnostic olacak (RFC6962 zorunluluğu kalkıyor).
- **Static CT API v1.0.0-rc.1** stabilize oldu; witness imzaları, `leaf_index` SCT extension, tile path normalleşti.
- **Apple log list schema güncellendi**: `assetVersionV2` ve `operators[].tiled_logs[]` (monitoring_url + submission_url + tls_only) eklendi — tiled log discovery artık standart.

Codebase durumu: `src/ct/static_ct.rs` (1142 satır) + `dedup.rs` zaten var, tile path encoding ve checkpoint parsing doğru. Asıl boşluk: log discovery (Apple `tiled_logs`), RFC6962 disable mekanizması, ve operasyonel parite (rate limiter, health check fallback).

---

## P0 — RFC6962 ölümünden sonra acil

### 1. Static-CT health check fallback ekle
- **Dosya**: `src/ct/log_list.rs:159-185`
- **Sorun**: Health check sadece `/ct/v1/get-sth` deniyor. Static-ct-only loglar (Sycamore, Willow, Azul) hep "unhealthy" görünür ve discovery sessizce kırılır.
- **Yapılacak**: log entry'ye `LogType` taşı; static log için `<monitoring_url>/checkpoint` GET, RFC6962 için mevcut `/get-sth`. Her ikisi için 200 + non-empty body kabul.
- **Kabul kriteri**: Sycamore + Willow URL'leri healthy işaretleniyor; testte mock checkpoint dönen server için doğru çalışıyor.

### 2. Apple log list desteği + `tiled_logs` discovery
- **Dosya**: `src/ct/log_list.rs` (tüm parser), `src/config.rs`
- **Sorun**: Sadece Google v3 list (`gstatic.com/ct/log_list/v3/log_list.json`) parse ediliyor. Apple'ın listesinde `operators[].tiled_logs[]` array'i var: `description`, `log_id`, `key`, `monitoring_url`, `submission_url`, `tls_only`, `temporal_interval`, `state`. Bu olmadan tiled logları manuel `config.yaml > static_logs` altına eklemek zorunda kalıyoruz.
- **Yapılacak**:
  - Apple list URL'i için ikinci fetcher ekle (default: `https://valid.apple.com/ct/log_list/current_log_list.json`).
  - Parser'ı genişlet: `tiled_logs` dizisini oku, her birini `StaticCtLog { name, url: monitoring_url, log_origin: derive_from_submission_url }` olarak normalize et.
  - `assetVersionV2` ve `tiled_logs` alanlarını `#[serde(default)]` ile karşıla; iki listeden gelen logları `log_id`'e göre dedupe et (Apple > Google öncelik).
  - Config: `apple_ct_logs_url: Option<String>`, default açık.
- **Kabul kriteri**: Boş `static_logs` config'iyle başlatıldığında Apple/Google list'inden tiled loglar otomatik discover ediliyor.

### 3. RFC6962 ve static-CT için runtime enable/disable
- **Dosya**: `src/main.rs:189-415`, `src/config.rs`
- **Sorun**: Tek yol config'i boşaltmak. Migration / A-B test / deneme için kötü.
- **Yapılacak**: `CERTSTREAM_RFC6962_ENABLED` (default `true`), `CERTSTREAM_STATIC_CT_ENABLED` (default `true`) env vars; config'de de aynı flag'ler. False ise watcher hiç spawn edilmiyor (log seviyesi `INFO` ile bildir).
- **Kabul kriteri**: `CERTSTREAM_RFC6962_ENABLED=false` ile başlatınca sadece static watcher dönüyor; metrics doğru.

### 4. Static-CT için per-operator rate limiter
- **Dosya**: `src/main.rs:200, 363-415`
- **Sorun**: RFC6962 watcher'larında 500ms (2 req/s) per-operator limiter var, static-ct'de yok. Apple list'inden gelen aynı operatörün 6+ tiled log'u olabilir; CDN kibar olsa da operatöre saygı disiplini olmalı.
- **Yapılacak**: Static log entry'sine `operator_name` taşı (log list'ten gelir), `operator_limiters: HashMap<String, Arc<Semaphore>>` oluştur, watcher görevine inject et.
- **Kabul kriteri**: 3 logu olan tek operatör için eş zamanlı request sayısı limit dahilinde.

---

## P1 — Spec uyumu (rc.1)

### 5. `leaf_index` SCT extension parsing
- **Dosya**: `src/ct/parser.rs` (extension extraction), `src/ct/static_ct.rs`
- **Spec**: SCT extension olarak `extension_type=0` (leaf_index), 5 byte big-endian unsigned 40-bit. Toplam extensions field uzunluğu 8 byte (2 type+len header + 1+5).
- **Yapılacak**: Embedded SCT içinden veya tile leaf'ten leaf_index'i çıkar; output mesajına opsiyonel `leaf_index: Option<u64>` ekle. Yokluğunda eski davranış.
- **Kabul kriteri**: Bilinen Sycamore log'undan gelen cert için leaf_index doğru parse ediliyor (unit test fixture ile).

### 6. Witness signature awareness (passive)
- **Dosya**: `src/ct/static_ct.rs:74-108` (checkpoint parser)
- **Spec**: Checkpoint'te birden fazla note signature olabilir; ana log imzası RFC6962NoteSignature (timestamp + TreeHeadSignature), ek olarak witness imzaları gelebilir.
- **Yapılacak**: Şimdilik validate etmeyebiliriz ama parser ek imzaları hatasız atlayabilmeli (görmezden gel, log'la). Future-proofing için `Vec<RawSignature>` saklamak iyi olur.
- **Kabul kriteri**: Witness'lı checkpoint parse'ı bozulmuyor; metric `ct.checkpoint.witness_count` görünür.

### 7. Tree size monotonicity & rollback detection
- **Dosya**: `src/ct/watcher.rs:553`, `src/ct/static_ct.rs` (checkpoint poll loop)
- **Sorun**: Log küçülürse (rollback / hatalı checkpoint) sessizce devam ediyoruz; bu CT açısından ciddi olay.
- **Yapılacak**: Önceki tree_size'ı state'te tut; yeni size daha küçükse `WARN` + `ct.log.rollback_total` counter, ilgili log'u circuit breaker'a sok.
- **Kabul kriteri**: Test fixture ile rollback detect ediliyor.

### 8. Partial tile width validation
- **Dosya**: `src/ct/static_ct.rs:576-580`
- **Spec**: Partial tile genişliği `floor(s / 256^l) mod 256` formülüyle deterministik. Server'dan gelen leaf sayısı announced width ile eşleşmeli.
- **Yapılacak**: Decode sonrası leaf count check; uyumsuzsa hata + log skip.

---

## P2 — Operasyonel sağlamlık

### 9. Cross-log dedup TTL stratejisi
- **Dosya**: `src/dedup.rs:7-9`
- **Sorun**: Global 5dk TTL, 500K kapasite. Geçiş döneminde aynı cert RFC6962 (varsa) + 2-3 static log'da belirebiliyor; static logların null MMD ile çok hızlı gelmesi window'u zorluyor.
- **Yapılacak**: TTL'i 15dk'ya çıkar (config'lenebilir tut), kapasiteyi 1M'ye çıkar; metric: `dedup.evictions`, `dedup.hits`, `dedup.size`. Trafik gözleminden sonra fine-tune.

### 10. Chrome 148 OCSP-stapled SCT — mesaj zenginleştirmesi (opsiyonel)
- **Dosya**: `src/models/`, `src/ct/parser.rs`
- **Bağlam**: Bizi log ingest tarafında doğrudan etkilemez (logdan okuyoruz, TLS'den değil). Ama embedded vs OCSP-stapled SCT ayrımı tüketicilere fayda sağlayabilir.
- **Yapılacak**: Output mesajına `sct_count_embedded` alanı ekle (cert SCT extension sayısı). Düşük öncelik, gerekirse atla.

### 11. State migration: log_url → log_id key
- **Dosya**: `src/state.rs`, `certstream_state.json` schema
- **Sorun**: State şu an URL-keyed. Apple/Google list'i bir log'un URL'ini değiştirirse (yeniden adresleme), saved index kaybolur ve baştan başlanır. Log ID değişmez.
- **Yapılacak**: Key olarak base64(log_id) kullan; mevcut state için bir kerelik migration (URL → log_id mapping) yaz, sonraki sürümde URL key desteğini kaldır.

### 12. Production log defaults
- **Dosya**: `config.yaml.example`
- **Yapılacak**: Mevcut bilinen prod tiled logları örnek olarak ekle (Sycamore 2026h1/h2, Willow 2026h1/h2, Cloudflare Azul 2026h1/h2, Google Argon 2026, vb). Discovery default'sa bile docs için faydalı.

---

## P3 — Test ve hijyen

### 13. Static-CT integration test
- **Dosya**: `tests/static_ct_integration.rs` (yeni)
- **Yapılacak**: Mock HTTP server (axum) ile checkpoint → tiles → leaf parse → broadcast tam pipeline'ı; gzip data tile, partial tile, issuer fetch dahil.

### 14. Apple log list parser fixture testi
- Vendored sample (sanitized) `current_log_list.json` ile parser unit test'i; `tiled_logs` boş/dolu varyantları, eksik alanlar.

### 15. simd-json fallback dokümantasyonu
- **Dosya**: `README.md`
- `--no-default-features` ile pure serde_json modu; ne zaman gerekir, perf etkisi.

### 16. RFC6962 watcher'ın deprecation timeline'ı
- **Dosya**: `README.md`, `CHANGELOG.md`
- v1.4.x: hâlâ default, deprecated uyarısı.
- v2.0: default kapalı, sadece explicit opt-in ile (Chrome'un Ekim 2026 API-agnostic geçişiyle uyumlu).

---

## Yapmıyoruz / Reddedildi

- **Kendi witness signing**: Witness olmak ayrı bir operasyon, scope dışı. Sadece witness'lı checkpoint parse'ı bozulmasın yeterli (P1#6).
- **Static log SUBMISSION endpoint'leri**: Biz monitor/streamer'ız, submitter değil. add-chain vs. ekleme yok.
- **Yeni dependency**: Geçişi mevcut (reqwest, serde, flate2, moka) ile yapılabilir; ek crate gerekmedikçe ekleme.

---

## Önerilen sırayla ilerleme

1. **Sprint 1** (P0): #1, #2, #3, #4 — bu dördü bitince post-RFC6962 dünyada production-ready'iz.
2. **Sprint 2** (P1): #5, #7, #8, #6 — spec rc.1 uyumu.
3. **Sprint 3** (P2/P3): #9, #11, #13, #14 — operasyonel olgunluk + test.
4. #10, #12, #15, #16 fırsat buldukça.

Her item için ayrı PR; #2 büyükse parser + config + discovery şeklinde 2-3'e bölünebilir.
