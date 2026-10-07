use serde::Deserialize;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

/// `env_override!(target, "ENV_NAME")` reads the named env var, parses it,
/// and assigns on success — leaving `target` untouched on missing var or
/// parse failure. Replaces ~3 lines of boilerplate per field with one line
/// while preserving the exact "ignore garbage env values" semantics of the
/// hand-rolled code.
macro_rules! env_override {
    ($field:expr, $env:literal) => {
        if let Ok(v) = std::env::var($env)
            && let Ok(parsed) = v.parse()
        {
            $field = parsed;
        }
    };
    ($field:expr, $env:literal, str) => {
        if let Ok(v) = std::env::var($env) {
            $field = v;
        }
    };
    ($field:expr, $env:literal, some_str) => {
        if let Ok(v) = std::env::var($env) {
            $field = Some(v);
        }
    };
    ($field:expr, $env:literal, ok_opt) => {
        if let Ok(v) = std::env::var($env) {
            $field = v.parse().ok();
        }
    };
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomCtLog {
    pub name: String,
    pub url: String,
    /// Optional operator-declared base64-encoded CT log ID for runtime
    /// identity, metrics, and duplicate-log detection.
    #[serde(default)]
    pub expected_log_id: Option<String>,
    /// Optional per-log overrides; absent entries inherit the global CT log
    /// batch size and poll interval.
    #[serde(default)]
    pub batch_size: Option<u64>,
    #[serde(default)]
    pub poll_interval_ms: Option<u64>,
}

/// Where a static-CT watcher reads the tree head from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeSizeSource {
    /// The signed `/checkpoint` endpoint, as static-ct-api specifies.
    #[default]
    Checkpoint,
    /// RFC 6962 `/ct/v1/get-sth`. For logs that serve tile data but answer
    /// `/checkpoint` with a 404: TrustAsia's log2026a, log2026b and hetu2027
    /// do this, and their `get-entries` is slow enough (25-31s for 256 entries
    /// against under a second from a warm tile) that reading tiles is worth
    /// giving up the checkpoint for.
    ///
    /// Nothing about such a log is cryptographically verifiable on our side:
    /// there is no signed head to check the tiles against. Only use this for
    /// logs whose operator has said they serve tiles deliberately.
    GetSth,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticCtLog {
    pub name: String,
    pub url: String,
    /// Override the expected checkpoint origin for logs where the fetch URL (e.g. `mon.*`)
    /// differs from the origin embedded in the checkpoint (e.g. `log.*`).
    /// When absent, the origin is derived from the URL by stripping the scheme and trailing slash.
    #[serde(default)]
    pub log_origin: Option<String>,
    /// Optional expected base64-encoded CT log ID for override validation.
    #[serde(default)]
    pub expected_log_id: Option<String>,
    /// Optional base64-encoded SubjectPublicKeyInfo (DER) of the log's public
    /// key, used to verify checkpoint signatures. When absent, checkpoints from
    /// this log cannot be cryptographically verified (treated as unverifiable).
    #[serde(default)]
    pub key: Option<String>,
    /// Optional per-log overrides; absent entries inherit the global CT log
    /// batch size and poll interval.
    #[serde(default)]
    pub batch_size: Option<u64>,
    #[serde(default)]
    pub poll_interval_ms: Option<u64>,
    /// Where to read the tree head from. Defaults to the signed checkpoint.
    #[serde(default)]
    pub tree_size_source: TreeSizeSource,
    /// Operator this log belongs to. Rate limits are keyed by operator name,
    /// so getting this right is what keeps several logs from one operator in
    /// the same bucket (and out of everyone else's). When omitted, an entry
    /// that replaces a discovered log inherits that log's operator; otherwise
    /// it falls back to a generic name.
    #[serde(default)]
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolConfig {
    #[serde(default = "default_true")]
    pub websocket: bool,
    #[serde(default)]
    pub sse: bool,
    #[serde(default = "default_true")]
    pub metrics: bool,
    #[serde(default = "default_true")]
    pub health: bool,
    #[serde(default = "default_true")]
    pub example_json: bool,
    #[serde(default)]
    pub api: bool,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            websocket: true,
            sse: false,
            metrics: true,
            health: true,
            example_json: true,
            api: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CtLogConfig {
    /// Static-CT checkpoint signature verification policy. `warn` (default)
    /// verifies the log signature and logs/counts failures but always accepts
    /// the checkpoint; `enforce` additionally rejects checkpoints whose
    /// signature is present but fails verification. Checkpoints that cannot be
    /// verified at all (no usable P-256 key) are accepted in both modes.
    /// Override with `CERTSTREAM_STATIC_CT_CHECKPOINT_SIGNATURE`.
    #[serde(default)]
    pub checkpoint_signature_mode: CheckpointSignatureMode,
    #[serde(default = "default_retry_max_attempts")]
    pub retry_max_attempts: u32,
    #[serde(default = "default_retry_initial_delay_ms")]
    pub retry_initial_delay_ms: u64,
    #[serde(default = "default_retry_max_delay_ms")]
    pub retry_max_delay_ms: u64,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_health_check_interval_secs")]
    pub health_check_interval_secs: u64,
    #[serde(default = "default_state_file")]
    pub state_file: Option<String>,
    /// What to do when `state_file` exists but cannot be read or parsed.
    /// `fresh` (default) warns and restarts every watcher from the log head;
    /// `fail` refuses to start, so an operator who cares about continuity is
    /// told the saved position is gone instead of silently re-reading from
    /// the head. A missing state file is a first run, not a corrupt one, and
    /// starts fresh under both settings.
    /// Override with `CERTSTREAM_CT_LOG_STATE_RECOVERY`.
    #[serde(default)]
    pub state_recovery: StateRecovery,
    #[serde(default = "default_batch_size")]
    pub batch_size: u64,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// Number of get-entries windows / tiles fetched concurrently per watcher
    /// during catch-up. The per-operator token bucket allows a burst of this
    /// size, so the long-run request rate still honours the operator rate
    /// limit — concurrency only pipelines the latency. 1 = sequential.
    #[serde(default = "default_fetch_concurrency")]
    pub fetch_concurrency: u32,
    /// Seconds a caught-up static-CT watcher waits before fetching the newest
    /// partial tile, hoping it fills first: a full tile is fetched once and
    /// cacheable, while each width of a partial tile is a new uncached URL. The
    /// last 0-255 entries are delivered up to this long (plus one idle poll)
    /// later. `0` fetches partial tiles at once.
    /// Override with `CERTSTREAM_CT_LOG_PARTIAL_TILE_WAIT_SECS`.
    #[serde(default = "default_partial_tile_wait_secs")]
    pub partial_tile_wait_secs: u64,
    /// Number of leaves a fresh static-CT watcher starts behind the current checkpoint head.
    /// The default preserves the existing head-256 behavior while making the overlap tunable.
    #[serde(default = "default_start_overlap_leaves")]
    pub start_overlap_leaves: u64,
    /// How often the CT log list is re-fetched while the server runs, so a
    /// log added to the catalog is picked up without a restart. `0` disables
    /// refresh entirely, leaving discovery to happen once at boot.
    /// Override with `CERTSTREAM_CT_LOG_REFRESH_INTERVAL_SECS`.
    #[serde(default = "default_log_refresh_interval_secs")]
    pub log_refresh_interval_secs: u64,
    /// What a refresh does with a running watcher whose log the catalog no
    /// longer lists. Never applies to logs from `custom_logs` / `static_logs`:
    /// those come from this server's own config, so a catalog that stops
    /// listing them says nothing about them.
    /// Override with `CERTSTREAM_CT_LOG_REMOVED_POLICY`.
    #[serde(default)]
    pub removed_log_policy: RemovedLogPolicy,
    /// Merkle verification against a static-CT log's own hash tiles. The
    /// checkpoint signature says the log signed *some* tree; these say
    /// whether that tree contains what was just read, and whether it extends
    /// the tree seen a moment ago. Extra fetches and CPU, so opt-in.
    /// Override with `CERTSTREAM_STATIC_CT_MERKLE_VERIFICATION`.
    #[serde(default)]
    pub merkle_verification: MerkleVerification,
    /// Read names from a static-CT log's optional names-tiles extension
    /// instead of parsing its data tiles. Far cheaper for a
    /// domains-only deployment, and unauthenticated — see [`NamesTiles`].
    /// Override with `CERTSTREAM_STATIC_CT_NAMES_TILES`.
    #[serde(default)]
    pub names_tiles: NamesTiles,
    /// Master switch for the legacy RFC 6962 watcher pool. When `false`, the
    /// Google v3 log list (and any `custom_logs`) are skipped at startup.
    /// Override with `CERTSTREAM_RFC6962_ENABLED`.
    #[serde(default = "default_true")]
    pub rfc6962_enabled: bool,
    /// Master switch for the static-CT (Sunlight / static-ct-api) watchers.
    /// When `false`, both `static_logs` and any tiled logs discovered via the
    /// log list are skipped at startup.
    /// Override with `CERTSTREAM_STATIC_CT_ENABLED`.
    #[serde(default = "default_true")]
    pub static_ct_enabled: bool,
    /// Per-operator outbound rate-limit floor in milliseconds for any operator
    /// not listed in `operator_rate_limits`.
    #[serde(default = "default_operator_rate_limit_ms")]
    pub default_operator_rate_limit_ms: u64,
    /// Per-operator overrides. Keys are canonicalized at use, so a YAML key like
    /// "digicert" matches the catalog-emitted operator regardless of case,
    /// whitespace, or punctuation. Empty map means every operator uses the default.
    #[serde(default)]
    pub operator_rate_limits: std::collections::HashMap<String, u64>,
    /// HTTP User-Agent for outbound requests. Some CT log operators (e.g.
    /// Geomys) apply a more generous rate limit tier to clients that include
    /// a contact email. Unset or blank falls back to the compiled-in
    /// `certstream-server-rust/{VERSION} (+https://github.com/reloading01/certstream-server-rust)`; read this through
    /// [`CtLogConfig::user_agent_override`] rather than directly.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Operators whose watchers fetch over a dedicated HTTP/1.1-only client.
    /// DigiCert throttles per TCP connection rather than per IP; under HTTP/2
    /// reqwest multiplexes every request for a host onto one connection, so
    /// that per-connection quota becomes a whole-process quota. HTTP/1.1
    /// spreads the same request rate — still capped by the per-operator
    /// limiter — over one connection per in-flight fetch. Names are
    /// canonicalized with the same rules as `operator_rate_limits`.
    #[serde(default)]
    pub force_http1_operators: Vec<String>,
    /// Operators whose catalog logs are never monitored. Names are
    /// canonicalized like `operator_rate_limits` keys. Logs configured by hand
    /// in `static_logs` or `custom_logs` are not affected.
    #[serde(default)]
    pub excluded_operators: Vec<String>,
    /// Individual catalog logs that are never monitored, by monitoring URL as
    /// `/api/logs` shows it. Excluded logs are not contacted at all.
    #[serde(default)]
    pub excluded_logs: Vec<String>,
    /// Per-catalog-source runtime-authority overrides. Keys are the catalog
    /// registry source names (`google_v3_usable`, `google_v3_all`, `apple`).
    /// An override can only grant authority to a source that currently verifies;
    /// it cannot promote an unverified source. Unknown keys are ignored.
    #[serde(default)]
    pub catalog_authority_overrides: std::collections::HashMap<String, bool>,
}

/// Whether to collect names from a log's names-tiles extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NamesTiles {
    /// Always read data tiles. Default.
    #[default]
    Off,
    /// Read names tiles from logs that serve them, and data tiles from logs
    /// that do not.
    ///
    /// Names tiles are unauthenticated: the extension states they cannot be
    /// checked for inclusion in a signed tree head. Entries read this way are
    /// published as `dns_entries_unauthenticated` so a consumer can tell them
    /// apart, and this mode is only valid when `domains_only` is the sole
    /// enabled stream — there is no certificate to build the others from.
    Prefer,
}

impl std::str::FromStr for NamesTiles {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Ok(Self::Off),
            "prefer" => Ok(Self::Prefer),
            _ => Err(()),
        }
    }
}

/// How much of a static-CT log's tree to verify while reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MerkleVerification {
    /// Trust the checkpoint signature and read. Default, and what every
    /// release before 1.6 did.
    #[default]
    Off,
    /// Prove each new checkpoint extends the previous one. A handful of extra
    /// hash-tile fetches per checkpoint; catches a log that rewrites history.
    Consistency,
    /// Consistency, plus proof that every ingested entry is in the signed
    /// tree. Costs hash-tile fetches and hashing proportional to ingest.
    Full,
}

impl MerkleVerification {
    pub fn checks_consistency(self) -> bool {
        matches!(self, Self::Consistency | Self::Full)
    }

    pub fn checks_inclusion(self) -> bool {
        matches!(self, Self::Full)
    }
}

impl std::str::FromStr for MerkleVerification {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Ok(Self::Off),
            "consistency" => Ok(Self::Consistency),
            "full" => Ok(Self::Full),
            _ => Err(()),
        }
    }
}

/// What a log-list refresh does with a watcher whose log was delisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemovedLogPolicy {
    /// Stop the watcher. Default: a delisted log is retired or rejected, and
    /// polling it spends operator request budget on a tree that no longer
    /// grows. The saved position is kept, so a log that reappears resumes
    /// where it stopped rather than replaying.
    #[default]
    Stop,
    /// Leave it running. For deployments that would rather keep reading a
    /// delisted log than trust the catalog's removal.
    Keep,
}

impl std::str::FromStr for RemovedLogPolicy {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stop" => Ok(Self::Stop),
            "keep" => Ok(Self::Keep),
            _ => Err(()),
        }
    }
}

/// What to do with a state file that exists but cannot be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateRecovery {
    /// Warn and start from the log head. Default.
    #[default]
    Fresh,
    /// Refuse to start. For deployments where re-reading from the head is
    /// worse than not running.
    Fail,
}

impl std::str::FromStr for StateRecovery {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fresh" => Ok(Self::Fresh),
            "fail" => Ok(Self::Fail),
            _ => Err(()),
        }
    }
}

/// Verification policy for static-CT checkpoint signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckpointSignatureMode {
    /// Verify the log signature and log/count failures, but always accept the
    /// checkpoint (never blocks ingest). Default.
    #[default]
    Warn,
    /// Reject checkpoints whose signature is present but fails verification.
    /// Checkpoints that cannot be verified at all (no usable key) are still
    /// accepted — inability to verify is not proof of forgery.
    Enforce,
}

impl std::str::FromStr for CheckpointSignatureMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "warn" => Ok(Self::Warn),
            "enforce" => Ok(Self::Enforce),
            _ => Err(()),
        }
    }
}

impl CtLogConfig {
    /// The configured User-Agent with surrounding whitespace trimmed, or
    /// `None` when unset or blank. A blank value is treated as unset because
    /// `CERTSTREAM_USER_AGENT=` in a compose file or `.env` reads back as an
    /// empty string, and an empty `User-Agent:` header is exactly the opposite
    /// of what an operator setting this is asking for.
    pub fn user_agent_override(&self) -> Option<&str> {
        self.user_agent
            .as_deref()
            .map(str::trim)
            .filter(|ua| !ua.is_empty())
    }
}

impl Default for CtLogConfig {
    fn default() -> Self {
        Self {
            checkpoint_signature_mode: CheckpointSignatureMode::default(),
            retry_max_attempts: default_retry_max_attempts(),
            retry_initial_delay_ms: default_retry_initial_delay_ms(),
            retry_max_delay_ms: default_retry_max_delay_ms(),
            request_timeout_secs: default_request_timeout_secs(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            health_check_interval_secs: default_health_check_interval_secs(),
            state_file: default_state_file(),
            state_recovery: StateRecovery::default(),
            merkle_verification: MerkleVerification::default(),
            names_tiles: NamesTiles::default(),
            log_refresh_interval_secs: default_log_refresh_interval_secs(),
            removed_log_policy: RemovedLogPolicy::default(),
            batch_size: default_batch_size(),
            poll_interval_ms: default_poll_interval_ms(),
            fetch_concurrency: default_fetch_concurrency(),
            partial_tile_wait_secs: default_partial_tile_wait_secs(),
            start_overlap_leaves: default_start_overlap_leaves(),
            rfc6962_enabled: true,
            static_ct_enabled: true,
            default_operator_rate_limit_ms: default_operator_rate_limit_ms(),
            operator_rate_limits: std::collections::HashMap::new(),
            user_agent: None,
            force_http1_operators: Vec::new(),
            excluded_operators: Vec::new(),
            excluded_logs: Vec::new(),
            catalog_authority_overrides: std::collections::HashMap::new(),
        }
    }
}

pub const MAX_START_OVERLAP_LEAVES: u64 = 100_000;
pub const MAX_PARTIAL_TILE_WAIT_SECS: u64 = 600;

/// Split a comma-separated env value into operator names, dropping blanks so
/// `"digicert,"` and `"digicert, ,geomys"` behave like the obvious YAML list.
fn parse_operator_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn default_operator_rate_limit_ms() -> u64 {
    25
}

fn default_retry_max_attempts() -> u32 {
    3
}
fn default_retry_initial_delay_ms() -> u64 {
    1000
}
fn default_retry_max_delay_ms() -> u64 {
    30000
}
fn default_request_timeout_secs() -> u64 {
    30
}
fn default_healthy_threshold() -> u32 {
    2
}
fn default_unhealthy_threshold() -> u32 {
    5
}
fn default_health_check_interval_secs() -> u64 {
    60
}
fn default_batch_size() -> u64 {
    // RFC 6962 servers clamp get-entries responses to their own maximum and
    // returning fewer entries than requested is spec-legal, so asking for
    // 1024 is safe everywhere; logs that allow it deliver 4× more entries
    // per (rate-limited) request than the old 256 default. The watcher
    // adapts its window to whatever the server actually returns.
    1024
}
fn default_poll_interval_ms() -> u64 {
    1000
}
fn default_fetch_concurrency() -> u32 {
    4
}
fn default_partial_tile_wait_secs() -> u64 {
    60
}
fn default_start_overlap_leaves() -> u64 {
    256
}
fn default_log_refresh_interval_secs() -> u64 {
    // Log lists change on the scale of weeks. Hourly is frequent enough that
    // a new log is picked up the same day and rare enough that the catalog
    // fetch is nothing next to the ingest traffic.
    3600
}
fn default_state_file() -> Option<String> {
    Some("certstream_state.json".to_string())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default)]
    pub per_ip_limit: Option<u32>,
}

impl Default for ConnectionLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: default_max_connections(),
            per_ip_limit: None,
        }
    }
}

fn default_max_connections() -> u32 {
    10000
}

/// Per-IP rate limit. Single tier — no premium/standard split. Auth and
/// rate-limit are independent concerns: auth gates *who* can talk to the
/// server, rate limit gates *how often* per source IP.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_tokens", alias = "free_max_tokens")]
    pub max_tokens: f64,
    #[serde(default = "default_refill_rate", alias = "free_refill_rate")]
    pub refill_rate: f64,
    #[serde(default = "default_burst", alias = "free_burst")]
    pub burst: f64,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_window_max_requests")]
    pub window_max_requests: u32,
    #[serde(default = "default_burst_window_seconds")]
    pub burst_window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_tokens: default_max_tokens(),
            refill_rate: default_refill_rate(),
            burst: default_burst(),
            window_seconds: default_window_seconds(),
            window_max_requests: default_window_max_requests(),
            burst_window_seconds: default_burst_window_seconds(),
        }
    }
}

fn default_max_tokens() -> f64 {
    100.0
}
fn default_refill_rate() -> f64 {
    10.0
}
fn default_burst() -> f64 {
    20.0
}
fn default_window_seconds() -> u64 {
    60
}
fn default_window_max_requests() -> u32 {
    1000
}
fn default_burst_window_seconds() -> u64 {
    10
}

#[derive(Debug, Clone, Deserialize)]
pub struct DedupConfig {
    #[serde(default = "default_dedup_capacity")]
    pub capacity: usize,
    #[serde(default = "default_dedup_ttl_secs")]
    pub ttl_secs: u64,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            capacity: default_dedup_capacity(),
            ttl_secs: default_dedup_ttl_secs(),
        }
    }
}

fn default_dedup_capacity() -> usize {
    // Reset from 1M (v1.4) to 200K in 1.5.0 after the memory audit.
    // See dedup.rs::DEFAULT_CAPACITY for the rationale; in short, the
    // 1M cap cost ~38 MiB of resident memory for a window that the
    // working set never needed.
    200_000
}
fn default_dedup_ttl_secs() -> u64 {
    900
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            cache_capacity: default_cache_capacity(),
        }
    }
}

fn default_cache_capacity() -> usize {
    // Dropped from 10K to 1K in 1.5.0. The /api/cert/{hash} endpoint is a
    // niche operator lookup, not a hot path — 10K cache entries at ~1.5 KB
    // each is ~15 MiB of memory mostly serving requests that never come.
    // Operators with heavier REST traffic can bump via `CERTSTREAM_API_*`
    // / YAML `api.cache_capacity`.
    1_000
}

/// Bearer-token auth. Single flat token list — no premium/standard tiering.
/// Rate limiting is enforced separately, per source IP, and does not look at
/// the bearer at all.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tokens: Vec<String>,
    #[serde(default = "default_header_name")]
    pub header_name: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tokens: Vec::new(),
            header_name: default_header_name(),
        }
    }
}

fn default_header_name() -> String {
    "Authorization".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct StreamConfig {
    #[serde(default = "default_true")]
    pub full: bool,
    #[serde(default = "default_true")]
    pub lite: bool,
    #[serde(default = "default_true")]
    pub domains_only: bool,
    /// Version 2 of the wire format: the same certificate with an explicit
    /// source address (`log_id` + entry index), entry type, observation time,
    /// and what was actually verified. Off by default — it is a fourth
    /// serialization of every certificate, and a deployment that nobody
    /// consumes it from should not pay for it.
    #[serde(default)]
    pub v2: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            full: true,
            lite: true,
            domains_only: true,
            v2: false,
        }
    }
}

/// What to do when JetStream will not take a record — a full stream under
/// `discard: new`, a broker that is down, or an acknowledgement that never
/// arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NatsOnFull {
    /// Wait for room. The saved position stays behind the unstored record, so
    /// a restart re-reads it. Slows ingest rather than losing data. Default,
    /// because a durable output that quietly drops is not a durable output.
    #[default]
    Block,
    /// Give up on the record and keep reading. For a deployment that would
    /// rather have a live stream with holes than a stalled one.
    Drop,
}

impl std::str::FromStr for NatsOnFull {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "block" => Ok(Self::Block),
            "drop" => Ok(Self::Drop),
            _ => Err(()),
        }
    }
}

/// Optional durable output to NATS JetStream.
#[derive(Debug, Clone, Deserialize)]
pub struct NatsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nats_url")]
    pub url: String,
    #[serde(default = "default_nats_stream")]
    pub stream: String,
    /// Records are published to `<prefix>.<operator>.<log>`, so a consumer can
    /// subscribe to one operator or one log instead of the whole feed.
    #[serde(default = "default_nats_subject_prefix")]
    pub subject_prefix: String,
    /// Stream size cap. Reaching it rejects publishes rather than deleting the
    /// oldest records — see [`NatsOnFull`].
    #[serde(default = "default_nats_max_bytes")]
    pub max_bytes: i64,
    /// How long the server remembers a `Nats-Msg-Id`. A restart that re-reads
    /// entries republishes them with the same id; inside this window the
    /// server recognises them and stores one copy. Set it wider than the
    /// longest restart you expect to survive without duplicates.
    #[serde(default = "default_nats_duplicate_window_secs")]
    pub duplicate_window_secs: u64,
    #[serde(default = "default_nats_publish_timeout_secs")]
    pub publish_timeout_secs: u64,
    /// Records queued between the watchers and the publisher. Deep enough to
    /// absorb a slow ack, shallow enough that back-pressure reaches ingest
    /// before memory does.
    #[serde(default = "default_nats_queue_depth")]
    pub queue_depth: usize,
    #[serde(default)]
    pub on_full: NatsOnFull,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_nats_url(),
            stream: default_nats_stream(),
            subject_prefix: default_nats_subject_prefix(),
            max_bytes: default_nats_max_bytes(),
            duplicate_window_secs: default_nats_duplicate_window_secs(),
            publish_timeout_secs: default_nats_publish_timeout_secs(),
            queue_depth: default_nats_queue_depth(),
            on_full: NatsOnFull::default(),
        }
    }
}

fn default_nats_url() -> String {
    "nats://127.0.0.1:4222".to_string()
}
fn default_nats_stream() -> String {
    "CERTSTREAM".to_string()
}
fn default_nats_subject_prefix() -> String {
    "certstream".to_string()
}
fn default_nats_max_bytes() -> i64 {
    // 8 GiB. Explicit rather than unlimited: "unlimited" means the disk
    // decides what happens when the stream fills, and it decides badly.
    8 * 1024 * 1024 * 1024
}
fn default_nats_duplicate_window_secs() -> u64 {
    // Wider than JetStream's 2-minute default: a restart that re-reads a
    // batch should still be deduplicated after a slow redeploy.
    900
}
fn default_nats_publish_timeout_secs() -> u64 {
    30
}
fn default_nats_queue_depth() -> usize {
    10_000
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HotReloadConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub watch_path: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone)]
pub struct Config {
    pub host: IpAddr,
    pub port: u16,
    pub log_level: String,
    pub buffer_size: usize,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub custom_logs: Vec<CustomCtLog>,
    pub static_logs: Vec<StaticCtLog>,
    pub protocols: ProtocolConfig,
    pub ct_log: CtLogConfig,
    pub connection_limit: ConnectionLimitConfig,
    /// Proxies, as IP addresses or CIDR ranges, whose `X-Forwarded-For` and
    /// `X-Real-IP` headers are believed when working out a client's address.
    /// Empty means the TCP peer is always the client.
    pub trusted_proxies: Vec<String>,
    pub rate_limit: RateLimitConfig,
    pub api: ApiConfig,
    pub auth: AuthConfig,
    pub hot_reload: HotReloadConfig,
    pub nats: NatsConfig,
    pub streams: StreamConfig,
    pub dedup: DedupConfig,
    pub config_path: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct YamlConfig {
    host: Option<String>,
    port: Option<u16>,
    log_level: Option<String>,
    buffer_size: Option<usize>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    #[serde(default)]
    custom_logs: Vec<CustomCtLog>,
    #[serde(default)]
    static_logs: Vec<StaticCtLog>,
    #[serde(default)]
    protocols: Option<ProtocolConfig>,
    #[serde(default)]
    ct_log: Option<CtLogConfig>,
    #[serde(default)]
    connection_limit: Option<ConnectionLimitConfig>,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    api: Option<ApiConfig>,
    #[serde(default)]
    auth: Option<AuthConfig>,
    #[serde(default)]
    hot_reload: Option<HotReloadConfig>,
    nats: Option<NatsConfig>,
    #[serde(default)]
    streams: Option<StreamConfig>,
    #[serde(default)]
    dedup: Option<DedupConfig>,
}

struct YamlConfigWithPath {
    config: YamlConfig,
    path: Option<String>,
}

#[derive(Debug)]
pub struct ConfigValidationError {
    pub field: String,
    pub message: String,
}

impl Config {
    pub fn load() -> Self {
        let yaml_result = Self::load_yaml();
        let yaml_config = yaml_result.config;
        let config_path = yaml_result.path;

        let host = env::var("CERTSTREAM_HOST")
            .ok()
            .or(yaml_config.host)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| "0.0.0.0".parse().unwrap());

        let port = env::var("CERTSTREAM_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .or(yaml_config.port)
            .unwrap_or(8080);

        let log_level = env::var("CERTSTREAM_LOG_LEVEL")
            .ok()
            .or(yaml_config.log_level)
            .unwrap_or_else(|| "info".to_string());

        let buffer_size = env::var("CERTSTREAM_BUFFER_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .or(yaml_config.buffer_size)
            .unwrap_or(1000);

        // CT log sources are provided by the code-owned signed-catalog registry.

        let tls_cert = env::var("CERTSTREAM_TLS_CERT").ok().or(yaml_config.tls_cert);
        let tls_key = env::var("CERTSTREAM_TLS_KEY").ok().or(yaml_config.tls_key);

        let mut protocols = yaml_config.protocols.unwrap_or_default();
        env_override!(protocols.websocket, "CERTSTREAM_WS_ENABLED");
        env_override!(protocols.sse, "CERTSTREAM_SSE_ENABLED");
        env_override!(protocols.metrics, "CERTSTREAM_METRICS_ENABLED");
        env_override!(protocols.health, "CERTSTREAM_HEALTH_ENABLED");
        env_override!(protocols.example_json, "CERTSTREAM_EXAMPLE_JSON_ENABLED");
        env_override!(protocols.api, "CERTSTREAM_API_ENABLED");

        let mut ct_log = yaml_config.ct_log.unwrap_or_default();
        env_override!(ct_log.retry_max_attempts, "CERTSTREAM_CT_LOG_RETRY_MAX_ATTEMPTS");
        env_override!(ct_log.retry_initial_delay_ms, "CERTSTREAM_CT_LOG_RETRY_INITIAL_DELAY_MS");
        env_override!(ct_log.retry_max_delay_ms, "CERTSTREAM_CT_LOG_RETRY_MAX_DELAY_MS");
        env_override!(ct_log.request_timeout_secs, "CERTSTREAM_CT_LOG_REQUEST_TIMEOUT_SECS");
        env_override!(ct_log.unhealthy_threshold, "CERTSTREAM_CT_LOG_UNHEALTHY_THRESHOLD");
        env_override!(ct_log.healthy_threshold, "CERTSTREAM_CT_LOG_HEALTHY_THRESHOLD");
        env_override!(ct_log.health_check_interval_secs, "CERTSTREAM_CT_LOG_HEALTH_CHECK_INTERVAL_SECS");
        env_override!(ct_log.state_file, "CERTSTREAM_CT_LOG_STATE_FILE", some_str);
        env_override!(ct_log.state_recovery, "CERTSTREAM_CT_LOG_STATE_RECOVERY");
        env_override!(
            ct_log.log_refresh_interval_secs,
            "CERTSTREAM_CT_LOG_REFRESH_INTERVAL_SECS"
        );
        env_override!(ct_log.removed_log_policy, "CERTSTREAM_CT_LOG_REMOVED_POLICY");
        env_override!(
            ct_log.merkle_verification,
            "CERTSTREAM_STATIC_CT_MERKLE_VERIFICATION"
        );
        env_override!(ct_log.names_tiles, "CERTSTREAM_STATIC_CT_NAMES_TILES");
        env_override!(ct_log.batch_size, "CERTSTREAM_CT_LOG_BATCH_SIZE");
        env_override!(ct_log.poll_interval_ms, "CERTSTREAM_CT_LOG_POLL_INTERVAL_MS");
        env_override!(ct_log.fetch_concurrency, "CERTSTREAM_CT_LOG_FETCH_CONCURRENCY");
        env_override!(
            ct_log.partial_tile_wait_secs,
            "CERTSTREAM_CT_LOG_PARTIAL_TILE_WAIT_SECS"
        );
        env_override!(ct_log.start_overlap_leaves, "CERTSTREAM_CT_LOG_START_OVERLAP_LEAVES");
        env_override!(ct_log.rfc6962_enabled, "CERTSTREAM_RFC6962_ENABLED");
        env_override!(ct_log.static_ct_enabled, "CERTSTREAM_STATIC_CT_ENABLED");
        env_override!(
            ct_log.checkpoint_signature_mode,
            "CERTSTREAM_STATIC_CT_CHECKPOINT_SIGNATURE"
        );
        env_override!(ct_log.user_agent, "CERTSTREAM_USER_AGENT", some_str);
        if let Ok(v) = env::var("CERTSTREAM_CT_LOG_FORCE_HTTP1_OPERATORS") {
            ct_log.force_http1_operators = parse_operator_list(&v);
        }
        if let Ok(v) = env::var("CERTSTREAM_CT_LOG_EXCLUDED_OPERATORS") {
            ct_log.excluded_operators = parse_operator_list(&v);
        }
        if let Ok(v) = env::var("CERTSTREAM_CT_LOG_EXCLUDED_LOGS") {
            ct_log.excluded_logs = parse_operator_list(&v);
        }

        let mut connection_limit = yaml_config.connection_limit.unwrap_or_default();
        env_override!(connection_limit.enabled, "CERTSTREAM_CONNECTION_LIMIT_ENABLED");
        env_override!(connection_limit.max_connections, "CERTSTREAM_CONNECTION_LIMIT_MAX_CONNECTIONS");
        env_override!(connection_limit.per_ip_limit, "CERTSTREAM_CONNECTION_LIMIT_PER_IP_LIMIT", ok_opt);

        let mut trusted_proxies = yaml_config.trusted_proxies;
        if let Ok(v) = env::var("CERTSTREAM_TRUSTED_PROXIES") {
            trusted_proxies = parse_operator_list(&v);
        }

        let mut rate_limit = yaml_config.rate_limit.unwrap_or_default();
        env_override!(rate_limit.enabled, "CERTSTREAM_RATE_LIMIT_ENABLED");

        let api = yaml_config.api.unwrap_or_default();

        let mut auth = yaml_config.auth.unwrap_or_default();
        env_override!(auth.enabled, "CERTSTREAM_AUTH_ENABLED");
        if let Ok(v) = env::var("CERTSTREAM_AUTH_TOKENS") {
            // Comma-split; macro doesn't cover this shape.
            auth.tokens = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        env_override!(auth.header_name, "CERTSTREAM_AUTH_HEADER_NAME", str);

        let mut hot_reload = yaml_config.hot_reload.unwrap_or_default();
        env_override!(hot_reload.enabled, "CERTSTREAM_HOT_RELOAD_ENABLED");
        env_override!(hot_reload.watch_path, "CERTSTREAM_HOT_RELOAD_WATCH_PATH", some_str);

        let mut dedup = yaml_config.dedup.unwrap_or_default();
        env_override!(dedup.capacity, "CERTSTREAM_DEDUP_CAPACITY");
        env_override!(dedup.ttl_secs, "CERTSTREAM_DEDUP_TTL_SECS");

        let mut streams = yaml_config.streams.unwrap_or_default();
        env_override!(streams.full, "CERTSTREAM_STREAM_FULL_ENABLED");
        env_override!(streams.lite, "CERTSTREAM_STREAM_LITE_ENABLED");
        env_override!(streams.domains_only, "CERTSTREAM_STREAM_DOMAINS_ONLY_ENABLED");
        env_override!(streams.v2, "CERTSTREAM_STREAM_V2_ENABLED");

        let mut nats = yaml_config.nats.unwrap_or_default();
        env_override!(nats.enabled, "CERTSTREAM_NATS_ENABLED");
        env_override!(nats.url, "CERTSTREAM_NATS_URL", str);
        env_override!(nats.stream, "CERTSTREAM_NATS_STREAM", str);
        env_override!(nats.subject_prefix, "CERTSTREAM_NATS_SUBJECT_PREFIX", str);
        env_override!(nats.max_bytes, "CERTSTREAM_NATS_MAX_BYTES");
        env_override!(nats.on_full, "CERTSTREAM_NATS_ON_FULL");

        Self {
            host,
            port,
            log_level,
            buffer_size,
            tls_cert,
            tls_key,
            custom_logs: yaml_config.custom_logs,
            static_logs: yaml_config.static_logs,
            protocols,
            ct_log,
            connection_limit,
            trusted_proxies,
            rate_limit,
            api,
            auth,
            hot_reload,
            nats,
            streams,
            dedup,
            config_path,
        }
    }

    pub fn validate(&self) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        if let Err(message) = crate::middleware::TrustedProxies::parse(&self.trusted_proxies) {
            errors.push(ConfigValidationError {
                field: "trusted_proxies".to_string(),
                message,
            });
        }

        if self.port == 0 {
            errors.push(ConfigValidationError {
                field: "port".to_string(),
                message: "Port must be greater than 0".to_string(),
            });
        }

        if self.buffer_size == 0 {
            errors.push(ConfigValidationError {
                field: "buffer_size".to_string(),
                message: "Buffer size must be greater than 0".to_string(),
            });
        }

        // A names tile carries names, not a certificate. There is nothing to
        // build the full, lite or v2 payloads from, so asking for both is a
        // configuration that cannot be satisfied rather than one to satisfy
        // partially.
        if self.ct_log.names_tiles == NamesTiles::Prefer {
            if self.streams.full || self.streams.lite || self.streams.v2 {
                errors.push(ConfigValidationError {
                    field: "ct_log.names_tiles".to_string(),
                    message:
                        "`prefer` needs domains_only to be the only enabled stream; names tiles \
                         carry no certificate to build the full, lite or v2 payloads from"
                            .to_string(),
                });
            }
            // The durable output publishes v2 records, which a names entry
            // cannot produce. Accepting both would run a server that reports
            // JetStream as enabled while every names-serving log silently
            // published nothing and never advanced its saved position.
            if self.nats.enabled {
                errors.push(ConfigValidationError {
                    field: "ct_log.names_tiles".to_string(),
                    message: "`prefer` cannot be combined with nats.enabled; names tiles carry no \
                              certificate, so there is no durable record to publish"
                        .to_string(),
                });
            }
        }

        if self.has_tls() {
            if let Some(ref cert) = self.tls_cert
                && !Path::new(cert).exists()
            {
                errors.push(ConfigValidationError {
                    field: "tls_cert".to_string(),
                    message: format!("TLS certificate file not found: {}", cert),
                });
            }
            if let Some(ref key) = self.tls_key
                && !Path::new(key).exists()
            {
                errors.push(ConfigValidationError {
                    field: "tls_key".to_string(),
                    message: format!("TLS key file not found: {}", key),
                });
            }
        }

        if self.connection_limit.enabled && self.connection_limit.max_connections == 0 {
            errors.push(ConfigValidationError {
                field: "connection_limit.max_connections".to_string(),
                message: "Max connections must be greater than 0 when enabled".to_string(),
            });
        }

        if self.rate_limit.enabled && self.rate_limit.refill_rate <= 0.0 {
            errors.push(ConfigValidationError {
                field: "rate_limit.refill_rate".to_string(),
                message: "Refill rate must be positive".to_string(),
            });
        }

        if self.ct_log.start_overlap_leaves > MAX_START_OVERLAP_LEAVES {
            errors.push(ConfigValidationError {
                field: "ct_log.start_overlap_leaves".to_string(),
                message: format!(
                    "Start overlap must be at most {} leaves",
                    MAX_START_OVERLAP_LEAVES
                ),
            });
        }

        if self.ct_log.partial_tile_wait_secs > MAX_PARTIAL_TILE_WAIT_SECS {
            errors.push(ConfigValidationError {
                field: "ct_log.partial_tile_wait_secs".to_string(),
                message: format!(
                    "Partial tile wait must be at most {} seconds",
                    MAX_PARTIAL_TILE_WAIT_SECS
                ),
            });
        }

        if self.ct_log.fetch_concurrency == 0 || self.ct_log.fetch_concurrency > 16 {
            errors.push(ConfigValidationError {
                field: "ct_log.fetch_concurrency".to_string(),
                message: "Fetch concurrency must be between 1 and 16".to_string(),
            });
        }
        if let Some(ua) = self.ct_log.user_agent_override()
            && reqwest::header::HeaderValue::try_from(ua).is_err()
        {
            errors.push(ConfigValidationError {
                field: "ct_log.user_agent".to_string(),
                message: "User-Agent must be a valid HTTP header value".to_string(),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn load_yaml() -> YamlConfigWithPath {
        let config_paths = [
            env::var("CERTSTREAM_CONFIG").ok(),
            Some("config.yaml".to_string()),
            Some("config.yml".to_string()),
            Some("/etc/certstream/config.yaml".to_string()),
        ];

        for path in config_paths.into_iter().flatten() {
            if Path::new(&path).exists()
                && let Ok(content) = fs::read_to_string(&path)
            {
                match serde_yaml::from_str::<YamlConfig>(&content) {
                    Ok(config) => {
                        return YamlConfigWithPath {
                            config,
                            path: Some(path),
                        };
                    }
                    Err(e) => {
                        eprintln!("WARNING: failed to parse {}: {}", path, e);
                    }
                }
            }
        }

        YamlConfigWithPath {
            config: YamlConfig::default(),
            path: None,
        }
    }

    pub fn has_tls(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            host: "0.0.0.0".parse().unwrap(),
            port: 8080,
            log_level: "info".to_string(),
            buffer_size: 1000,
            tls_cert: None,
            tls_key: None,
            custom_logs: vec![],
            static_logs: vec![],
            protocols: ProtocolConfig::default(),
            ct_log: CtLogConfig::default(),
            connection_limit: ConnectionLimitConfig::default(),
            trusted_proxies: Vec::new(),
            rate_limit: RateLimitConfig::default(),
            api: ApiConfig::default(),
            auth: AuthConfig::default(),
            hot_reload: HotReloadConfig::default(),
            nats: NatsConfig::default(),
            streams: StreamConfig::default(),
            dedup: DedupConfig::default(),
            config_path: None,
        }
    }

    #[test]
    fn test_default_state_file() {
        let val = default_state_file();
        assert_eq!(val, Some("certstream_state.json".to_string()));
    }

    #[test]
    fn test_ct_log_config_defaults() {
        let config = CtLogConfig::default();
        assert_eq!(config.retry_max_attempts, 3);
        assert_eq!(config.retry_initial_delay_ms, 1000);
        assert_eq!(config.retry_max_delay_ms, 30000);
        assert_eq!(config.request_timeout_secs, 30);
        assert_eq!(config.healthy_threshold, 2);
        assert_eq!(config.unhealthy_threshold, 5);
        assert_eq!(config.health_check_interval_secs, 60);
        assert_eq!(config.state_file, Some("certstream_state.json".to_string()));
        assert_eq!(config.batch_size, 1024);
        assert_eq!(config.poll_interval_ms, 1000);
        assert_eq!(config.fetch_concurrency, 4);
        assert_eq!(config.partial_tile_wait_secs, 60);
        assert_eq!(config.start_overlap_leaves, 256);
        assert!(config.rfc6962_enabled);
        assert!(config.static_ct_enabled);
        assert!(config.user_agent.is_none());
    }

    #[test]
    fn test_ct_log_config_deserialize_user_agent() {
        let yaml = r#"
user_agent: "certstream-server-rust/1.5.3 (contact@example.com)"
"#;
        let config: CtLogConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            config.user_agent.as_deref(),
            Some("certstream-server-rust/1.5.3 (contact@example.com)")
        );
    }

    #[test]
    fn test_blank_user_agent_falls_back_to_default() {
        // `CERTSTREAM_USER_AGENT=` in a compose file reads back as Ok(""), and
        // an empty User-Agent header is worse than the default one.
        for blank in ["", "   ", "\t"] {
            let config = CtLogConfig {
                user_agent: Some(blank.to_string()),
                ..CtLogConfig::default()
            };
            assert_eq!(config.user_agent_override(), None, "blank: {blank:?}");
        }
    }

    #[test]
    fn test_user_agent_override_is_trimmed() {
        let config = CtLogConfig {
            user_agent: Some("  certstream/1.0 (me@example.com)  ".to_string()),
            ..CtLogConfig::default()
        };
        assert_eq!(
            config.user_agent_override(),
            Some("certstream/1.0 (me@example.com)")
        );
    }

    #[test]
    fn test_validate_blank_user_agent_is_not_an_error() {
        let config = Config {
            ct_log: CtLogConfig {
                user_agent: Some("  ".to_string()),
                ..CtLogConfig::default()
            },
            ..test_config()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_operator_list_drops_blanks_and_trims() {
        assert_eq!(
            parse_operator_list("DigiCert, Geomys"),
            vec!["DigiCert".to_string(), "Geomys".to_string()]
        );
        assert_eq!(
            parse_operator_list("digicert,, ,geomys,"),
            vec!["digicert".to_string(), "geomys".to_string()]
        );
        assert!(parse_operator_list("").is_empty());
        assert!(parse_operator_list("  ,  ").is_empty());
    }

    #[test]
    fn test_ct_log_config_deserialize_force_http1_operators() {
        let yaml = r#"
force_http1_operators:
  - DigiCert
  - Geomys
"#;
        let config: CtLogConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.force_http1_operators, vec!["DigiCert", "Geomys"]);
    }

    #[test]
    fn test_validate_user_agent_invalid_header() {
        let config = Config {
            ct_log: CtLogConfig {
                user_agent: Some("bad\nuser-agent".to_string()),
                ..CtLogConfig::default()
            },
            ..test_config()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "ct_log.user_agent"));
    }

    #[test]
    fn test_ct_log_config_disable_flags() {
        let yaml = r#"
rfc6962_enabled: false
static_ct_enabled: false
"#;
        let config: CtLogConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.rfc6962_enabled);
        assert!(!config.static_ct_enabled);
    }

    #[test]
    fn test_static_log_tree_size_source_parses_and_defaults() {
        let yaml = r#"
name: "TrustAsia log2026a"
url: "https://ct2026-a.trustasia.com/log2026a"
tree_size_source: get_sth
"#;
        let log: StaticCtLog = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(log.tree_size_source, TreeSizeSource::GetSth);

        // Omitting it must keep the signed-checkpoint path: opting out of
        // verification has to be written down explicitly.
        let yaml = r#"
name: "LE Sycamore"
url: "https://mon.sycamore.ct.letsencrypt.org/2026h1/"
"#;
        let log: StaticCtLog = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(log.tree_size_source, TreeSizeSource::Checkpoint);
    }

    #[test]
    fn test_protocol_config_defaults() {
        let config = ProtocolConfig::default();
        assert!(config.websocket);
        assert!(!config.sse);
        assert!(config.metrics);
        assert!(config.health);
        assert!(config.example_json);
        assert!(!config.api);
    }

    #[test]
    fn test_protocol_config_yaml_omitting_sse_keeps_it_disabled() {
        // SSE is opt-in, like the REST API. A `protocols:` block that omits
        // `sse` goes through the serde field default rather than
        // `ProtocolConfig::default()`; the two are separate code paths, and
        // the docs claimed SSE was on by default while both of them said
        // otherwise, so pin the behaviour here.
        let yaml = "websocket: true\napi: true\n";
        let config: ProtocolConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.sse);
        assert!(config.api);
    }

    #[test]
    fn test_connection_limit_config_defaults() {
        let config = ConnectionLimitConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_connections, 10000);
        assert!(config.per_ip_limit.is_none());
    }

    #[test]
    fn test_auth_config_defaults() {
        let config = AuthConfig::default();
        assert!(!config.enabled);
        assert!(config.tokens.is_empty());
        assert_eq!(config.header_name, "Authorization");
    }

    #[test]
    fn test_static_ct_log_deserialize() {
        let yaml = r#"
name: "Test Log"
url: "https://test.example.com/log/"
"#;
        let log: StaticCtLog = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(log.name, "Test Log");
        assert_eq!(log.url, "https://test.example.com/log/");
        assert!(log.expected_log_id.is_none());
        assert!(log.batch_size.is_none());
        assert!(log.poll_interval_ms.is_none());
    }

    #[test]
    fn test_custom_ct_log_deserialize() {
        let yaml = r#"
name: "Custom Log"
url: "https://custom.example.com/ct"
"#;
        let log: CustomCtLog = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(log.name, "Custom Log");
        assert_eq!(log.url, "https://custom.example.com/ct");
        assert!(log.expected_log_id.is_none());
        assert!(log.batch_size.is_none());
        assert!(log.poll_interval_ms.is_none());
    }

    #[test]
    fn test_custom_ct_log_deserialize_overrides() {
        let yaml = r#"
name: "Custom Log"
url: "https://custom.example.com/ct"
expected_log_id: "custom-log-id"
batch_size: 128
poll_interval_ms: 2500
"#;
        let log: CustomCtLog = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(log.expected_log_id.as_deref(), Some("custom-log-id"));
        assert_eq!(log.batch_size, Some(128));
        assert_eq!(log.poll_interval_ms, Some(2500));
    }

    #[test]
    fn test_static_ct_log_deserialize_overrides() {
        let yaml = r#"
name: "Static Log"
url: "https://static.example.com/log/"
log_origin: "static.example.com/log"
expected_log_id: "static-log-id"
batch_size: 64
poll_interval_ms: 3000
"#;
        let log: StaticCtLog = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(log.log_origin.as_deref(), Some("static.example.com/log"));
        assert_eq!(log.expected_log_id.as_deref(), Some("static-log-id"));
        assert_eq!(log.batch_size, Some(64));
        assert_eq!(log.poll_interval_ms, Some(3000));
    }

    #[test]
    fn test_yaml_config_with_static_logs() {
        let yaml = r#"
host: "127.0.0.1"
port: 9090
static_logs:
  - name: "Log A"
    url: "https://a.example.com/"
  - name: "Log B"
    url: "https://b.example.com/"
"#;
        let config: YamlConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.static_logs.len(), 2);
        assert_eq!(config.static_logs[0].name, "Log A");
        assert_eq!(config.static_logs[1].name, "Log B");
    }

    #[test]
    fn test_yaml_config_empty_static_logs() {
        let yaml = r#"
host: "127.0.0.1"
port: 9090
"#;
        let config: YamlConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.static_logs.is_empty());
    }

    #[test]
    fn test_has_tls_both_set() {
        let config = Config {
            tls_cert: Some("cert.pem".to_string()),
            tls_key: Some("key.pem".to_string()),
            ..test_config()
        };
        assert!(config.has_tls());
    }

    #[test]
    fn test_has_tls_none() {
        assert!(!test_config().has_tls());
    }

    #[test]
    fn test_has_tls_partial() {
        let config = Config {
            tls_cert: Some("cert.pem".to_string()),
            ..test_config()
        };
        assert!(!config.has_tls());
    }

    #[test]
    fn test_validate_valid_config() {
        assert!(test_config().validate().is_ok());
    }

    #[test]
    fn test_validate_zero_port() {
        let config = Config { port: 0, ..test_config() };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "port"));
    }

    #[test]
    fn test_validate_zero_buffer_size() {
        let config = Config { buffer_size: 0, ..test_config() };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "buffer_size"));
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_tokens, 100.0);
        assert_eq!(config.refill_rate, 10.0);
        assert_eq!(config.burst, 20.0);
        assert_eq!(config.window_seconds, 60);
        assert_eq!(config.window_max_requests, 1000);
    }

    #[test]
    fn test_rate_limit_config_back_compat_aliases() {
        // Legacy YAML using `free_*` keys must still parse so v1.4 configs
        // don't break on upgrade.
        let yaml = "enabled: true\nfree_max_tokens: 42\nfree_refill_rate: 7\nfree_burst: 3\n";
        let cfg: RateLimitConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_tokens, 42.0);
        assert_eq!(cfg.refill_rate, 7.0);
        assert_eq!(cfg.burst, 3.0);
    }

    #[test]
    fn test_ct_log_config_deserialize_with_state_file() {
        let yaml = r#"
retry_max_attempts: 5
state_file: "my_state.json"
batch_size: 512
start_overlap_leaves: 1024
"#;
        let config: CtLogConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.retry_max_attempts, 5);
        assert_eq!(config.state_file, Some("my_state.json".to_string()));
        assert_eq!(config.batch_size, 512);
        assert_eq!(config.start_overlap_leaves, 1024);
        assert_eq!(config.retry_initial_delay_ms, 1000);
    }

    fn names_mode(nats_enabled: bool, streams: StreamConfig) -> Config {
        Config {
            ct_log: CtLogConfig {
                names_tiles: NamesTiles::Prefer,
                ..CtLogConfig::default()
            },
            nats: NatsConfig {
                enabled: nats_enabled,
                ..NatsConfig::default()
            },
            streams,
            ..test_config()
        }
    }

    fn domains_only() -> StreamConfig {
        StreamConfig {
            full: false,
            lite: false,
            domains_only: true,
            v2: false,
        }
    }

    /// A names tile carries no certificate, so the durable output has no v2
    /// record to publish. Accepting the pair would run a server that reports
    /// JetStream as enabled while names-serving logs published nothing.
    #[test]
    fn names_tiles_cannot_be_combined_with_the_durable_output() {
        let Err(errors) = names_mode(true, domains_only()).validate() else {
            panic!("names_tiles + nats must not validate");
        };
        assert!(
            errors
                .iter()
                .any(|e| e.field == "ct_log.names_tiles" && e.message.contains("nats.enabled")),
            "{errors:?}"
        );

        assert!(names_mode(false, domains_only()).validate().is_ok());
    }

    #[test]
    fn names_tiles_requires_domains_only_to_be_the_sole_stream() {
        for streams in [
            StreamConfig { full: true, ..domains_only() },
            StreamConfig { lite: true, ..domains_only() },
            StreamConfig { v2: true, ..domains_only() },
        ] {
            assert!(
                names_mode(false, streams).validate().is_err(),
                "names tiles cannot feed the certificate streams"
            );
        }
    }

    #[test]
    fn test_validate_start_overlap_leaves_bound() {
        let config = Config {
            ct_log: CtLogConfig {
                start_overlap_leaves: MAX_START_OVERLAP_LEAVES + 1,
                ..CtLogConfig::default()
            },
            ..test_config()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field == "ct_log.start_overlap_leaves"));
    }

    #[test]
    fn test_validate_partial_tile_wait_bound() {
        let at = |secs| Config {
            ct_log: CtLogConfig {
                partial_tile_wait_secs: secs,
                ..CtLogConfig::default()
            },
            ..test_config()
        };
        assert!(at(0).validate().is_ok());
        assert!(at(MAX_PARTIAL_TILE_WAIT_SECS).validate().is_ok());
        let errors = at(MAX_PARTIAL_TILE_WAIT_SECS + 1).validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.field == "ct_log.partial_tile_wait_secs"));
    }

    #[test]
    fn test_stream_config_defaults() {
        let config = StreamConfig::default();
        assert!(config.full);
        assert!(config.lite);
        assert!(config.domains_only);
    }

    #[test]
    fn test_stream_config_deserialize_partial() {
        let yaml = r#"
full: false
"#;
        let config: StreamConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.full);
        assert!(config.lite);
        assert!(config.domains_only);
    }

    #[test]
    fn test_stream_config_deserialize_all_disabled() {
        let yaml = r#"
full: false
lite: false
domains_only: false
"#;
        let config: StreamConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.full);
        assert!(!config.lite);
        assert!(!config.domains_only);
    }

    #[test]
    fn test_yaml_config_with_streams() {
        let yaml = r#"
host: "127.0.0.1"
port: 9090
streams:
  full: false
  lite: true
  domains_only: true
"#;
        let config: YamlConfig = serde_yaml::from_str(yaml).unwrap();
        let streams = config.streams.unwrap();
        assert!(!streams.full);
        assert!(streams.lite);
        assert!(streams.domains_only);
    }
}
