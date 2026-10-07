//! Optional durable output to NATS JetStream.
//!
//! The use this exists for: "I took my analysis service down for ten minutes;
//! when it comes back it should carry on from where it stopped." A WebSocket
//! subscriber cannot do that — a stream it is not connected to is a stream it
//! misses. A JetStream consumer can.
//!
//! Publishing alone would buy little, so three things go with it:
//!
//! * **The saved position follows acknowledgements, not reads.** A watcher
//!   that has read to entry N but had only entries up to M acknowledged
//!   persists M, so a restart re-reads `M..N` rather than skipping it.
//!   [`AckTracker`] keeps those two positions apart, and advances only over a
//!   contiguous prefix — an index that produced no record has to be settled
//!   explicitly or it pins the position where it is.
//!
//! * **Republished records carry a stable identity.** The `Nats-Msg-Id` is
//!   `<log_id>:<index>`, the same address the v2 output uses, so a re-read
//!   after a restart is deduplicated by the server inside its duplicate
//!   window instead of appearing twice.
//!
//! * **A full stream has a stated behaviour.** The stream is created with
//!   `discard: new`, so it rejects the write rather than deleting records a
//!   stopped consumer had not read. `on_full` decides what happens next:
//!   `block` retries the record until the server stores it and lets the queue
//!   behind it push back on ingest, `drop` gives up on the record and settles
//!   its index so the position can move past it.
//!
//! What this does **not** provide: delivery is at-least-once within the
//! server's own reading, not exactly-once end to end. A record `drop` mode
//! gave up on is gone, and cross-log duplicates of one certificate are
//! published as the separate log records they are.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::{self, stream::DiscardPolicy};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::{NatsConfig, NatsOnFull};

/// One record on its way to JetStream.
pub struct Record {
    /// Log the entry came from, as a state-file key.
    pub log_url: Arc<str>,
    /// Stable identity: `<log_id>:<index>`, or `<url>:<index>` for a log
    /// whose list entry carries no id.
    pub msg_id: String,
    /// Where in the log this entry sits. Drives the acknowledged position.
    pub index: u64,
    pub subject: String,
    pub payload: bytes::Bytes,
}

/// Per-log gap between what has been read and what JetStream has confirmed.
///
/// The saved position must be the *contiguous* acknowledged prefix, not the
/// highest acknowledged index: acknowledgements can land out of order, and
/// persisting a high index with a hole below it would skip the hole forever.
#[derive(Default)]
pub struct AckTracker {
    logs: Mutex<HashMap<Arc<str>, LogAcks>>,
}

#[derive(Default)]
struct LogAcks {
    /// Everything strictly below this is acknowledged.
    contiguous: u64,
    /// Acknowledged indexes at or above `contiguous`, waiting on the gap
    /// below them to close.
    ahead: std::collections::BTreeSet<u64>,
    /// Ranges the watcher chose never to read, as start -> end (exclusive),
    /// waiting for the prefix to reach their start.
    skipped: std::collections::BTreeMap<u64, u64>,
    started: bool,
}

impl LogAcks {
    fn advance(&mut self) {
        loop {
            if self.ahead.remove(&self.contiguous) {
                self.contiguous += 1;
            } else if let Some(end) = self.skipped.remove(&self.contiguous) {
                self.contiguous = end;
            } else {
                break;
            }
        }
    }
}

impl AckTracker {
    /// Anchor a log's acknowledged position, from the state file at startup
    /// or from a watcher's starting index the first time it reads a log with
    /// no saved position.
    ///
    /// Without an anchor the contiguous prefix would start at 0 while the
    /// watcher publishes from the log's head, so nothing would ever close the
    /// gap and every save would write index 0 — rewinding the log to the
    /// beginning on the next restart. Only the first anchor counts; a later
    /// call cannot move a log that is already running.
    pub fn resume_at(&self, log_url: &str, index: u64) {
        let mut logs = self.logs.lock();
        let entry = logs.entry(Arc::from(log_url)).or_default();
        if !entry.started {
            entry.contiguous = index;
            entry.started = true;
        }
    }

    /// An index JetStream has stored.
    pub fn record_ack(&self, log_url: &Arc<str>, index: u64) {
        self.settle(log_url, index);
    }

    /// An index that will never be published, and so must not hold the
    /// position back.
    ///
    /// A watcher does not publish every index it reads: an entry it cannot
    /// parse produces no record. Without this the contiguous prefix would stop
    /// at the first such index forever, pinning the saved position and letting
    /// every later acknowledgement pile up unresolved.
    pub fn record_skipped(&self, log_url: &Arc<str>, index: u64) {
        self.settle(log_url, index);
    }

    fn settle(&self, log_url: &Arc<str>, index: u64) {
        let mut logs = self.logs.lock();
        let entry = logs.entry(Arc::clone(log_url)).or_default();
        entry.started = true;

        if index < entry.contiguous {
            return;
        }
        entry.ahead.insert(index);
        entry.advance();
    }

    /// Indexes `from..to` a catch-up jump skipped, never to be published. The
    /// prefix passes them only once everything below `from` is acknowledged.
    pub fn record_skipped_range(&self, log_url: &Arc<str>, from: u64, to: u64) {
        let mut logs = self.logs.lock();
        let entry = logs.entry(Arc::clone(log_url)).or_default();
        entry.started = true;

        if to <= entry.contiguous {
            return;
        }
        entry.skipped.insert(from.max(entry.contiguous), to);
        entry.advance();
    }

    /// The position it is safe to persist for this log.
    pub fn acked_index(&self, log_url: &str) -> Option<u64> {
        let logs = self.logs.lock();
        logs.get(log_url)
            .filter(|acks| acks.started)
            .map(|acks| acks.contiguous)
    }

    pub fn pending(&self) -> usize {
        self.logs.lock().values().map(|a| a.ahead.len()).sum()
    }
}

/// Handle the watchers hold. Cheap to clone; the work happens in the
/// publisher task.
#[derive(Clone)]
pub struct NatsSink {
    tx: mpsc::Sender<Record>,
    on_full: NatsOnFull,
    pub acks: Arc<AckTracker>,
}

impl NatsSink {
    /// Queue a record. Returns false when the record was dropped rather than
    /// queued, which only happens under `on_full: drop`.
    ///
    /// Under `block` this waits for room. That back-pressure is the point: the
    /// publisher retries the record at the head of the queue until the server
    /// stores it, so a queue that fills is ingest being told to slow down
    /// rather than records being lost.
    pub async fn publish(&self, record: Record) -> bool {
        match self.on_full {
            NatsOnFull::Block => self.tx.send(record).await.is_ok(),
            NatsOnFull::Drop => match self.tx.try_send(record) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    metrics::counter!("certstream_nats_dropped_total").increment(1);
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
        }
    }
}

/// Connect, ensure the stream exists, and start the publisher task.
pub async fn start(
    config: &NatsConfig,
    cancel: CancellationToken,
) -> Result<NatsSink, async_nats::Error> {
    let client = async_nats::ConnectOptions::new()
        .name(concat!("certstream-server-rust/", env!("CARGO_PKG_VERSION")))
        .connect(&config.url)
        .await?;
    let context = jetstream::new(client);

    let stream_config = jetstream::stream::Config {
        name: config.stream.clone(),
        subjects: vec![format!("{}.>", config.subject_prefix)],
        max_bytes: config.max_bytes,
        // The whole point of the durable path: a full stream must refuse the
        // write so the publisher finds out, not quietly delete the oldest
        // records a stopped consumer had not read yet.
        discard: DiscardPolicy::New,
        duplicate_window: Duration::from_secs(config.duplicate_window_secs),
        ..Default::default()
    };
    let stream = context.get_or_create_stream(stream_config).await?;
    let info = stream.cached_info();
    info!(
        stream = %config.stream,
        subject = %format!("{}.>", config.subject_prefix),
        max_bytes = config.max_bytes,
        duplicate_window_secs = config.duplicate_window_secs,
        messages = info.state.messages,
        "NATS JetStream output enabled"
    );

    let (tx, rx) = mpsc::channel(config.queue_depth);
    let acks = Arc::new(AckTracker::default());
    spawn_publisher(context, rx, Arc::clone(&acks), config.clone(), cancel);

    Ok(NatsSink {
        tx,
        on_full: config.on_full,
        acks,
    })
}

fn spawn_publisher(
    context: jetstream::Context,
    mut rx: mpsc::Receiver<Record>,
    acks: Arc<AckTracker>,
    config: NatsConfig,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let timeout = Duration::from_secs(config.publish_timeout_secs);
        loop {
            let record = tokio::select! {
                _ = cancel.cancelled() => break,
                record = rx.recv() => match record {
                    Some(r) => r,
                    None => break,
                },
            };

            let mut attempt: u32 = 0;
            loop {
                match store(&context, &record, timeout).await {
                    Ok(()) => {
                        acks.record_ack(&record.log_url, record.index);
                        metrics::counter!("certstream_nats_published_total").increment(1);
                        break;
                    }
                    Err(reason) => {
                        metrics::counter!("certstream_nats_publish_failures_total").increment(1);
                        if cancel.is_cancelled() {
                            break;
                        }
                        if config.on_full == NatsOnFull::Drop {
                            warn!(msg_id = %record.msg_id, reason, "record dropped");
                            metrics::counter!("certstream_nats_dropped_total").increment(1);
                            // The index still has to settle, or it pins the
                            // saved position at a record this mode chose not
                            // to keep.
                            acks.record_skipped(&record.log_url, record.index);
                            break;
                        }

                        // `block` means this record is retried until it is
                        // stored. The queue behind it fills, and that
                        // back-pressure reaches ingest — which is the point:
                        // giving up here would leave a hole no restart can
                        // see, because the saved position never passes it.
                        attempt = attempt.saturating_add(1);
                        let backoff = retry_delay(attempt);
                        warn!(
                            msg_id = %record.msg_id,
                            reason,
                            attempt,
                            retry_in_ms = backoff.as_millis() as u64,
                            "JetStream did not store the record; retrying"
                        );
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                    }
                }
            }
        }
        info!(pending = acks.pending(), "NATS publisher stopped");
    });
}

/// One publish attempt: send, then wait for the server to say it stored it.
async fn store(
    context: &jetstream::Context,
    record: &Record,
    timeout: Duration,
) -> Result<(), String> {
    let mut headers = async_nats::HeaderMap::new();
    // Stable across republishes, so a re-read after a restart is the same
    // message to the server rather than a second one.
    headers.insert("Nats-Msg-Id", record.msg_id.as_str());

    let future = context
        .publish_with_headers(record.subject.clone(), headers, record.payload.clone())
        .await
        .map_err(|e| e.to_string())?;

    match tokio::time::timeout(timeout, future.into_future()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("ack timed out".to_string()),
    }
}

/// Exponential backoff, capped. A full stream or a broker outage lasts
/// minutes, not milliseconds, and retrying faster than that only burns the
/// connection.
fn retry_delay(attempt: u32) -> Duration {
    const BASE_MS: u64 = 250;
    const MAX_MS: u64 = 30_000;
    Duration::from_millis(BASE_MS.saturating_mul(1 << attempt.min(7)).min(MAX_MS))
}

/// Log an unrecoverable startup problem in the same shape as the rest of the
/// server's fatal paths.
pub fn report_start_failure(e: &async_nats::Error) {
    error!(error = %e, "could not start the NATS JetStream output");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_with(url: &str, resume: u64) -> (AckTracker, Arc<str>) {
        let tracker = AckTracker::default();
        tracker.resume_at(url, resume);
        (tracker, Arc::from(url))
    }

    /// The property the whole module exists for: what gets saved is what was
    /// acknowledged, not what was read.
    #[test]
    fn the_acked_position_is_the_contiguous_prefix() {
        let (tracker, url) = tracker_with("https://log.example", 0);

        for index in 0..5 {
            tracker.record_ack(&url, index);
        }
        assert_eq!(tracker.acked_index("https://log.example"), Some(5));
    }

    /// Acks land out of order. Persisting the highest one would step over the
    /// hole below it, and the hole would never be re-read.
    #[test]
    fn a_hole_holds_the_position_back_until_it_closes() {
        let (tracker, url) = tracker_with("https://log.example", 0);

        tracker.record_ack(&url, 0);
        tracker.record_ack(&url, 1);
        tracker.record_ack(&url, 3);
        tracker.record_ack(&url, 4);
        assert_eq!(
            tracker.acked_index("https://log.example"),
            Some(2),
            "entry 2 is unacknowledged; the position must not pass it"
        );
        assert_eq!(tracker.pending(), 2);

        tracker.record_ack(&url, 2);
        assert_eq!(tracker.acked_index("https://log.example"), Some(5));
        assert_eq!(tracker.pending(), 0);
    }

    /// Without the anchor, a log read from its head would never close the gap
    /// down to zero, and every save would write index 0.
    #[test]
    fn a_resumed_log_starts_from_its_saved_position() {
        let (tracker, url) = tracker_with("https://log.example", 1_000);
        assert_eq!(tracker.acked_index("https://log.example"), Some(1000));

        tracker.record_ack(&url, 1000);
        tracker.record_ack(&url, 1001);
        assert_eq!(tracker.acked_index("https://log.example"), Some(1002));

        // A late ack from below the resume point changes nothing.
        tracker.record_ack(&url, 12);
        assert_eq!(tracker.acked_index("https://log.example"), Some(1002));
    }

    #[test]
    fn resuming_twice_does_not_move_a_log_that_is_already_running() {
        let (tracker, url) = tracker_with("https://log.example", 100);
        tracker.record_ack(&url, 100);
        tracker.resume_at("https://log.example", 5);
        assert_eq!(tracker.acked_index("https://log.example"), Some(101));
    }

    #[test]
    fn a_log_with_no_acks_and_no_resume_has_no_position() {
        let tracker = AckTracker::default();
        assert_eq!(tracker.acked_index("https://never-seen.example"), None);
    }

    /// A watcher starting a log with no saved position anchors at its own
    /// starting index. Acknowledging from there must advance the position
    /// rather than leave it pinned at zero.
    #[test]
    fn a_log_read_from_its_head_advances_from_that_head() {
        let head = 45_949_247;
        let (tracker, url) = tracker_with("https://fresh.example", head);

        for offset in 0..3 {
            tracker.record_ack(&url, head + offset);
        }
        assert_eq!(tracker.acked_index("https://fresh.example"), Some(head + 3));
    }

    /// The gap the live dedup and parse failures leave. A watcher does not
    /// publish every index it reads; if an unpublished index never settles,
    /// the position stops there and every later acknowledgement accumulates.
    #[test]
    fn an_index_that_is_never_published_does_not_pin_the_position() {
        let (tracker, url) = tracker_with("https://log.example", 100);

        tracker.record_ack(&url, 100);
        // 101 produced no record at all.
        tracker.record_skipped(&url, 101);
        for index in 102..1102 {
            tracker.record_ack(&url, index);
        }

        assert_eq!(
            tracker.acked_index("https://log.example"),
            Some(1102),
            "a settled skip must let the prefix close over it"
        );
        assert_eq!(
            tracker.pending(),
            0,
            "nothing should be left waiting behind the skip"
        );
    }

    /// Without the skip, this is exactly the failure: the position sticks and
    /// the later acknowledgements are retained indefinitely.
    #[test]
    fn an_unsettled_index_is_what_pins_the_position() {
        let (tracker, url) = tracker_with("https://log.example", 100);

        tracker.record_ack(&url, 100);
        for index in 102..1102 {
            tracker.record_ack(&url, index);
        }

        assert_eq!(tracker.acked_index("https://log.example"), Some(101));
        assert_eq!(tracker.pending(), 1000);
    }

    #[test]
    fn retry_backoff_grows_and_is_capped() {
        assert!(retry_delay(1) < retry_delay(4));
        assert_eq!(retry_delay(20), retry_delay(30), "must reach a ceiling");
        assert!(retry_delay(30) <= Duration::from_secs(30));
    }

    /// With everything before it acknowledged, the position moves over a skipped range at once.
    #[test]
    fn a_skipped_range_closes_when_nothing_is_pending_below_it() {
        let (tracker, url) = tracker_with("https://log.example", 100);
        for index in 100..110 {
            tracker.record_ack(&url, index);
        }

        tracker.record_skipped_range(&url, 110, 5_000);
        assert_eq!(tracker.acked_index("https://log.example"), Some(5_000));

        tracker.record_ack(&url, 5_000);
        assert_eq!(tracker.acked_index("https://log.example"), Some(5_001));
    }

    /// Records read before the jump may still be in flight: the position stays
    /// below them, so a restart re-reads them, and passes the range once stored.
    #[test]
    fn a_skipped_range_waits_for_unacknowledged_records_below_it() {
        let (tracker, url) = tracker_with("https://log.example", 100);
        tracker.record_ack(&url, 100);
        tracker.record_ack(&url, 102);

        tracker.record_skipped_range(&url, 103, 5_000);
        tracker.record_ack(&url, 5_000);
        assert_eq!(
            tracker.acked_index("https://log.example"),
            Some(101),
            "entry 101 is unacknowledged; the position must not pass it"
        );

        tracker.record_ack(&url, 101);
        assert_eq!(tracker.acked_index("https://log.example"), Some(5_001));
        assert_eq!(tracker.pending(), 0);
    }

    #[test]
    fn a_skipped_range_already_behind_the_position_changes_nothing() {
        let (tracker, url) = tracker_with("https://log.example", 100);
        tracker.record_skipped_range(&url, 50, 100);
        assert_eq!(tracker.acked_index("https://log.example"), Some(100));
    }

    /// Logs must not share a position.
    #[test]
    fn positions_are_tracked_per_log() {
        let tracker = AckTracker::default();
        tracker.resume_at("https://a.example", 0);
        tracker.resume_at("https://b.example", 0);
        let a: Arc<str> = Arc::from("https://a.example");
        let b: Arc<str> = Arc::from("https://b.example");

        tracker.record_ack(&a, 0);
        tracker.record_ack(&a, 1);
        tracker.record_ack(&b, 0);

        assert_eq!(tracker.acked_index("https://a.example"), Some(2));
        assert_eq!(tracker.acked_index("https://b.example"), Some(1));
    }
}
