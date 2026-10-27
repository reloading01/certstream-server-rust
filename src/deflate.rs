//! Shared-context permessage-deflate (RFC 7692) for the WebSocket fan-out.
//!
//! Standard permessage-deflate keeps one compressor per connection, so its
//! CPU cost grows with the subscriber count. Here each stream format is
//! compressed once, by one task, and every negotiating subscriber is sent the
//! same bytes. The compressors are reset every [`EPOCH`] messages. A
//! subscriber starts at a reset, and after losing messages waits for the next
//! one: from a reset on, the compressed stream refers to nothing it has not
//! received, which is the only thing its decompressor's window has to agree
//! with.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use flate2::{Compress, Compression, FlushCompress};
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tracing::{debug, info};

use crate::models::PreSerializedMessage;

/// Messages between compressor resets. Longer epochs compress better and make
/// a joining or recovering subscriber wait longer. 128 is about 0.25 s of the
/// public stream and within 3% of never resetting (measured on 60 s of live
/// lite traffic: 288 B/msg against 281 B/msg).
pub const EPOCH: u64 = 128;

/// The value of `Sec-WebSocket-Extensions` in the 101 response.
pub const EXTENSION_RESPONSE: &str = "permessage-deflate";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Full = 0,
    Lite = 1,
    DomainsOnly = 2,
    V2 = 3,
}

/// One broadcast message, compressed. A payload is empty when the format had
/// nothing to send or nobody negotiated compression for it.
#[derive(Debug)]
pub struct DeflatedMessage {
    /// The compressors were reset just before this message.
    pub boundary: bool,
    payloads: [Bytes; 4],
}

impl DeflatedMessage {
    pub fn payload(&self, format: Format) -> &Bytes {
        &self.payloads[format as usize]
    }
}

/// Whether the client's `Sec-WebSocket-Extensions` offers can be answered with
/// [`EXTENSION_RESPONSE`].
///
/// Only offers that let the server keep its context between messages are
/// accepted, with the default 15-bit window: that is what the shared stream
/// is compressed with. A client asking for `server_no_context_takeover` or a
/// smaller server window gets the uncompressed stream instead.
pub fn negotiate<'a>(header_values: impl IntoIterator<Item = &'a str>) -> bool {
    header_values
        .into_iter()
        .flat_map(|value| value.split(','))
        .any(acceptable_offer)
}

fn acceptable_offer(offer: &str) -> bool {
    let mut parts = offer.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("permessage-deflate"))
    {
        return false;
    }
    parts.all(|param| {
        let (name, value) = match param.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
            None => (param, None),
        };
        match name.to_ascii_lowercase().as_str() {
            // Governs what the client compresses with; the server only sends.
            "client_max_window_bits" | "client_no_context_takeover" => true,
            "server_max_window_bits" => value == Some("15"),
            _ => false,
        }
    })
}

/// Compresses the broadcast stream in channel order.
struct Encoder {
    compressors: [Compress; 4],
    since_reset: u64,
    reset_pending: bool,
}

impl Encoder {
    fn new() -> Self {
        Self {
            compressors: std::array::from_fn(|_| Compress::new(Compression::default(), false)),
            since_reset: 0,
            reset_pending: true,
        }
    }

    /// Make the next message a boundary, for when the stream lost messages
    /// before they could be compressed.
    fn reset_next(&mut self) {
        self.reset_pending = true;
    }

    /// `active[f]` says whether format `f` has a compressing subscriber.
    /// Every compressor is reset at a boundary whether or not it is active,
    /// so a subscriber that starts there finds its format in a known state.
    fn encode(&mut self, msg: &PreSerializedMessage, active: [bool; 4]) -> DeflatedMessage {
        let boundary = self.reset_pending || self.since_reset >= EPOCH;
        if boundary {
            for c in &mut self.compressors {
                c.reset();
            }
            self.since_reset = 0;
            self.reset_pending = false;
        }
        self.since_reset += 1;

        let sources = [&msg.full, &msg.lite, &msg.domains_only, &msg.v2];
        let payloads = std::array::from_fn(|i| {
            if active[i] && !sources[i].is_empty() {
                deflate(&mut self.compressors[i], sources[i].as_bytes())
            } else {
                Bytes::new()
            }
        });
        DeflatedMessage { boundary, payloads }
    }
}

/// One message as a permessage-deflate payload: the input followed by a sync
/// flush, minus the `00 00 ff ff` tail RFC 7692 has the sender drop.
fn deflate(c: &mut Compress, input: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(input.len() / 2 + 64);
    let start = c.total_in();
    loop {
        let consumed = (c.total_in() - start) as usize;
        c.compress_vec(&input[consumed..], &mut out, FlushCompress::Sync)
            .expect("in-memory deflate cannot fail");
        if (c.total_in() - start) as usize == input.len() && out.len() < out.capacity() {
            break;
        }
        out.reserve(out.capacity().max(64));
    }
    debug_assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
    out.truncate(out.len() - 4);
    Bytes::from(out)
}

/// Owns the shared compressors and the task that runs them.
///
/// Like the filter dispatcher, the task exists only while a compressing
/// subscriber does, so it never holds the main channel's receiver count above
/// zero on an idle server.
pub struct DeflateHub {
    source: broadcast::Sender<Arc<PreSerializedMessage>>,
    out: broadcast::Sender<Arc<DeflatedMessage>>,
    dispatching: Mutex<bool>,
    seats: [AtomicUsize; 4],
}

/// A compressing subscriber. Holding it keeps its format compressed.
pub struct Seat {
    hub: Arc<DeflateHub>,
    format: Format,
    pub rx: broadcast::Receiver<Arc<DeflatedMessage>>,
}

impl Drop for Seat {
    fn drop(&mut self) {
        self.hub.seats[self.format as usize].fetch_sub(1, Ordering::Relaxed);
    }
}

impl DeflateHub {
    pub fn new(source: broadcast::Sender<Arc<PreSerializedMessage>>, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            source,
            out: broadcast::channel(capacity).0,
            dispatching: Mutex::new(false),
            seats: Default::default(),
        })
    }

    pub fn subscribe(self: &Arc<Self>, format: Format) -> Seat {
        let mut dispatching = self.dispatching.lock();
        self.seats[format as usize].fetch_add(1, Ordering::Relaxed);
        let seat = Seat {
            hub: Arc::clone(self),
            format,
            rx: self.out.subscribe(),
        };
        if !*dispatching {
            *dispatching = true;
            self.clone().spawn_dispatcher();
        }
        seat
    }

    fn spawn_dispatcher(self: Arc<Self>) {
        let mut rx = self.source.subscribe();
        tokio::spawn(async move {
            debug!("deflate dispatcher started");
            let mut encoder = Encoder::new();
            loop {
                let msg = match rx.recv().await {
                    Ok(msg) => msg,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        metrics::counter!("certstream_deflate_dispatch_lagged").increment(n);
                        encoder.reset_next();
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };

                // Checked again under the lock so a subscriber arriving now
                // either sees the dispatcher running or starts a new one.
                if self.out.receiver_count() == 0 {
                    let mut dispatching = self.dispatching.lock();
                    if self.out.receiver_count() == 0 {
                        *dispatching = false;
                        break;
                    }
                }

                let active = std::array::from_fn(|i| self.seats[i].load(Ordering::Relaxed) > 0);
                let _ = self.out.send(Arc::new(encoder.encode(&msg, active)));
            }
            info!("deflate dispatcher stopped");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Decompress, FlushDecompress};
    use tokio_tungstenite::tungstenite::Utf8Bytes;

    fn msg(i: usize) -> PreSerializedMessage {
        let lite = format!(
            r#"{{"message_type":"certificate_update","data":{{"leaf_cert":{{"all_domains":["host{i}.example.com","www.host{i}.example.com"],"issuer":{{"O":"Let's Encrypt","CN":"R1{}"}}}},"cert_index":{}}}}}"#,
            i % 3,
            1000 + i
        );
        PreSerializedMessage {
            full: Utf8Bytes::from_static(""),
            lite: Utf8Bytes::from(lite),
            domains_only: Utf8Bytes::from(format!(r#"{{"message_type":"dns_entries","data":["host{i}.example.com"]}}"#)),
            v2: Utf8Bytes::from_static(""),
            leaf: None,
        }
    }

    /// What a client's decompressor does with one message.
    fn inflate(d: &mut Decompress, payload: &[u8]) -> String {
        let mut input = payload.to_vec();
        input.extend_from_slice(&[0, 0, 0xff, 0xff]);
        let mut out = Vec::with_capacity(input.len() * 8 + 1024);
        let start = d.total_in();
        loop {
            let consumed = (d.total_in() - start) as usize;
            d.decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync).unwrap();
            if (d.total_in() - start) as usize == input.len() && out.len() < out.capacity() {
                break;
            }
            out.reserve(out.capacity());
        }
        String::from_utf8(out).unwrap()
    }

    /// A subscriber that joins mid-epoch and one that loses messages both
    /// decode every message they accept, byte for byte.
    #[test]
    fn subscribers_decode_from_a_boundary_after_joining_or_losing_messages() {
        let originals: Vec<_> = (0..700).map(msg).collect();
        let mut encoder = Encoder::new();
        let encoded: Vec<_> = originals
            .iter()
            .map(|m| encoder.encode(m, [false, true, true, false]))
            .collect();

        for (format, pick) in [
            (Format::Lite, (|m: &PreSerializedMessage| m.lite.to_string()) as fn(&_) -> _),
            (Format::DomainsOnly, |m: &PreSerializedMessage| m.domains_only.to_string()),
        ] {
            let mut d = Decompress::new(false);
            let mut synced = false;
            let mut decoded = 0;
            for (i, (original, enc)) in originals.iter().zip(&encoded).enumerate() {
                // Joins at message 50; misses 300..=310 as a lagging client would.
                if i < 50 || (300..=310).contains(&i) {
                    synced = false;
                    continue;
                }
                if enc.boundary {
                    synced = true;
                }
                if !synced {
                    continue;
                }
                assert_eq!(inflate(&mut d, enc.payload(format)), pick(original), "message {i}");
                decoded += 1;
            }
            // 128..300 after joining, then 384..700 after the loss.
            assert_eq!(decoded, (300 - 128) + (700 - 384), "{format:?}");
        }
    }

    #[test]
    fn boundaries_fall_every_epoch_and_after_a_reset_request() {
        let mut encoder = Encoder::new();
        let m = msg(0);
        let boundaries: Vec<_> = (0..300)
            .map(|i| {
                if i == 200 {
                    encoder.reset_next();
                }
                encoder.encode(&m, [false, true, false, false]).boundary
            })
            .collect();
        let at: Vec<_> = boundaries.iter().enumerate().filter(|(_, b)| **b).map(|(i, _)| i).collect();
        assert_eq!(at, vec![0, 128, 200]);
    }

    #[test]
    fn inactive_formats_are_left_empty() {
        let mut encoder = Encoder::new();
        let out = encoder.encode(&msg(1), [false, false, true, false]);
        assert!(out.payload(Format::Lite).is_empty());
        assert!(!out.payload(Format::DomainsOnly).is_empty());
    }

    #[test]
    fn negotiation_accepts_offers_the_shared_stream_can_honour() {
        assert!(negotiate(["permessage-deflate"]));
        assert!(negotiate(["permessage-deflate; client_max_window_bits"]));
        assert!(negotiate(["permessage-deflate; client_max_window_bits=12; client_no_context_takeover"]));
        assert!(negotiate(["permessage-deflate; server_max_window_bits=15"]));
        assert!(negotiate(["x-webkit-deflate-frame", "permessage-deflate"]));
        assert!(negotiate(["permessage-deflate; server_max_window_bits=10, permessage-deflate"]));
    }

    #[test]
    fn negotiation_rejects_offers_that_need_a_per_connection_compressor() {
        assert!(!negotiate([] as [&str; 0]));
        assert!(!negotiate(["permessage-deflate; server_no_context_takeover"]));
        assert!(!negotiate(["permessage-deflate; server_max_window_bits=10"]));
        assert!(!negotiate(["permessage-deflate; something_new"]));
        assert!(!negotiate(["x-webkit-deflate-frame"]));
    }
}

