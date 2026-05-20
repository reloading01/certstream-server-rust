#![no_main]

// Fuzz target: feed arbitrary bytes to the tile-leaf parser. Adversarial
// tile data (corrupt CDN response, malicious mirror) must surface as a
// truncated `Vec<TileLeaf>` rather than a panic — the static-CT watcher
// loop calls this on every fetched tile.
//
// Run:
//   cargo +nightly fuzz run parse_tile_leaves -- -max_total_time=60

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = certstream_server_rust::ct::static_ct::parse_tile_leaves(data);
});
