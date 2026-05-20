#![no_main]

// Fuzz target: feed arbitrary bytes to `parse_certificate` and assert it
// never panics. Certificate Transparency tiles are externally-served binary
// data; a corrupted or maliciously crafted DER blob must produce `None`, not
// a process panic that the supervisor restart loop would mask.
//
// Run:
//   cargo +nightly fuzz run parse_certificate
//   cargo +nightly fuzz run parse_certificate -- -max_total_time=60

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both `is_leaf` paths should be panic-safe.
    let _ = certstream_server_rust::ct::parse_certificate(data, true);
    let _ = certstream_server_rust::ct::parse_certificate(data, false);
});
