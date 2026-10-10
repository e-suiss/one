//! The leak scanner never panics and is deterministic on arbitrary input (SEC-6, T-41 (2)).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let line = String::from_utf8_lossy(data);
    let first = one_telemetry::leak::scan(&line);
    let second = one_telemetry::leak::scan(&line);
    assert_eq!(first, second);
});
