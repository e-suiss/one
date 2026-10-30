//! Every vector of `conformance/retention/vectors/expiry.json`: destroy time from the start event and the pinned Access duration, the hourly sweep bound, refusal of local durations and unpinned files, and the six-month sweep floor (PV-16, PV-17, OP-7).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

mod common;

use common::{fixed, load};
use one_keys::domain::retention::{
    DurationSource, RetentionError, RetentionRule, RetentionTable, Sweep, check_pin, destroy,
    sweep_overdue,
};
use one_proto::data_class::RetentionClass;
use one_proto::ontology::{CalendarDuration, Instant};
use serde_json::Value;

fn at(v: &Value) -> Instant {
    Instant::parse(v.as_str().unwrap()).unwrap()
}

fn class(v: &Value) -> RetentionClass {
    RetentionClass::from_name(v.as_str().unwrap()).unwrap()
}

#[test]
fn pv_17_retention_expiry_vectors() {
    let mut seen = 0;
    for v in load("retention/vectors/expiry.json") {
        seen += 1;
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        if let Some(pinned) = input["pinned_sha256"].as_str() {
            let file: [u8; 32] = fixed(input["file_sha256"].as_str().unwrap());
            assert_eq!(
                check_pin(pinned, &file).unwrap_err().as_str(),
                expected["error"],
                "{d}"
            );
            continue;
        }
        if let Some(last) = input.get("last_sweep_at") {
            assert_eq!(
                sweep_overdue(&at(last), &at(&input["now"])),
                expected["sweep_overdue"].as_bool().unwrap(),
                "{d}"
            );
            continue;
        }
        let class = class(&input["class"]);
        if input["duration_source"] == "local" {
            let rule = RetentionRule {
                class,
                start_event: "record_written".to_owned(),
                duration: CalendarDuration::default(),
                source: DurationSource::Local,
                sweep: None,
            };
            let start = Instant::parse("2026-11-02T00:00:00Z").unwrap();
            assert_eq!(
                destroy(&rule, &start).unwrap_err().as_str(),
                expected["error"],
                "{d}"
            );
            continue;
        }
        let start_event = input["start_event"].as_str().unwrap();
        let Some(duration) = input["duration"].as_str() else {
            let err = RetentionTable::default()
                .rule(class, start_event)
                .unwrap_err();
            assert_eq!(err.as_str(), expected["error"], "{d}");
            continue;
        };
        let table = RetentionTable::new(vec![RetentionRule {
            class,
            start_event: start_event.to_owned(),
            duration: CalendarDuration::parse(duration).unwrap(),
            source: DurationSource::PinnedAccessFile,
            sweep: (input["sweep"] == "hourly").then_some(Sweep::Hourly),
        }]);
        assert_eq!(
            table.rule(class, "another_event"),
            Err(RetentionError::NoAppendixCEntry)
        );
        let out = destroy(
            table.rule(class, start_event).unwrap(),
            &at(&input["start_at"]),
        )
        .unwrap();
        assert_eq!(out.at, at(&expected["destroy_at"]), "{d}");
        if let Some(by) = expected.get("destroy_by") {
            assert_eq!(out.by, at(by), "{d}");
        }
        if let Some(method) = expected.get("method") {
            assert_eq!(out.method.as_str(), method, "{d}");
        }
    }
    assert_eq!(seen, 8);
}

#[test]
fn op_7_binding_pins_the_access_file_and_names_every_class() {
    let path = format!(
        "{}/../../conformance/retention/binding.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let pinned = text
        .lines()
        .find_map(|l| l.strip_prefix("sha256 = \""))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap();
    assert!(check_pin(pinned, &[0; 32]).is_err());
    for c in RetentionClass::ALL {
        assert!(
            text.contains(&format!("name = \"{}\"", c.as_str())),
            "{}",
            c.as_str()
        );
    }
}
