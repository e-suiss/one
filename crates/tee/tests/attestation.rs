//! Every vector of `conformance/tee/vectors/attestation.json` over normalized claims, and the trust store against `conformance/tee/trust-roots.toml` (SEC-27, PV-11, T-27 (10), T-57).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::convert::Infallible;

use one_proto::ontology::Instant;
use one_runtime::UnixNanos;
use one_tee::app::{TrustError, trust_node};
use one_tee::domain::attestation::{
    Evidence, GpuEvidence, MinTcb, Policy, Rejection, SnpTcb, Tcb, TdxTcb, verify,
};
use one_tee::domain::roots::{LOCAL_ROOTS, Profile, VENDOR_ROOTS, trust_store};
use one_tee::ports::Attestation;
use one_testkit::VirtualClock;
use serde_json::Value;

fn conformance(path: &str) -> String {
    let full = format!(
        "{}/../../conformance/tee/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(full).unwrap()
}

fn fixed<const N: usize>(v: &Value) -> [u8; N] {
    let s = v.as_str().unwrap();
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn byte(v: &Value) -> u8 {
    u8::try_from(v.as_u64().unwrap()).unwrap()
}

fn text(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn snp(v: &Value) -> SnpTcb {
    SnpTcb {
        bootloader: byte(&v["bootloader"]),
        tee: byte(&v["tee"]),
        snp: byte(&v["snp"]),
        microcode: byte(&v["microcode"]),
    }
}

fn evidence(e: &Value) -> Evidence {
    let tcb = &e["tcb"];
    let tcb = if tcb.get("tee_tcb_svn").is_some() {
        let rtmr: Vec<[u8; 48]> = tcb["rtmr"].as_array().unwrap().iter().map(fixed).collect();
        Tcb::Tdx(Box::new(TdxTcb {
            tee_tcb_svn: fixed(&tcb["tee_tcb_svn"]),
            mrseam: fixed(&tcb["mrseam"]),
            rtmr: rtmr.try_into().unwrap(),
        }))
    } else {
        Tcb::Snp(snp(tcb))
    };
    let gpus = e["gpus"].as_array().map_or_else(Vec::new, |gpus| {
        gpus.iter()
            .map(|g| GpuEvidence {
                vendor: text(&g["vendor"]),
                model: text(&g["model"]),
                cc_mode: text(&g["cc_mode"]),
                measurement: fixed(&g["measurement"]),
                nonce: fixed(&g["nonce"]),
                chain_root: text(&g["chain_root"]),
            })
            .collect()
    });
    Evidence {
        eat_profile: text(&e["eat_profile"]),
        iat: Instant::parse(e["iat"].as_str().unwrap()).unwrap(),
        platform: text(&e["platform"]),
        measurement: fixed(&e["measurement"]),
        tcb,
        report_data: fixed(&e["report_data"]),
        dbgstat: text(&e["dbgstat"]),
        chain_root: text(&e["chain_root"]),
        gpus,
    }
}

struct Owned {
    profile: Profile,
    now: Instant,
    max_age_secs: u64,
    min_tcb: MinTcb,
    log: Vec<[u8; 48]>,
    report_data: [u8; 64],
    gpu_log: Vec<[u8; 48]>,
    gpu_models: Vec<String>,
}

fn owned(p: &Value) -> Owned {
    let min = &p["min_tcb"];
    let list = |v: &Value| -> Vec<[u8; 48]> {
        v.as_array()
            .map_or_else(Vec::new, |a| a.iter().map(fixed).collect())
    };
    Owned {
        profile: match p["profile"].as_str().unwrap() {
            "release" => Profile::Release,
            "dev" => Profile::Dev,
            other => panic!("profile {other}"),
        },
        now: Instant::parse(p["now"].as_str().unwrap()).unwrap(),
        max_age_secs: p["max_age_seconds"].as_u64().unwrap(),
        min_tcb: if min.get("tee_tcb_svn").is_some() {
            MinTcb::Tdx(fixed(&min["tee_tcb_svn"]))
        } else {
            MinTcb::Snp(snp(min))
        },
        log: list(&p["log"]),
        report_data: fixed(&p["expected_report_data"]),
        gpu_log: list(&p["gpu_log"]),
        gpu_models: p["gpu_models"]
            .as_array()
            .map_or_else(Vec::new, |a| a.iter().map(text).collect()),
    }
}

fn check(e: &Evidence, o: &Owned) -> Result<(), Rejection> {
    let models: Vec<&str> = o.gpu_models.iter().map(String::as_str).collect();
    verify(
        e,
        &Policy {
            profile: o.profile,
            now: o.now,
            max_age_secs: o.max_age_secs,
            min_tcb: o.min_tcb,
            log: &o.log,
            expected_report_data: &o.report_data,
            gpu_log: &o.gpu_log,
            gpu_models: &models,
        },
    )
}

fn vectors() -> Vec<Value> {
    serde_json::from_str(&conformance("vectors/attestation.json")).unwrap()
}

#[test]
fn sec_27_attestation_vectors() {
    let mut seen = 0;
    for v in vectors() {
        let d = v["description"].as_str().unwrap();
        let e = evidence(&v["input"]["evidence"]);
        let got = check(&e, &owned(&v["input"]["policy"]));
        if v["expected"]["verified"].as_bool().unwrap() {
            assert_eq!(got, Ok(()), "{d}");
        } else {
            assert_eq!(got.unwrap_err().as_str(), v["expected"]["reason"], "{d}");
        }
        seen += 1;
    }
    assert_eq!(seen, 17);
}

#[test]
fn sec_27_freshness_bound_is_inclusive_and_future_evidence_is_refused() {
    let v = &vectors()[0];
    let mut e = evidence(&v["input"]["evidence"]);
    let mut p = owned(&v["input"]["policy"]);
    p.now = Instant::parse("2026-11-02T01:05:00Z").unwrap();
    assert_eq!(check(&e, &p), Ok(()));
    e.iat = Instant::parse("2026-11-02T01:05:01Z").unwrap();
    assert_eq!(check(&e, &p), Err(Rejection::Stale));
}

#[test]
fn sec_27_a_vendor_root_never_anchors_another_platform() {
    let v = &vectors()[0];
    let mut e = evidence(&v["input"]["evidence"]);
    e.chain_root = "intel-sgx-root-ca".to_owned();
    assert_eq!(
        check(&e, &owned(&v["input"]["policy"])),
        Err(Rejection::UnknownRoot)
    );
    e.chain_root = "nvidia-device-identity-ca".to_owned();
    assert_eq!(
        check(&e, &owned(&v["input"]["policy"])),
        Err(Rejection::UnknownRoot)
    );
}

struct Normalized(Evidence);

impl Attestation for Normalized {
    type Error = Infallible;

    fn normalize(&self, _: &[u8], _: &[Vec<u8>]) -> Result<Evidence, Infallible> {
        Ok(self.0.clone())
    }
}

#[test]
fn sec_27_trust_reads_the_time_from_the_clock_port() {
    let v = &vectors()[0];
    let e = evidence(&v["input"]["evidence"]);
    let o = owned(&v["input"]["policy"]);
    let models: Vec<&str> = Vec::new();
    let policy = Policy {
        profile: o.profile,
        now: Instant::from_unix(0),
        max_age_secs: o.max_age_secs,
        min_tcb: o.min_tcb,
        log: &o.log,
        expected_report_data: &o.report_data,
        gpu_log: &o.gpu_log,
        gpu_models: &models,
    };
    let clock = VirtualClock::new(UnixNanos(
        u128::try_from(o.now.unix_secs()).unwrap() * 1_000_000_000,
    ));
    let port = Normalized(e.clone());
    assert_eq!(trust_node(&clock, &port, &[], &[], &policy), Ok(e));
    assert!(clock.advance(std::time::Duration::from_secs(600)));
    assert_eq!(
        trust_node(&clock, &port, &[], &[], &policy),
        Err(TrustError::Rejected(Rejection::Stale))
    );
}

#[test]
fn t_27_trust_store_matches_trust_roots_toml() {
    let table: toml::Table = conformance("trust-roots.toml").parse().unwrap();
    let theirs: Vec<(String, String, String, Vec<String>)> = table["root"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let s = |k: &str| r[k].as_str().unwrap().to_owned();
            let profiles = r["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_owned())
                .collect();
            (s("id"), s("platform"), s("sha256"), profiles)
        })
        .collect();
    let ours: Vec<(String, String, String, Vec<String>)> = trust_store()
        .map(|r| {
            let profiles = r.profiles.iter().map(|p| p.as_str().to_owned()).collect();
            (
                r.name.to_owned(),
                r.platform.to_owned(),
                r.sha256.to_owned(),
                profiles,
            )
        })
        .collect();
    assert_eq!(ours, theirs);
    let release: Vec<&str> = table["release_profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(release, [Profile::Release.as_str()]);
    assert!(
        VENDOR_ROOTS
            .iter()
            .all(|r| r.profiles.contains(&Profile::Release))
    );
    assert!(
        LOCAL_ROOTS
            .iter()
            .all(|r| !r.profiles.contains(&Profile::Release))
    );
    assert_eq!(Profile::BUILD, Profile::Dev);
}
