//! The attestation simulator: its root digest is the one `trust-roots.toml` pins, a simulated report verifies and normalizes back to the claims it was made from and admits the node key it binds in the `dev` store, while a release policy, a modified report or a chain is refused, and a request sealed to the admitted node opens inside it (T-27 (10), T-42 (3), SEC-27, PV-11).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::format_collect,
    reason = "T-38"
)]

use one_hpke::{Kem, KeyPair, report_data};
use one_proto::ontology::Instant;
use one_runtime::UnixNanos;
use one_tee::app::{TrustError, trust_node};
use one_tee::channel::{AttestedNode, open_request, route_aad, seal_request};
use one_tee::domain::attestation::{
    EAT_PROFILE, Evidence, GpuEvidence, MinTcb, Policy, Rejection, SnpTcb, Tcb, TdxTcb,
};
use one_tee::domain::roots::{Profile, root};
use one_tee::ports::Attestation;
use one_tee::simulator::{ROOT_NAME, Simulator, SimulatorError, SimulatorRoot, root_sha256};
use one_testkit::VirtualClock;

const NOW: i64 = 1_793_491_200;
const MEASUREMENT: [u8; 48] = [7; 48];
const GPU_MEASUREMENT: [u8; 48] = [9; 48];
const ZERO: SnpTcb = SnpTcb {
    bootloader: 0,
    tee: 0,
    snp: 0,
    microcode: 0,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn evidence(report: [u8; 64]) -> Evidence {
    Evidence {
        eat_profile: EAT_PROFILE.to_owned(),
        iat: Instant::from_unix(NOW),
        platform: "amd-sev-snp".to_owned(),
        measurement: MEASUREMENT,
        tcb: Tcb::Snp(SnpTcb {
            bootloader: 3,
            tee: 0,
            snp: 22,
            microcode: 213,
        }),
        report_data: report,
        dbgstat: "disabled-since-boot".to_owned(),
        chain_root: ROOT_NAME.to_owned(),
        gpus: vec![GpuEvidence {
            vendor: "nvidia".to_owned(),
            model: "h100".to_owned(),
            cc_mode: "on".to_owned(),
            measurement: GPU_MEASUREMENT,
            nonce: [5; 32],
            chain_root: ROOT_NAME.to_owned(),
        }],
    }
}

fn policy<'a>(profile: Profile, log: &'a [[u8; 48]], gpu_log: &'a [[u8; 48]]) -> Policy<'a> {
    Policy {
        profile,
        now: Instant::from_unix(NOW),
        max_age_secs: 300,
        min_tcb: MinTcb::Snp(ZERO),
        log,
        expected_report_data: &[0; 64],
        gpu_log,
        gpu_models: &["h100", "h200"],
    }
}

fn clock() -> VirtualClock {
    VirtualClock::new(UnixNanos(u128::try_from(NOW).unwrap() * 1_000_000_000))
}

#[test]
fn t_27_the_simulator_root_is_the_pinned_dev_root() {
    let pinned = root(ROOT_NAME).unwrap();
    assert_eq!(hex(&root_sha256().unwrap()), pinned.sha256);
    assert_eq!(pinned.profiles, [Profile::Dev]);
}

#[test]
fn t_27_a_simulated_report_normalizes_to_its_claims() {
    let node = KeyPair::generate(Kem::X25519).unwrap();
    let public = node.public_key().unwrap();
    let claims = evidence(report_data(&public));
    let raw = Simulator::new().unwrap().report(&claims).unwrap();
    let port = SimulatorRoot::new().unwrap();
    assert_eq!(port.normalize(&raw, &[]).unwrap(), claims);

    let mut tdx = evidence(report_data(&public));
    tdx.platform = "intel-tdx".to_owned();
    tdx.tcb = Tcb::Tdx(Box::new(TdxTcb {
        tee_tcb_svn: [1; 16],
        mrseam: [2; 48],
        rtmr: [[3; 48]; 4],
    }));
    tdx.gpus.clear();
    let raw = Simulator::new().unwrap().report(&tdx).unwrap();
    assert_eq!(port.normalize(&raw, &[]).unwrap(), tdx);
}

#[test]
fn sec_27_a_simulated_node_is_trusted_only_in_the_dev_store() {
    let node = KeyPair::generate(Kem::X25519).unwrap();
    let public = node.public_key().unwrap();
    let raw = Simulator::new()
        .unwrap()
        .report(&evidence(report_data(&public)))
        .unwrap();
    let port = SimulatorRoot::new().unwrap();
    let log = [MEASUREMENT];
    let gpu_log = [GPU_MEASUREMENT];
    let dev = policy(Profile::Dev, &log, &gpu_log);
    let release = policy(Profile::Release, &log, &gpu_log);
    let trusted = trust_node(
        &clock(),
        &port,
        &raw,
        &[],
        &Policy {
            expected_report_data: &report_data(&public),
            ..dev
        },
    )
    .unwrap();
    assert_eq!(
        trust_node(
            &clock(),
            &port,
            &raw,
            &[],
            &Policy {
                expected_report_data: &report_data(&public),
                ..release
            }
        ),
        Err(TrustError::Rejected(Rejection::DevRootInRelease))
    );
    assert_eq!(
        AttestedNode::admit(&public, &trusted, &release),
        Err(one_tee::channel::ChannelError::NotAttested(
            Rejection::DevRootInRelease
        ))
    );

    let attested = AttestedNode::admit(&public, &trusted, &dev).unwrap();
    let aad = route_aad("memory.recall");
    let (request, _) = seal_request(&attested, &aad, b"what did I promise on friday").unwrap();
    let (plain, _) = open_request(&node, &request, &aad).unwrap();
    assert_eq!(plain.as_slice(), b"what did I promise on friday");

    let other = KeyPair::generate(Kem::X25519)
        .unwrap()
        .public_key()
        .unwrap();
    assert_eq!(
        AttestedNode::admit(&other, &trusted, &dev),
        Err(one_tee::channel::ChannelError::NotAttested(
            Rejection::ReportDataMismatch
        ))
    );
}

#[test]
fn sec_27_a_modified_or_chained_report_is_refused() {
    let claims = evidence([1; 64]);
    let raw = Simulator::new().unwrap().report(&claims).unwrap();
    let port = SimulatorRoot::new().unwrap();
    for i in [4, raw.len() / 2, raw.len() - 1] {
        let mut bad = raw.clone();
        bad[i] ^= 1;
        assert!(port.normalize(&bad, &[]).is_err(), "byte {i}");
    }
    assert_eq!(
        port.normalize(&raw, &[vec![0x30]]),
        Err(SimulatorError::Chain)
    );
    assert_eq!(
        port.normalize(b"not a report", &[]),
        Err(SimulatorError::Signature)
    );
}
