//! The local attestation simulator (T-27 (10), T-42 (3)): a report is a tagged `COSE_Sign1` over the `dCBOR` claims of `conformance/tee/attestation-evidence.cddl` without `chain` and `raw_report`, signed with `Ed25519` by the simulator root, whose seed is SHA-256 of a public label; only builds with debug assertions compile it and only the `dev` trust store holds its root, so a release client never trusts a simulated node.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use one_proto::ontology::Instant;
use suiss_crypto::aws::AwsLcBackend;
use suiss_crypto::cose::{self, Algorithm, KeySet, PublicKey};
use suiss_crypto::dcbor::{self, COSE_SIGN1_TAG, Limits, Value};

use crate::domain::attestation::{Evidence, GpuEvidence, SnpTcb, Tcb, TdxTcb};
use crate::ports::Attestation;

/// The trust store name of the simulator root.
pub const ROOT_NAME: &str = "one-tee-simulator";

/// The label whose SHA-256 is the simulator root's `Ed25519` seed.
pub const SEED_LABEL: &[u8] = b"one/tee/simulator/root/v1";

/// The content type of a simulated report.
pub const CONTENT_TYPE: &str = "application/one-tee-evidence+cbor";

const ALG: u64 = 1;
const CONTENT_TYPE_LABEL: u64 = 3;
const KID: u64 = 4;

const CLAIMS: [&str; 8] = [
    "eat_profile",
    "iat",
    "platform",
    "measurement",
    "tcb",
    "report_data",
    "dbgstat",
    "gpus",
];
const SNP: [&str; 4] = ["bootloader", "tee", "snp", "microcode"];
const TDX: [&str; 3] = ["tee_tcb_svn", "mrseam", "rtmr"];
const GPU: [&str; 5] = ["vendor", "model", "cc_mode", "measurement", "nonce"];

/// Why a simulated report was not made or did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SimulatorError {
    /// The signature does not verify under the simulator root, or the envelope is malformed.
    Signature,
    /// The claims do not match the evidence shape.
    Claims,
    /// A simulated report carries no certificate chain.
    Chain,
    /// The root key could not be made.
    Key,
}

/// The simulator root key, from its public seed.
fn root_key() -> Result<Ed25519KeyPair, SimulatorError> {
    let seed = digest(&SHA256, SEED_LABEL);
    Ed25519KeyPair::from_seed_unchecked(seed.as_ref()).map_err(|_| SimulatorError::Key)
}

fn public(key: &Ed25519KeyPair) -> Result<[u8; 32], SimulatorError> {
    key.public_key()
        .as_ref()
        .try_into()
        .map_err(|_| SimulatorError::Key)
}

fn thumbprint(public: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest(&SHA256, public).as_ref());
    out
}

/// The simulator root's SHA-256, the value `trust-roots.toml` pins.
///
/// # Errors
/// [`SimulatorError::Key`].
pub fn root_sha256() -> Result<[u8; 32], SimulatorError> {
    Ok(thumbprint(&public(&root_key()?)?))
}

/// The signing side: a local node's simulated report.
pub struct Simulator {
    key: Ed25519KeyPair,
    kid: [u8; 32],
}

impl Simulator {
    /// The simulator with its root key.
    ///
    /// # Errors
    /// [`SimulatorError::Key`].
    pub fn new() -> Result<Self, SimulatorError> {
        let key = root_key()?;
        let kid = thumbprint(&public(&key)?);
        Ok(Self { key, kid })
    }

    /// A report over `evidence`; its `chain_root` is not encoded, since the verifier names the root it checked.
    ///
    /// # Errors
    /// [`SimulatorError::Claims`] when the claims do not encode.
    pub fn report(&self, evidence: &Evidence) -> Result<Vec<u8>, SimulatorError> {
        let limits = Limits::CEILING;
        let protected = dcbor::encode(
            &Value::Map(vec![
                (Value::Unsigned(ALG), Value::int(Algorithm::Ed25519.cose())),
                (
                    Value::Unsigned(CONTENT_TYPE_LABEL),
                    Value::text(CONTENT_TYPE),
                ),
                (Value::Unsigned(KID), Value::Bytes(self.kid.to_vec())),
            ]),
            limits,
        )
        .map_err(|_| SimulatorError::Claims)?;
        let payload =
            dcbor::encode(&claims(evidence)?, limits).map_err(|_| SimulatorError::Claims)?;
        let signature = self.key.sign(&cose::to_be_signed(&protected, &payload));
        let message = Value::Tag(
            COSE_SIGN1_TAG,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(Vec::new()),
                Value::Bytes(payload),
                Value::Bytes(signature.as_ref().to_vec()),
            ])),
        );
        dcbor::encode(&message, limits).map_err(|_| SimulatorError::Claims)
    }
}

/// The verifying side: the `Attestation` adapter for simulated reports, holding only the root's public key.
pub struct SimulatorRoot {
    keys: KeySet,
}

impl SimulatorRoot {
    /// The adapter with the simulator root.
    ///
    /// # Errors
    /// [`SimulatorError::Key`].
    pub fn new() -> Result<Self, SimulatorError> {
        let public = public(&root_key()?)?;
        let mut keys = KeySet::default();
        keys.insert(thumbprint(&public), PublicKey::Ed25519(public))
            .map_err(|_| SimulatorError::Key)?;
        keys.allowed.insert(Algorithm::Ed25519);
        Ok(Self { keys })
    }
}

impl Attestation for SimulatorRoot {
    type Error = SimulatorError;

    fn normalize(&self, raw_report: &[u8], chain: &[Vec<u8>]) -> Result<Evidence, Self::Error> {
        if !chain.is_empty() {
            return Err(SimulatorError::Chain);
        }
        let verified = cose::verify_sign1(&AwsLcBackend, raw_report, &self.keys, CONTENT_TYPE)
            .map_err(|_| SimulatorError::Signature)?;
        let value = dcbor::decode(&verified.payload, Limits::CEILING)
            .map_err(|_| SimulatorError::Claims)?;
        evidence(&value)
    }
}

fn entry(key: &str, value: Value) -> (Value, Value) {
    (Value::text(key), value)
}

fn claims(e: &Evidence) -> Result<Value, SimulatorError> {
    let iat = u64::try_from(e.iat.unix_secs()).map_err(|_| SimulatorError::Claims)?;
    let tcb = match &e.tcb {
        Tcb::Snp(t) => Value::Map(vec![
            entry("bootloader", Value::Unsigned(t.bootloader.into())),
            entry("tee", Value::Unsigned(t.tee.into())),
            entry("snp", Value::Unsigned(t.snp.into())),
            entry("microcode", Value::Unsigned(t.microcode.into())),
        ]),
        Tcb::Tdx(t) => Value::Map(vec![
            entry("tee_tcb_svn", Value::Bytes(t.tee_tcb_svn.to_vec())),
            entry("mrseam", Value::Bytes(t.mrseam.to_vec())),
            entry(
                "rtmr",
                Value::Array(t.rtmr.iter().map(|r| Value::Bytes(r.to_vec())).collect()),
            ),
        ]),
    };
    let mut map = vec![
        entry("eat_profile", Value::text(&e.eat_profile)),
        entry("iat", Value::Unsigned(iat)),
        entry("platform", Value::text(&e.platform)),
        entry("measurement", Value::Bytes(e.measurement.to_vec())),
        entry("tcb", tcb),
        entry("report_data", Value::Bytes(e.report_data.to_vec())),
        entry("dbgstat", Value::text(&e.dbgstat)),
    ];
    if !e.gpus.is_empty() {
        let gpus = e
            .gpus
            .iter()
            .map(|g| {
                Value::Map(vec![
                    entry("vendor", Value::text(&g.vendor)),
                    entry("model", Value::text(&g.model)),
                    entry("cc_mode", Value::text(&g.cc_mode)),
                    entry("measurement", Value::Bytes(g.measurement.to_vec())),
                    entry("nonce", Value::Bytes(g.nonce.to_vec())),
                ])
            })
            .collect();
        map.push(entry("gpus", Value::Array(gpus)));
    }
    Ok(Value::Map(map))
}

fn closed(value: &Value, keys: &[&str]) -> Result<(), SimulatorError> {
    let Value::Map(entries) = value else {
        return Err(SimulatorError::Claims);
    };
    let known = entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if keys.contains(&t.as_str())));
    if known {
        Ok(())
    } else {
        Err(SimulatorError::Claims)
    }
}

fn get<'a>(value: &'a Value, key: &str) -> Result<&'a Value, SimulatorError> {
    value.get(key).ok_or(SimulatorError::Claims)
}

fn text(value: &Value, key: &str) -> Result<String, SimulatorError> {
    match get(value, key)? {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(SimulatorError::Claims),
    }
}

fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], SimulatorError> {
    match value {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| SimulatorError::Claims),
        _ => Err(SimulatorError::Claims),
    }
}

fn byte(value: &Value, key: &str) -> Result<u8, SimulatorError> {
    match get(value, key)? {
        Value::Unsigned(n) => u8::try_from(*n).map_err(|_| SimulatorError::Claims),
        _ => Err(SimulatorError::Claims),
    }
}

fn tcb(value: &Value) -> Result<Tcb, SimulatorError> {
    if value.get("tee_tcb_svn").is_some() {
        closed(value, &TDX)?;
        let Value::Array(rtmr) = get(value, "rtmr")? else {
            return Err(SimulatorError::Claims);
        };
        let rtmr: Vec<[u8; 48]> = rtmr.iter().map(fixed::<48>).collect::<Result<_, _>>()?;
        Ok(Tcb::Tdx(Box::new(TdxTcb {
            tee_tcb_svn: fixed(get(value, "tee_tcb_svn")?)?,
            mrseam: fixed(get(value, "mrseam")?)?,
            rtmr: rtmr.try_into().map_err(|_| SimulatorError::Claims)?,
        })))
    } else {
        closed(value, &SNP)?;
        Ok(Tcb::Snp(SnpTcb {
            bootloader: byte(value, "bootloader")?,
            tee: byte(value, "tee")?,
            snp: byte(value, "snp")?,
            microcode: byte(value, "microcode")?,
        }))
    }
}

fn gpu(value: &Value) -> Result<GpuEvidence, SimulatorError> {
    closed(value, &GPU)?;
    Ok(GpuEvidence {
        vendor: text(value, "vendor")?,
        model: text(value, "model")?,
        cc_mode: text(value, "cc_mode")?,
        measurement: fixed(get(value, "measurement")?)?,
        nonce: fixed(get(value, "nonce")?)?,
        chain_root: ROOT_NAME.to_owned(),
    })
}

fn evidence(value: &Value) -> Result<Evidence, SimulatorError> {
    closed(value, &CLAIMS)?;
    let Value::Unsigned(iat) = get(value, "iat")? else {
        return Err(SimulatorError::Claims);
    };
    let iat = i64::try_from(*iat).map_err(|_| SimulatorError::Claims)?;
    let gpus = match value.get("gpus") {
        None => Vec::new(),
        Some(Value::Array(gpus)) if !gpus.is_empty() => {
            gpus.iter().map(gpu).collect::<Result<_, _>>()?
        }
        Some(_) => return Err(SimulatorError::Claims),
    };
    Ok(Evidence {
        eat_profile: text(value, "eat_profile")?,
        iat: Instant::from_unix(iat),
        platform: text(value, "platform")?,
        measurement: fixed(get(value, "measurement")?)?,
        tcb: tcb(get(value, "tcb")?)?,
        report_data: fixed(get(value, "report_data")?)?,
        dbgstat: text(value, "dbgstat")?,
        chain_root: ROOT_NAME.to_owned(),
        gpus,
    })
}
