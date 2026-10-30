//! The claim checks over normalized evidence (`conformance/tee/attestation-evidence.cddl`): EAT profile, CPU platform, a root of this build's store for the profile, freshness, debug off, measurement in the public log, TCB at least the minimum, `report_data` binding the node key, and every GPU admitted, in CC mode, logged and chained to its vendor root (SEC-27, PV-11, T-57).

use one_proto::ontology::Instant;

use super::roots::{Profile, SIMULATOR_PLATFORM, root};

/// The EAT profile of One TEE evidence.
pub const EAT_PROFILE: &str = "tag:suiss.app,2026:one/tee/eat/v1";

/// The CPU platforms a node may run on.
pub const CPU_PLATFORMS: [&str; 2] = ["amd-sev-snp", "intel-tdx"];

/// The platform of a GPU root.
pub const GPU_PLATFORM: &str = "nvidia-cc";

/// The debug states that count as off.
pub const DEBUG_OFF: [&str; 2] = ["disabled-since-boot", "disabled-permanently"];

/// An SEV-SNP TCB version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnpTcb {
    /// Boot loader SVN.
    pub bootloader: u8,
    /// PSP OS SVN.
    pub tee: u8,
    /// SNP firmware SVN.
    pub snp: u8,
    /// Microcode SVN.
    pub microcode: u8,
}

impl SnpTcb {
    /// Whether every component is at least `min`'s.
    #[must_use]
    pub const fn at_least(&self, min: &Self) -> bool {
        self.bootloader >= min.bootloader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
    }
}

/// A TDX TCB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TdxTcb {
    /// The TEE TCB SVN, one SVN per byte.
    pub tee_tcb_svn: [u8; 16],
    /// The TDX module measurement.
    pub mrseam: [u8; 48],
    /// The runtime measurement registers.
    pub rtmr: [[u8; 48]; 4],
}

/// The TCB of a report.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tcb {
    /// SEV-SNP.
    Snp(SnpTcb),
    /// TDX.
    Tdx(Box<TdxTcb>),
}

/// The lowest TCB a policy accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MinTcb {
    /// SEV-SNP.
    Snp(SnpTcb),
    /// TDX: the lowest TEE TCB SVN, per byte.
    Tdx([u8; 16]),
}

impl Tcb {
    /// Whether the TCB meets `min`; a minimum for the other platform is never met.
    #[must_use]
    pub fn at_least(&self, min: &MinTcb) -> bool {
        match (self, min) {
            (Self::Snp(t), MinTcb::Snp(m)) => t.at_least(m),
            (Self::Tdx(t), MinTcb::Tdx(m)) => t.tee_tcb_svn.iter().zip(m).all(|(a, b)| a >= b),
            _ => false,
        }
    }
}

/// The evidence of one GPU in CC mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuEvidence {
    /// The vendor.
    pub vendor: String,
    /// The model.
    pub model: String,
    /// The confidential computing mode.
    pub cc_mode: String,
    /// The GPU firmware and driver measurement.
    pub measurement: [u8; 48],
    /// The nonce of the GPU report.
    pub nonce: [u8; 32],
    /// The root its certificate chain verified to.
    pub chain_root: String,
}

/// Evidence after the `Attestation` port verified its signatures and chain and normalized its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The EAT profile.
    pub eat_profile: String,
    /// When the report was issued.
    pub iat: Instant,
    /// The CPU platform.
    pub platform: String,
    /// The TEE image measurement.
    pub measurement: [u8; 48],
    /// The TCB.
    pub tcb: Tcb,
    /// The report data: the node key digest, zero padded.
    pub report_data: [u8; 64],
    /// The debug state.
    pub dbgstat: String,
    /// The root the CPU report's chain verified to.
    pub chain_root: String,
    /// The GPUs.
    pub gpus: Vec<GpuEvidence>,
}

/// What a client or job accepts.
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    /// The trust store profile.
    pub profile: Profile,
    /// The current time, read through the `Clock` port.
    pub now: Instant,
    /// The oldest evidence accepted, in seconds.
    pub max_age_secs: u64,
    /// The lowest TCB accepted.
    pub min_tcb: MinTcb,
    /// The measurements of the public TEE image log (T-57).
    pub log: &'a [[u8; 48]],
    /// The report data the node key binds: its digest, zero padded.
    pub expected_report_data: &'a [u8; 64],
    /// The GPU measurements of the public log.
    pub gpu_log: &'a [[u8; 48]],
    /// The GPU models admitted.
    pub gpu_models: &'a [&'a str],
}

/// Why evidence is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// Another EAT profile.
    UnknownEatProfile,
    /// A CPU platform other than SEV-SNP and TDX.
    UnknownPlatform,
    /// The chain ends at a root this build's store does not hold for the platform.
    UnknownRoot,
    /// The chain ends at a root outside the policy's profile.
    DevRootInRelease,
    /// The evidence is older than the bound, or from the future.
    Stale,
    /// The guest is debuggable.
    DebugEnabled,
    /// The measurement is not in the public log.
    MeasurementNotInLog,
    /// The TCB is below the minimum.
    TcbBelowMinimum,
    /// The report data does not carry the node key digest.
    ReportDataMismatch,
    /// A GPU model is not admitted.
    GpuModelNotAdmitted,
    /// A GPU is not in CC mode.
    GpuCcOff,
    /// A GPU measurement is not in the public log.
    GpuMeasurementNotInLog,
}

impl Rejection {
    /// The reason as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownEatProfile => "unknown_eat_profile",
            Self::UnknownPlatform => "unknown_platform",
            Self::UnknownRoot => "unknown_root",
            Self::DevRootInRelease => "dev_root_in_release",
            Self::Stale => "stale",
            Self::DebugEnabled => "debug_enabled",
            Self::MeasurementNotInLog => "measurement_not_in_log",
            Self::TcbBelowMinimum => "tcb_below_minimum",
            Self::ReportDataMismatch => "report_data_mismatch",
            Self::GpuModelNotAdmitted => "gpu_model_not_admitted",
            Self::GpuCcOff => "gpu_cc_off",
            Self::GpuMeasurementNotInLog => "gpu_measurement_not_in_log",
        }
    }
}

fn check_root(name: &str, platform: &str, profile: Profile) -> Result<(), Rejection> {
    let root = root(name).ok_or(Rejection::UnknownRoot)?;
    if root.platform != platform && root.platform != SIMULATOR_PLATFORM {
        return Err(Rejection::UnknownRoot);
    }
    if !root.profiles.contains(&profile) {
        return Err(Rejection::DevRootInRelease);
    }
    Ok(())
}

/// Checks normalized evidence against a policy.
///
/// # Errors
/// The first [`Rejection`] that applies.
pub fn verify(evidence: &Evidence, policy: &Policy<'_>) -> Result<(), Rejection> {
    if evidence.eat_profile != EAT_PROFILE {
        return Err(Rejection::UnknownEatProfile);
    }
    if !CPU_PLATFORMS.contains(&evidence.platform.as_str()) {
        return Err(Rejection::UnknownPlatform);
    }
    check_root(&evidence.chain_root, &evidence.platform, policy.profile)?;
    let age = policy.now.since(&evidence.iat).ok_or(Rejection::Stale)?;
    if age.secs > policy.max_age_secs || (age.secs == policy.max_age_secs && age.nanos > 0) {
        return Err(Rejection::Stale);
    }
    if !DEBUG_OFF.contains(&evidence.dbgstat.as_str()) {
        return Err(Rejection::DebugEnabled);
    }
    if !policy.log.contains(&evidence.measurement) {
        return Err(Rejection::MeasurementNotInLog);
    }
    if !evidence.tcb.at_least(&policy.min_tcb) {
        return Err(Rejection::TcbBelowMinimum);
    }
    if &evidence.report_data != policy.expected_report_data {
        return Err(Rejection::ReportDataMismatch);
    }
    for gpu in &evidence.gpus {
        if gpu.vendor != "nvidia" || !policy.gpu_models.contains(&gpu.model.as_str()) {
            return Err(Rejection::GpuModelNotAdmitted);
        }
        if gpu.cc_mode != "on" {
            return Err(Rejection::GpuCcOff);
        }
        if !policy.gpu_log.contains(&gpu.measurement) {
            return Err(Rejection::GpuMeasurementNotInLog);
        }
        check_root(&gpu.chain_root, GPU_PLATFORM, policy.profile)?;
    }
    Ok(())
}
