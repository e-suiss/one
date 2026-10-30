//! The attestation trust store of `conformance/tee/trust-roots.toml`: vendor roots in every build, the local simulator root only in builds with debug assertions, so a release build carries vendor roots alone (T-27 (10), T-42 (3), SEC-27).

/// A build profile of the trust store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// A release build: vendor roots only.
    Release,
    /// A local build: vendor roots and the simulator root.
    Dev,
}

impl Profile {
    /// The profile of this build: [`Profile::Release`] without debug assertions.
    pub const BUILD: Self = if cfg!(debug_assertions) {
        Self::Dev
    } else {
        Self::Release
    };

    /// The profile as `trust-roots.toml` writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Dev => "dev",
        }
    }
}

/// A pinned root certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustRoot {
    /// The root name the normalized evidence gives as `chain_root`.
    pub name: &'static str,
    /// The platform whose reports chain to it.
    pub platform: &'static str,
    /// The lower-case hex SHA-256 of the root certificate, or `pending`.
    pub sha256: &'static str,
    /// The profiles whose store holds the root.
    pub profiles: &'static [Profile],
}

/// The platform of the simulator root, which signs reports of any CPU platform.
pub const SIMULATOR_PLATFORM: &str = "simulator";

/// The vendor roots, in every build.
pub const VENDOR_ROOTS: &[TrustRoot] = &[
    TrustRoot {
        name: "amd-ark-milan",
        platform: "amd-sev-snp",
        sha256: "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
        profiles: &[Profile::Release, Profile::Dev],
    },
    TrustRoot {
        name: "amd-ark-genoa",
        platform: "amd-sev-snp",
        sha256: "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
        profiles: &[Profile::Release, Profile::Dev],
    },
    TrustRoot {
        name: "amd-ark-turin",
        platform: "amd-sev-snp",
        sha256: "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
        profiles: &[Profile::Release, Profile::Dev],
    },
    TrustRoot {
        name: "intel-sgx-root-ca",
        platform: "intel-tdx",
        sha256: "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3",
        profiles: &[Profile::Release, Profile::Dev],
    },
    TrustRoot {
        name: "nvidia-device-identity-ca",
        platform: "nvidia-cc",
        sha256: "pending",
        profiles: &[Profile::Release, Profile::Dev],
    },
];

/// The local roots, only in builds with debug assertions.
#[cfg(debug_assertions)]
pub const LOCAL_ROOTS: &[TrustRoot] = &[TrustRoot {
    name: "one-tee-simulator",
    platform: "simulator",
    sha256: "pending",
    profiles: &[Profile::Dev],
}];

/// The local roots, only in builds with debug assertions.
#[cfg(not(debug_assertions))]
pub const LOCAL_ROOTS: &[TrustRoot] = &[];

/// Every root this build's store holds.
pub fn trust_store() -> impl Iterator<Item = &'static TrustRoot> {
    VENDOR_ROOTS.iter().chain(LOCAL_ROOTS)
}

/// The root named `name`, if this build's store holds it.
#[must_use]
pub fn root(name: &str) -> Option<&'static TrustRoot> {
    trust_store().find(|r| r.name == name)
}
