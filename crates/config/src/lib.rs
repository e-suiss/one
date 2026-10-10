//! Typed process configuration for `one-server`, read from a TOML file and `ONE_`-prefixed environment variables and validated before the process starts; user settings never come from here (T-27 (9), T-4).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

/// A module role the single `one-server` binary can run (T-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Client and developer API.
    Api,
    /// Sync.
    Sync,
    /// Task records.
    Task,
    /// Memory and retrieval.
    Memory,
    /// Router rule gate and estimates.
    Router,
    /// Capability registry.
    Capabilities,
    /// Attention value estimation.
    Attention,
    /// One↔One federation.
    Federation,
    /// Job executor.
    Jobs,
}

impl Role {
    /// Roles whose modules exist in this build.
    pub const BUILT: &'static [Role] = &[Role::Api];

    /// The stable configuration name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Sync => "sync",
            Self::Task => "task",
            Self::Memory => "memory",
            Self::Router => "router",
            Self::Capabilities => "capabilities",
            Self::Attention => "attention",
            Self::Federation => "federation",
            Self::Jobs => "jobs",
        }
    }
}

/// Validated `one-server` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Public listen address; loopback unless the operator decides otherwise.
    pub listen: SocketAddr,
    /// Internal listen address for `/livez` and `/readyz` (T-40 (7)).
    pub internal_listen: SocketAddr,
    /// `tracing` filter directives.
    pub log: String,
    /// Module roles this process runs.
    pub roles: Vec<Role>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8090)),
            internal_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8091)),
            log: "info".to_owned(),
            roles: vec![Role::Api],
        }
    }
}

/// Why the configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file or environment could not be parsed, or holds an unknown key.
    #[error(transparent)]
    Parse(#[from] Box<figment::Error>),
    /// No role was given.
    #[error("roles must not be empty")]
    NoRole,
    /// A role was listed twice.
    #[error("role `{}` is listed twice", .0.as_str())]
    DuplicateRole(Role),
    /// A role whose module is not in this build.
    #[error("role `{}` is not built yet", .0.as_str())]
    RoleNotBuilt(Role),
    /// Public and internal listeners share an address.
    #[error("listen and internal_listen must differ")]
    SharedListener,
}

impl ServerConfig {
    /// Loads defaults, then `path` if it exists, then `ONE_*` variables, and validates the result.
    ///
    /// # Errors
    /// Returns the first parse or validation failure.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(path))
            .merge(Env::prefixed("ONE_").ignore(&["CONFIG"]))
            .extract()
            .map_err(Box::new)?;
        config.validate()?;
        Ok(config)
    }

    /// Parses `toml` over the defaults and validates the result.
    ///
    /// # Errors
    /// Returns the first parse or validation failure.
    pub fn from_toml(toml: &str) -> Result<Self, ConfigError> {
        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::string(toml))
            .extract()
            .map_err(Box::new)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks the cross-field rules.
    ///
    /// # Errors
    /// Returns the first violated rule.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.roles.is_empty() {
            return Err(ConfigError::NoRole);
        }
        for (i, role) in self.roles.iter().enumerate() {
            if self
                .roles
                .iter()
                .skip(i.saturating_add(1))
                .any(|r| r == role)
            {
                return Err(ConfigError::DuplicateRole(*role));
            }
            if !Role::BUILT.contains(role) {
                return Err(ConfigError::RoleNotBuilt(*role));
            }
        }
        if self.listen == self.internal_listen {
            return Err(ConfigError::SharedListener);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_27_defaults_are_valid_and_loopback() {
        let config = ServerConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.listen.ip().is_loopback());
        assert!(config.internal_listen.ip().is_loopback());
    }

    #[test]
    fn t_27_unknown_key_is_rejected() {
        assert!(matches!(
            ServerConfig::from_toml("dev_mode = true"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn t_4_unbuilt_or_duplicate_role_is_rejected() {
        assert!(matches!(
            ServerConfig::from_toml("roles = [\"memory\"]"),
            Err(ConfigError::RoleNotBuilt(Role::Memory))
        ));
        assert!(matches!(
            ServerConfig::from_toml("roles = [\"api\", \"api\"]"),
            Err(ConfigError::DuplicateRole(Role::Api))
        ));
        assert!(matches!(
            ServerConfig::from_toml("roles = []"),
            Err(ConfigError::NoRole)
        ));
    }

    #[test]
    fn t_40_shared_listener_is_rejected() {
        assert!(matches!(
            ServerConfig::from_toml(
                "listen = \"127.0.0.1:9000\"\ninternal_listen = \"127.0.0.1:9000\""
            ),
            Err(ConfigError::SharedListener)
        ));
    }
}
