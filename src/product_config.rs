//! Typed, dependency-free product configuration model.
//!
//! Serialization is deliberately kept outside this module.  The controller may
//! later support YAML, JSON, or an API without allowing transport syntax to leak
//! into planning and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Profile {
    Standard,
    Enhanced,
    LowResource,
    Laboratory,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ModuleId {
    Tuic,
    Masque,
    AdaptiveFec,
    Pmtu,
    DirectEgress,
    MultiWarp,
    StableGoogleEgress,
    DnsDoh,
    DnsDotFallback,
    DnsDoq,
    Observability,
    AutomaticRollback,
}

impl ModuleId {
    pub fn dependencies(self) -> &'static [ModuleId] {
        use ModuleId::*;
        match self {
            AdaptiveFec => &[Tuic, Pmtu],
            MultiWarp => &[DirectEgress],
            StableGoogleEgress => &[DirectEgress],
            DnsDotFallback => &[DnsDoh],
            DnsDoq => &[DirectEgress],
            Tuic | Masque | Pmtu | DirectEgress | DnsDoh | Observability | AutomaticRollback => &[],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleSetting {
    Enabled,
    Disabled,
    Auto,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub bandwidth_mbps: u32,
    pub public_tcp_port: u16,
    pub public_udp_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductConfig {
    pub schema_version: u32,
    pub profile: Profile,
    pub server: ServerConfig,
    /// Explicit operator overrides. Unspecified modules inherit the profile.
    pub modules: BTreeMap<ModuleId, ModuleSetting>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    UnsupportedSchema {
        found: u32,
        supported: u32,
    },
    ZeroBandwidth,
    UnsafePublicPort,
    MissingDependency {
        module: ModuleId,
        dependency: ModuleId,
    },
    ConflictingTransports,
    ExperimentalModuleOutsideLaboratory(ModuleId),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ConfigError {}

impl ProductConfig {
    pub fn for_profile(profile: Profile) -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            profile,
            server: ServerConfig {
                bandwidth_mbps: 30,
                public_tcp_port: 443,
                public_udp_port: 443,
            },
            modules: BTreeMap::new(),
        }
    }

    pub fn resolve_modules(&self) -> Result<BTreeSet<ModuleId>, ConfigError> {
        self.validate_scalar_fields()?;
        let mut resolved = profile_defaults(self.profile);

        for (&module, &setting) in &self.modules {
            match setting {
                ModuleSetting::Enabled => {
                    resolved.insert(module);
                }
                ModuleSetting::Disabled => {
                    resolved.remove(&module);
                }
                ModuleSetting::Auto => {}
            }
        }

        if resolved.contains(&ModuleId::Tuic) && resolved.contains(&ModuleId::Masque) {
            return Err(ConfigError::ConflictingTransports);
        }
        for experimental in [ModuleId::Masque, ModuleId::DnsDoq] {
            if resolved.contains(&experimental) && self.profile != Profile::Laboratory {
                return Err(ConfigError::ExperimentalModuleOutsideLaboratory(
                    experimental,
                ));
            }
        }
        for &module in &resolved {
            for &dependency in module.dependencies() {
                if !resolved.contains(&dependency) {
                    return Err(ConfigError::MissingDependency { module, dependency });
                }
            }
        }
        Ok(resolved)
    }

    fn validate_scalar_fields(&self) -> Result<(), ConfigError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchema {
                found: self.schema_version,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }
        if self.server.bandwidth_mbps == 0 {
            return Err(ConfigError::ZeroBandwidth);
        }
        if self.server.public_tcp_port == 0 || self.server.public_udp_port == 0 {
            return Err(ConfigError::UnsafePublicPort);
        }
        Ok(())
    }
}

pub fn profile_defaults(profile: Profile) -> BTreeSet<ModuleId> {
    use ModuleId::*;
    let modules: &[ModuleId] = match profile {
        Profile::Standard => &[
            Tuic,
            AdaptiveFec,
            Pmtu,
            DirectEgress,
            DnsDoh,
            DnsDotFallback,
            Observability,
            AutomaticRollback,
        ],
        Profile::Enhanced => &[
            Tuic,
            AdaptiveFec,
            Pmtu,
            DirectEgress,
            MultiWarp,
            StableGoogleEgress,
            DnsDoh,
            DnsDotFallback,
            Observability,
            AutomaticRollback,
        ],
        Profile::LowResource => &[
            Tuic,
            AdaptiveFec,
            Pmtu,
            DirectEgress,
            DnsDoh,
            AutomaticRollback,
        ],
        Profile::Laboratory => &[
            Masque,
            Pmtu,
            DirectEgress,
            DnsDoh,
            DnsDoq,
            Observability,
            AutomaticRollback,
        ],
    };
    modules.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enhanced_profile_has_production_modules() {
        let modules = ProductConfig::for_profile(Profile::Enhanced)
            .resolve_modules()
            .unwrap();
        assert!(modules.contains(&ModuleId::MultiWarp));
        assert!(modules.contains(&ModuleId::AdaptiveFec));
        assert!(!modules.contains(&ModuleId::Masque));
        assert!(!modules.contains(&ModuleId::DnsDoq));
    }

    #[test]
    fn disabling_required_dependency_is_rejected() {
        let mut config = ProductConfig::for_profile(Profile::Enhanced);
        config
            .modules
            .insert(ModuleId::Pmtu, ModuleSetting::Disabled);
        assert_eq!(
            config.resolve_modules(),
            Err(ConfigError::MissingDependency {
                module: ModuleId::AdaptiveFec,
                dependency: ModuleId::Pmtu,
            })
        );
    }

    #[test]
    fn experimental_module_requires_laboratory_profile() {
        let mut config = ProductConfig::for_profile(Profile::Standard);
        config
            .modules
            .insert(ModuleId::Masque, ModuleSetting::Enabled);
        config
            .modules
            .insert(ModuleId::Tuic, ModuleSetting::Disabled);
        assert_eq!(
            config.resolve_modules(),
            Err(ConfigError::ExperimentalModuleOutsideLaboratory(
                ModuleId::Masque
            ))
        );
    }
}
