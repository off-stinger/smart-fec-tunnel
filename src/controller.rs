//! Safe planning and revision transaction primitives for the product controller.

use crate::product_config::{ConfigError, ModuleId, ProductConfig};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortBinding {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: TransportProtocol,
    pub owner: &'static str,
}

pub trait PortProbe {
    fn conflict(&self, requested: &PortBinding) -> io::Result<Option<PortConflict>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortConflict {
    pub requested: PortBinding,
    /// Best-effort diagnostic only; never used to construct a shell command.
    pub current_owner: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanAction {
    EnableModule(ModuleId),
    BindPort(PortBinding),
    StageRevision,
    ValidateCandidate,
    CommitRevision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentPlan {
    pub schema_version: u32,
    pub modules: BTreeSet<ModuleId>,
    pub actions: Vec<PlanAction>,
    pub conflicts: Vec<PortConflict>,
}

#[derive(Debug)]
pub enum PlanError {
    Config(ConfigError),
    Probe(io::Error),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "invalid product configuration: {error}"),
            Self::Probe(error) => write!(f, "port probe failed: {error}"),
        }
    }
}

impl std::error::Error for PlanError {}

pub struct Planner<'a, P> {
    probe: &'a P,
}

impl<'a, P: PortProbe> Planner<'a, P> {
    pub fn new(probe: &'a P) -> Self {
        Self { probe }
    }

    pub fn build(&self, config: &ProductConfig) -> Result<DeploymentPlan, PlanError> {
        let modules = config.resolve_modules().map_err(PlanError::Config)?;
        let bindings = requested_bindings(config, &modules);
        let mut conflicts = Vec::new();
        for binding in &bindings {
            if let Some(conflict) = self.probe.conflict(binding).map_err(PlanError::Probe)? {
                conflicts.push(conflict);
            }
        }

        let mut actions = modules
            .iter()
            .copied()
            .map(PlanAction::EnableModule)
            .collect::<Vec<_>>();
        actions.extend(bindings.into_iter().map(PlanAction::BindPort));
        actions.extend([
            PlanAction::StageRevision,
            PlanAction::ValidateCandidate,
            PlanAction::CommitRevision,
        ]);
        Ok(DeploymentPlan {
            schema_version: config.schema_version,
            modules,
            actions,
            conflicts,
        })
    }
}

fn requested_bindings(config: &ProductConfig, modules: &BTreeSet<ModuleId>) -> Vec<PortBinding> {
    let mut result = Vec::new();
    if modules.contains(&ModuleId::Tuic) || modules.contains(&ModuleId::Masque) {
        result.push(PortBinding {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: config.server.public_udp_port,
            protocol: TransportProtocol::Udp,
            owner: "smart-gateway-transport",
        });
    }
    result.push(PortBinding {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: config.server.public_tcp_port,
        protocol: TransportProtocol::Tcp,
        owner: "smart-gateway-public",
    });
    result
}

pub trait CandidateValidator {
    fn validate(&self, candidate: &Path) -> Result<(), String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionState {
    Candidate,
    Validated,
    Committed,
    RolledBack,
}

#[derive(Debug)]
pub enum TransactionError {
    Io(io::Error),
    InvalidState {
        expected: TransactionState,
        actual: TransactionState,
    },
    InvalidArtifactName,
    Validation(String),
    NoPreviousRevision,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TransactionError {}

impl From<io::Error> for TransactionError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Filesystem-backed transaction. Artifacts are constrained to plain file names
/// so a compromised configuration cannot write outside the candidate directory.
pub struct RevisionTransaction {
    root: PathBuf,
    candidate: PathBuf,
    previous: Option<String>,
    revision_id: String,
    state: TransactionState,
}

impl RevisionTransaction {
    pub fn begin(
        root: impl AsRef<Path>,
        previous: Option<String>,
    ) -> Result<Self, TransactionError> {
        let root = root.as_ref().to_path_buf();
        if previous
            .as_deref()
            .is_some_and(|value| !is_plain_file_name(value))
        {
            return Err(TransactionError::InvalidArtifactName);
        }
        fs::create_dir_all(root.join("candidates"))?;
        fs::create_dir_all(root.join("revisions"))?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "system clock before epoch"))?
            .as_nanos();
        let revision_id = format!("rev-{nanos}-{}", std::process::id());
        let candidate = root.join("candidates").join(&revision_id);
        fs::create_dir(&candidate)?;
        Ok(Self {
            root,
            candidate,
            previous,
            revision_id,
            state: TransactionState::Candidate,
        })
    }

    pub fn state(&self) -> &TransactionState {
        &self.state
    }
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn stage(&self, artifact_name: &str, bytes: &[u8]) -> Result<(), TransactionError> {
        self.expect(TransactionState::Candidate)?;
        if !is_plain_file_name(artifact_name) {
            return Err(TransactionError::InvalidArtifactName);
        }
        let path = self.candidate.join(artifact_name);
        let temporary = self.candidate.join(format!(".{artifact_name}.tmp"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(TransactionError::Io(error));
        }
        drop(file);
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(TransactionError::Io(error));
        }
        Ok(())
    }

    pub fn validate(
        &mut self,
        validator: &impl CandidateValidator,
    ) -> Result<(), TransactionError> {
        self.expect(TransactionState::Candidate)?;
        validator
            .validate(&self.candidate)
            .map_err(TransactionError::Validation)?;
        self.state = TransactionState::Validated;
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), TransactionError> {
        self.expect(TransactionState::Validated)?;
        let committed = self.root.join("revisions").join(&self.revision_id);
        fs::rename(&self.candidate, &committed)?;
        if let Err(error) = write_pointer(&self.root, "current", &self.revision_id) {
            // The active pointer was not changed. Restore the candidate so a
            // caller may correct the underlying I/O failure and retry safely.
            let _ = fs::rename(&committed, &self.candidate);
            return Err(TransactionError::Io(error));
        }
        self.state = TransactionState::Committed;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<(), TransactionError> {
        self.expect(TransactionState::Committed)?;
        let previous = self
            .previous
            .as_deref()
            .ok_or(TransactionError::NoPreviousRevision)?;
        let previous_path = self.root.join("revisions").join(previous);
        if !previous_path.is_dir() {
            return Err(TransactionError::NoPreviousRevision);
        }
        write_pointer(&self.root, "current", previous)?;
        self.state = TransactionState::RolledBack;
        Ok(())
    }

    fn expect(&self, expected: TransactionState) -> Result<(), TransactionError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(TransactionError::InvalidState {
                expected,
                actual: self.state.clone(),
            })
        }
    }
}

fn is_plain_file_name(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value).components().count() == 1
        && matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        )
}

fn write_pointer(root: &Path, name: &str, revision: &str) -> io::Result<()> {
    let temporary = root.join(format!(".{name}.tmp"));
    let backup = root.join(format!(".{name}.previous"));
    let destination = root.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(format!("{revision}\n").as_bytes())?;
    file.sync_all()?;
    drop(file);

    // Unix rename replaces an existing file atomically. Windows does not, so
    // retain a recoverable pointer while swapping there.
    if cfg!(windows) && destination.exists() {
        if backup.exists() {
            fs::remove_file(&backup)?;
        }
        fs::rename(&destination, &backup)?;
        if let Err(error) = fs::rename(&temporary, &destination) {
            let _ = fs::rename(&backup, &destination);
            return Err(error);
        }
        fs::remove_file(backup)?;
        Ok(())
    } else {
        fs::rename(temporary, destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::product_config::Profile;

    struct ClearPorts;
    impl PortProbe for ClearPorts {
        fn conflict(&self, _: &PortBinding) -> io::Result<Option<PortConflict>> {
            Ok(None)
        }
    }

    struct HasConflict;
    impl PortProbe for HasConflict {
        fn conflict(&self, request: &PortBinding) -> io::Result<Option<PortConflict>> {
            Ok(
                (request.protocol == TransportProtocol::Udp).then(|| PortConflict {
                    requested: request.clone(),
                    current_owner: Some("existing-daemon".into()),
                }),
            )
        }
    }

    struct RequireConfig;
    impl CandidateValidator for RequireConfig {
        fn validate(&self, candidate: &Path) -> Result<(), String> {
            candidate
                .join("config.yaml")
                .is_file()
                .then_some(())
                .ok_or_else(|| "config.yaml is missing".into())
        }
    }

    fn temporary_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("smart-gateway-{label}-{}", std::process::id()))
    }

    #[test]
    fn planner_reports_conflicts_without_mutation() {
        let config = ProductConfig::for_profile(Profile::Enhanced);
        let plan = Planner::new(&HasConflict).build(&config).unwrap();
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].requested.protocol, TransportProtocol::Udp);
    }

    #[test]
    fn transaction_requires_validation_and_can_rollback() {
        let root = temporary_root("transaction");
        let _ = fs::remove_dir_all(&root);

        let mut first = RevisionTransaction::begin(&root, None).unwrap();
        first.stage("config.yaml", b"schema_version: 1\n").unwrap();
        first.validate(&RequireConfig).unwrap();
        first.commit().unwrap();
        let first_id = first.revision_id().to_owned();

        let mut second = RevisionTransaction::begin(&root, Some(first_id.clone())).unwrap();
        second
            .stage("config.yaml", b"schema_version: 1\nprofile: enhanced\n")
            .unwrap();
        assert!(matches!(
            second.commit(),
            Err(TransactionError::InvalidState { .. })
        ));
        second.validate(&RequireConfig).unwrap();
        second.commit().unwrap();
        second.rollback().unwrap();

        assert_eq!(
            fs::read_to_string(root.join("current")).unwrap().trim(),
            first_id
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_path_traversal_is_rejected() {
        let root = temporary_root("traversal");
        let _ = fs::remove_dir_all(&root);
        let tx = RevisionTransaction::begin(&root, None).unwrap();
        assert!(matches!(
            tx.stage("../escape", b"bad"),
            Err(TransactionError::InvalidArtifactName)
        ));
        assert!(matches!(
            RevisionTransaction::begin(&root, Some("../old".into())),
            Err(TransactionError::InvalidArtifactName)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_validation_never_advances_state() {
        let root = temporary_root("invalid");
        let _ = fs::remove_dir_all(&root);
        let mut tx = RevisionTransaction::begin(&root, None).unwrap();
        assert!(matches!(
            tx.validate(&RequireConfig),
            Err(TransactionError::Validation(_))
        ));
        assert_eq!(tx.state(), &TransactionState::Candidate);
        assert!(!root.join("current").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn clear_port_plan_contains_transaction_steps() {
        let plan = Planner::new(&ClearPorts)
            .build(&ProductConfig::for_profile(Profile::Standard))
            .unwrap();
        assert!(plan.conflicts.is_empty());
        assert!(plan.actions.contains(&PlanAction::ValidateCandidate));
    }
}
