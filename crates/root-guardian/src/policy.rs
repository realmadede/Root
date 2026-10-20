use root_core::model::{
    FindingTarget, ProposedAction, ProtectionTier, RejectionReason, SafetyDecision, ScanFinding,
};
use std::path::Path;

/// Root Guardian safety policy evaluator.
///
/// In Phase 01, Root Guardian operates in strict read-only mode: any mutation or termination
/// request is rejected with explicit justification.
#[derive(Debug, Clone, Copy)]
pub struct GuardianPolicy {
    /// In Phase 01 and Phase 02, this invariant is always true: all mutations are prohibited.
    pub read_only_mode: bool,
}

impl Default for GuardianPolicy {
    fn default() -> Self {
        Self {
            read_only_mode: true,
        }
    }
}

impl GuardianPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates a candidate finding against the active safety policy.
    pub fn evaluate(
        &self,
        target: &FindingTarget,
        tier: ProtectionTier,
        action: ProposedAction,
        current_uid: u32,
    ) -> SafetyDecision {
        // Rule 1: Read-Only Invariant for Phase 01/02: reject all mutating operations
        if self.read_only_mode {
            match action {
                ProposedAction::Quarantine
                | ProposedAction::Prune
                | ProposedAction::TerminateGraceful => {
                    return SafetyDecision::reject(
                        RejectionReason::Phase02ReadOnlyPolicy,
                        "Phase 02 operates strictly in read-only mode; destructive and mutating actions are permanently prohibited",
                    );
                }
                ProposedAction::Inspect | ProposedAction::Ignore => {}
            }
        }

        // Rule 2: Tier 1 Strictly Protected invariant
        if tier == ProtectionTier::StrictlyProtected {
            match action {
                ProposedAction::Quarantine
                | ProposedAction::Prune
                | ProposedAction::TerminateGraceful => {
                    return SafetyDecision::reject(
                        RejectionReason::TierStrictlyProtected,
                        "Resource is classified as Tier 1 (Strictly Protected); deletion or termination is permanently forbidden",
                    );
                }
                ProposedAction::Inspect | ProposedAction::Ignore => {}
            }
        }

        // Rule 3: Target-specific checks
        match target {
            FindingTarget::Filesystem(res) => {
                // Rule 3a: Ownership invariant
                if res.ownership.uid != current_uid {
                    return SafetyDecision::reject(
                        RejectionReason::OwnershipMismatch,
                        format!(
                            "Resource is owned by UID {}, but current unprivileged user is UID {}",
                            res.ownership.uid, current_uid
                        ),
                    );
                }

                // Rule 3b: Path traversal and null byte rejection
                let path_str = res.location.path.to_string_lossy();
                if path_str.contains('\0') {
                    return SafetyDecision::reject(
                        RejectionReason::InvalidPath,
                        "Path contains null byte sequence",
                    );
                }

                // Rule 3c: Protected location prefixes
                if self.is_protected_system_location(&res.location.path) {
                    return SafetyDecision::reject(
                        RejectionReason::ProtectedLocation,
                        format!(
                            "Path {:?} is located in a protected operating system directory",
                            res.location.path
                        ),
                    );
                }

                // Rule 3d: Protected credential folders
                if path_str.contains("/.ssh")
                    || path_str.contains("/.gnupg")
                    || path_str.ends_with("oauth_creds.json")
                    || path_str.ends_with(".key")
                {
                    return SafetyDecision::reject(
                        RejectionReason::ProtectedLocation,
                        "Target matches protected cryptographic credential or token pattern",
                    );
                }
            }
            FindingTarget::Process(proc) => {
                // Rule 3e: Process UID match
                if proc.identity.real_uid != current_uid {
                    return SafetyDecision::reject(
                        RejectionReason::OwnershipMismatch,
                        format!(
                            "Process PID {} is owned by UID {}, but current user is UID {}",
                            proc.identity.pid, proc.identity.real_uid, current_uid
                        ),
                    );
                }

                // Rule 3f: Never touch init or kernel threads
                if proc.identity.pid <= 1 {
                    return SafetyDecision::reject(
                        RejectionReason::TierStrictlyProtected,
                        "System init (PID 1) and kernel tasks cannot be signaled",
                    );
                }
            }
        }

        SafetyDecision::Allowed
    }

    /// Evaluates a complete finding and updates its safety decision.
    pub fn audit_finding(&self, finding: &mut ScanFinding, current_uid: u32) {
        finding.safety_decision = self.evaluate(
            &finding.target,
            finding.protection_tier,
            finding.proposed_action,
            current_uid,
        );
    }

    fn is_protected_system_location(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.starts_with("/etc")
            || path_str.starts_with("/usr")
            || path_str.starts_with("/boot")
            || path_str.starts_with("/sys")
            || path_str.starts_with("/proc")
            || path_str.starts_with("/dev")
            || path_str.starts_with("/bin")
            || path_str.starts_with("/sbin")
            || path_str.starts_with("/lib")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use root_core::model::{
        FileType, FindingTarget, ProposedAction, ProtectionTier, RejectionReason,
        ResourceCandidate, ResourceCategory, ResourceId, ResourceLocation, ResourceMetadata,
        ResourceOwnership, StorageMeasurement,
    };
    use std::path::PathBuf;

    fn make_test_resource(
        path: &str,
        uid: u32,
        tier: ProtectionTier,
    ) -> (FindingTarget, ProtectionTier) {
        let res = ResourceCandidate {
            id: ResourceId::new("test_1"),
            location: ResourceLocation::new(PathBuf::from(path), None, 1, 100),
            category: ResourceCategory::PackageCache,
            metadata: ResourceMetadata {
                file_type: FileType::RegularFile,
                storage: StorageMeasurement::from_raw(1024, 2, 1),
                permissions_mode: 0o644,
                mtime_epoch_secs: 1000,
                atime_epoch_secs: 1000,
                ctime_epoch_secs: 1000,
            },
            ownership: ResourceOwnership {
                uid,
                gid: uid,
                is_current_user: uid == 1000,
            },
            associated_agent: None,
        };
        (FindingTarget::Filesystem(res), tier)
    }

    #[test]
    fn test_phase02_rejects_all_mutations() {
        let policy = GuardianPolicy::new();
        let (target, tier) =
            make_test_resource("/tmp/test.tmp", 1000, ProtectionTier::SafeRecoverable);

        let decision = policy.evaluate(&target, tier, ProposedAction::Quarantine, 1000);
        match decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(reason, RejectionReason::Phase02ReadOnlyPolicy);
            }
            SafetyDecision::Allowed => panic!("Phase 02 must reject quarantine"),
        }
    }

    #[test]
    fn test_allows_inspect_on_valid_resource() {
        let policy = GuardianPolicy::new();
        let (target, tier) =
            make_test_resource("/tmp/test.tmp", 1000, ProtectionTier::SafeRecoverable);

        let decision = policy.evaluate(&target, tier, ProposedAction::Inspect, 1000);
        assert_eq!(decision, SafetyDecision::Allowed);
    }

    #[test]
    fn test_rejects_foreign_ownership() {
        let policy = GuardianPolicy::new();
        let (target, tier) =
            make_test_resource("/tmp/other_user.tmp", 1001, ProtectionTier::SafeRecoverable);

        let decision = policy.evaluate(&target, tier, ProposedAction::Inspect, 1000);
        match decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(reason, RejectionReason::OwnershipMismatch);
            }
            SafetyDecision::Allowed => panic!("Must reject foreign ownership"),
        }
    }

    #[test]
    fn test_rejects_protected_locations() {
        let policy = GuardianPolicy::new();
        let (target, tier) =
            make_test_resource("/etc/shadow", 1000, ProtectionTier::StrictlyProtected);

        let decision = policy.evaluate(&target, tier, ProposedAction::Inspect, 1000);
        match decision {
            SafetyDecision::Rejected { reason, .. } => {
                assert_eq!(reason, RejectionReason::ProtectedLocation);
            }
            SafetyDecision::Allowed => panic!("Must reject system location"),
        }
    }
}
