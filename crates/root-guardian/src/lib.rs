//! Root Guardian: Safety policy evaluation, authorization, and sandboxed quarantine transaction engine.

//!
//! The policy, journal reader, and integrity code compile everywhere. The fixture mutation engine
//! (authorization, quarantine, restoration, sandbox, transaction engine) is compiled only on Linux,
//! where it exists to exercise Level 1 fixtures. It is absent from macOS and Windows builds, and no
//! CLI, GUI, scheduler, or monitor path on any platform constructs it.

pub mod crypto;
pub mod journal;
pub mod policy;
pub mod transaction;

#[cfg(target_os = "linux")]
pub mod authorization;
#[cfg(target_os = "linux")]
pub mod engine;
#[cfg(target_os = "linux")]
pub mod quarantine;
#[cfg(target_os = "linux")]
pub mod restoration;
#[cfg(target_os = "linux")]
pub mod sandbox;

#[cfg(target_os = "linux")]
pub use authorization::{
    AuthorizationDecision, AuthorizationEngine, AuthorizationReceipt, AuthorizationRequest,
    ConsentRecord,
};
pub use crypto::{sha256_digest, sha256_file, sha256_hex};
#[cfg(target_os = "linux")]
pub use engine::TransactionEngine;
pub use journal::{JournalRecord, RecoveryJournal};
pub use policy::GuardianPolicy;
#[cfg(target_os = "linux")]
pub use quarantine::QuarantineStore;
#[cfg(target_os = "linux")]
pub use restoration::RestorationEngine;
#[cfg(target_os = "linux")]
pub use sandbox::FixtureSandbox;
pub use transaction::{TransactionContext, TransactionState};
