//! Root Guardian: Safety policy evaluation, authorization, and sandboxed quarantine transaction engine.

pub mod authorization;
pub mod crypto;
pub mod engine;
pub mod journal;
pub mod policy;
pub mod quarantine;
pub mod restoration;
pub mod sandbox;
pub mod transaction;

pub use authorization::{
    AuthorizationDecision, AuthorizationEngine, AuthorizationReceipt, AuthorizationRequest,
};
pub use crypto::{sha256_digest, sha256_file, sha256_hex};
pub use engine::TransactionEngine;
pub use journal::{JournalRecord, RecoveryJournal};
pub use policy::GuardianPolicy;
pub use quarantine::QuarantineStore;
pub use restoration::RestorationEngine;
pub use sandbox::FixtureSandbox;
pub use transaction::{TransactionContext, TransactionState};
