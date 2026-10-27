//! Root Core: Domain models, classification policies, and synthetic testing fixtures.
//!
//! This crate contains pure, deterministic domain logic and data structures with zero platform
//! or GUI dependencies.

pub mod discovery;
pub mod error;
pub mod fixtures;
pub mod model;

pub use discovery::{
    DiscoveryContext, DiscoveryEngine, DiscoveryFilter, DiscoveryFinding, DiscoveryReport,
    DiscoveryRule, DiscoverySummary, DiscoveryTargetId, LifecycleAssessment, LifecycleState,
    ProcessAttribution, ResourceClassifier, RuleRegistry, TargetKind,
};
pub use error::{Result, RootError};
pub use fixtures::SyntheticFixture;
pub use model::*;
