//! Deterministic Fault-Injection Framework for Guardian Transaction Safety Verification.
//!
//! Provides explicit, thread-safe, sleep-free hooks for intercepting transaction
//! lifecycle stages, simulating TOCTOU filesystem races, injecting I/O and sync
//! failures, and verifying conservative crash-state recovery.
//!
//! This module is intended for Level 1 synthetic fixture testing and adversarial
//! verification. It is never invoked or reachable from production CLI or GUI code.

use root_core::error::RootError;

use crate::transaction::TransactionState;

/// Explicit interception points in the Guardian transaction lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Immediately before Guardian policy authorization is evaluated.
    BeforeAuthorization,
    /// Immediately after authorization succeeds, before preflight checks.
    AfterAuthorization,
    /// Immediately before preflight stat and identity snapshot.
    BeforePreflightValidation,
    /// Immediately after initial file stat, before content hashing.
    AfterIdentityValidation,
    /// During file content hashing.
    DuringHashing,
    /// Immediately after content hashing completes.
    AfterHashing,
    /// Immediately before appending a record of the specified state to the journal.
    BeforeJournalAppend(TransactionState),
    /// Immediately after appending a record of the specified state to the journal.
    AfterJournalAppend(TransactionState),
    /// Immediately before atomic filesystem relocation (rename).
    ImmediatelyBeforeRename,
    /// Immediately after atomic filesystem relocation (rename) completes.
    ImmediatelyAfterRename,
    /// Immediately before post-mutation verification (unlink and integrity check).
    BeforePostOperationVerification,
    /// Immediately after post-mutation verification completes.
    AfterVerification,
    /// Immediately before restoration commences.
    BeforeRestoration,
    /// During restoration conflict checking and preparation.
    DuringRestoration,
    /// Immediately after restoration relocation completes.
    AfterRestoration,
    /// During crash-state reconciliation.
    DuringReconciliation,
}

/// Action decided by an interceptor when a `FaultPoint` is reached.
#[derive(Debug)]
pub enum InterceptDecision {
    /// Continue execution normally.
    Continue,
    /// Abort the operation cleanly with the specified error, updating the transaction
    /// state to `Failed` and recording the failure in the journal when possible.
    Fail(RootError),
    /// Abort the operation abruptly to simulate an unexpected crash, kernel panic, or process kill,
    /// returning immediately without updating subsequent journal records.
    Crash(RootError),
}

/// A deterministic interceptor for Guardian operations.
pub trait FaultInterceptor: Send + Sync {
    /// Invoked at each lifecycle `FaultPoint`.
    fn on_fault_point(&self, point: FaultPoint, tx_id: &str) -> InterceptDecision {
        let _ = (point, tx_id);
        InterceptDecision::Continue
    }
}

/// Default no-op interceptor that allows all operations to proceed without interference.
pub struct NoopInterceptor;

impl FaultInterceptor for NoopInterceptor {}

/// Closure-based interceptor for flexible, test-specific fault injection.
pub struct FnInterceptor<F>
where
    F: Fn(FaultPoint, &str) -> InterceptDecision + Send + Sync,
{
    handler: F,
}

impl<F> FnInterceptor<F>
where
    F: Fn(FaultPoint, &str) -> InterceptDecision + Send + Sync,
{
    pub fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F> FaultInterceptor for FnInterceptor<F>
where
    F: Fn(FaultPoint, &str) -> InterceptDecision + Send + Sync,
{
    fn on_fault_point(&self, point: FaultPoint, tx_id: &str) -> InterceptDecision {
        (self.handler)(point, tx_id)
    }
}

/// Interceptor that fails cleanly with `InterceptDecision::Fail` at a specific target point.
pub struct TargetFailInterceptor {
    target: FaultPoint,
    reason: Option<String>,
}

impl TargetFailInterceptor {
    pub fn new(target: FaultPoint) -> Self {
        Self {
            target,
            reason: None,
        }
    }

    pub fn with_reason(target: FaultPoint, reason: impl Into<String>) -> Self {
        Self {
            target,
            reason: Some(reason.into()),
        }
    }
}

impl FaultInterceptor for TargetFailInterceptor {
    fn on_fault_point(&self, point: FaultPoint, tx_id: &str) -> InterceptDecision {
        if point == self.target {
            let reason = self
                .reason
                .clone()
                .unwrap_or_else(|| format!("Injected deterministic failure at {:?}", point));
            InterceptDecision::Fail(RootError::TransactionFailed {
                tx_id: tx_id.to_string(),
                reason,
            })
        } else {
            InterceptDecision::Continue
        }
    }
}

/// Interceptor that halts abruptly with `InterceptDecision::Crash` at a specific target point.
pub struct TargetCrashInterceptor {
    target: FaultPoint,
    reason: Option<String>,
}

impl TargetCrashInterceptor {
    pub fn new(target: FaultPoint) -> Self {
        Self {
            target,
            reason: None,
        }
    }

    pub fn with_reason(target: FaultPoint, reason: impl Into<String>) -> Self {
        Self {
            target,
            reason: Some(reason.into()),
        }
    }
}

impl FaultInterceptor for TargetCrashInterceptor {
    fn on_fault_point(&self, point: FaultPoint, tx_id: &str) -> InterceptDecision {
        if point == self.target {
            let reason = self
                .reason
                .clone()
                .unwrap_or_else(|| format!("Injected simulated crash at {:?}", point));
            InterceptDecision::Crash(RootError::TransactionFailed {
                tx_id: tx_id.to_string(),
                reason,
            })
        } else {
            InterceptDecision::Continue
        }
    }
}
