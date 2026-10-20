use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::measurement::MemoryMeasurement;

/// Process state from Linux `/proc/[pid]/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    TracingStop,
    Dead,
    Unknown,
}

impl ProcessState {
    pub fn from_char(c: char) -> Self {
        match c {
            'R' => ProcessState::Running,
            'S' => ProcessState::Sleeping,
            'D' => ProcessState::DiskSleep,
            'Z' => ProcessState::Zombie,
            'T' => ProcessState::Stopped,
            't' => ProcessState::TracingStop,
            'X' | 'x' => ProcessState::Dead,
            _ => ProcessState::Unknown,
        }
    }
}

/// Multi-factor process identity independently validating instance provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub real_uid: u32,
    pub name: String,
    pub executable: Option<PathBuf>,
    pub cmdline: Vec<String>,
    /// Jiffies since boot; guarantees against PID recycling when combined with pidfd.
    pub start_time_ticks: u64,
    /// Controlling terminal device number (0 indicates completely detached).
    pub tty_nr: i32,
}

/// A running or defunct process candidate evaluated by Root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCandidate {
    pub identity: ProcessIdentity,
    pub state: ProcessState,
    pub memory: MemoryMeasurement,
    /// Process was re-parented to PID 1. Note: Does NOT automatically mean abandoned.
    pub is_reparented_to_init: bool,
    /// Corroborated abandonment based on absence of TTY, dead session leader, and agent signature.
    pub is_abandoned: bool,
    pub associated_agent: Option<String>,
}
