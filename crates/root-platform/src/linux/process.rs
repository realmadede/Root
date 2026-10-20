use root_core::{
    error::Result,
    model::{MemoryMeasurement, ProcessCandidate, ProcessIdentity, ProcessState},
};
use std::{fs, os::unix::fs::MetadataExt};

use crate::traits::ProcessProvider;

#[derive(Debug, Default, Clone)]
pub struct LinuxProcess;

impl LinuxProcess {
    pub fn new() -> Self {
        Self
    }

    /// Parses the `/proc/[pid]/stat` line defensively.
    ///
    /// Linux `/proc/[pid]/stat` format:
    /// `pid (comm) state ppid pgrp session tty_nr ... starttime ...`
    ///
    /// The process name (`comm`) is enclosed in parentheses and may contain spaces or parens.
    /// We use `find('(')` and `rfind(')')` to safely isolate `comm`.
    pub fn parse_stat_line(
        stat_content: &str,
    ) -> Option<(u32, String, ProcessState, u32, i32, u64)> {
        let open_paren = stat_content.find('(')?;
        let close_paren = stat_content.rfind(')')?;

        if open_paren >= close_paren {
            return None;
        }

        let pid: u32 = stat_content[..open_paren].trim().parse().ok()?;
        let comm = stat_content[open_paren + 1..close_paren].to_string();

        let rest = stat_content[close_paren + 1..].trim();
        let fields: Vec<&str> = rest.split_whitespace().collect();

        if fields.len() < 20 {
            return None;
        }

        let state_char = fields.first()?.chars().next().unwrap_or('?');
        let state = ProcessState::from_char(state_char);
        let ppid: u32 = fields.get(1)?.parse().ok()?;
        let tty_nr: i32 = fields.get(4)?.parse().ok()?;
        let start_time_ticks: u64 = fields.get(19)?.parse().ok()?;

        Some((pid, comm, state, ppid, tty_nr, start_time_ticks))
    }

    /// Extracts real UID from `/proc/[pid]/status`.
    pub fn parse_status_uid(status_content: &str) -> Option<u32> {
        for line in status_content.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if let Some(real_uid_str) = parts.first() {
                    return real_uid_str.parse().ok();
                }
            }
        }
        None
    }

    /// Privacy-preserving command-line sanitizer.
    ///
    /// Avoids storing sensitive command-line parameters, tokens, or environment data.
    /// Truncates to a maximum of 5 arguments and redacts tokens containing `=` or credentials.
    pub fn sanitize_cmdline(raw_args: &[String]) -> Vec<String> {
        let mut sanitized = Vec::new();
        let sensitive_keys = [
            "token",
            "secret",
            "key",
            "password",
            "auth",
            "credential",
            "api-key",
        ];

        let mut redact_next = false;
        for (idx, arg) in raw_args.iter().enumerate() {
            if idx >= 5 {
                sanitized.push("[TRUNCATED]".to_string());
                break;
            }

            if redact_next {
                sanitized.push("[REDACTED]".to_string());
                redact_next = false;
                continue;
            }

            let lower = arg.to_lowercase();
            if sensitive_keys.iter().any(|k| lower.contains(k)) {
                if arg.contains('=') {
                    sanitized.push("[REDACTED]".to_string());
                } else {
                    sanitized.push(arg.clone());
                    redact_next = true;
                }
                continue;
            }

            if arg.contains('=') {
                // If it looks like an environment assignment or key=value parameter
                let parts: Vec<&str> = arg.splitn(2, '=').collect();
                sanitized.push(format!("{}=[REDACTED]", parts[0]));
            } else {
                sanitized.push(arg.clone());
            }
        }

        sanitized
    }
}

impl ProcessProvider for LinuxProcess {
    fn list_pids(&self) -> Result<Vec<u32>> {
        let mut pids = Vec::new();
        let entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return Ok(pids), // Non-Linux or restricted procfs
        };

        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
        pids.sort();
        Ok(pids)
    }

    fn get_process_memory(&self, pid: u32) -> Result<Option<MemoryMeasurement>> {
        // Attempt fast PSS/USS lookup via /proc/[pid]/smaps_rollup
        let smaps_rollup_path = format!("/proc/{}/smaps_rollup", pid);
        if let Ok(content) = fs::read_to_string(&smaps_rollup_path) {
            let mut rss_kb = 0u64;
            let mut pss_kb = 0u64;
            let mut private_clean_kb = 0u64;
            let mut private_dirty_kb = 0u64;
            let mut swap_kb = 0u64;

            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    match parts[0] {
                        "Rss:" => rss_kb = parts[1].parse().unwrap_or(0),
                        "Pss:" => pss_kb = parts[1].parse().unwrap_or(0),
                        "Private_Clean:" => private_clean_kb = parts[1].parse().unwrap_or(0),
                        "Private_Dirty:" => private_dirty_kb = parts[1].parse().unwrap_or(0),
                        "Swap:" => swap_kb = parts[1].parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }

            let uss_bytes = (private_clean_kb + private_dirty_kb) * 1024;
            return Ok(Some(MemoryMeasurement::new(
                rss_kb * 1024,
                Some(pss_kb * 1024),
                Some(uss_bytes),
                swap_kb * 1024,
            )));
        }

        // Fallback to /proc/[pid]/status for VmRSS and VmSwap
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(content) = fs::read_to_string(&status_path) {
            let mut vmrss_kb = 0u64;
            let mut vmswap_kb = 0u64;
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    vmrss_kb = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix("VmSwap:") {
                    vmswap_kb = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                }
            }

            return Ok(Some(MemoryMeasurement::new(
                vmrss_kb * 1024,
                None,
                None,
                vmswap_kb * 1024,
            )));
        }

        Ok(None)
    }

    fn inspect_process(&self, pid: u32) -> Result<Option<ProcessCandidate>> {
        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => return Ok(None), // Process disappeared or permission denied
        };

        let (pid, comm, state, ppid, tty_nr, start_time_ticks) =
            match Self::parse_stat_line(&stat_content) {
                Some(vals) => vals,
                None => return Ok(None),
            };

        let status_path = format!("/proc/{}/status", pid);
        let real_uid = fs::read_to_string(&status_path)
            .ok()
            .and_then(|c| Self::parse_status_uid(&c))
            .or_else(|| fs::metadata(&stat_path).ok().map(|m| m.uid()))
            .unwrap_or(1000);

        // Read raw commandline, sanitize for privacy, and redact potential secrets
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let raw_cmdline: Vec<String> = fs::read(&cmdline_path)
            .ok()
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect()
            })
            .unwrap_or_default();

        let cmdline = Self::sanitize_cmdline(&raw_cmdline);

        let exe_path = format!("/proc/{}/exe", pid);
        let executable = fs::read_link(&exe_path).ok();

        let memory = self
            .get_process_memory(pid)?
            .unwrap_or_else(|| MemoryMeasurement::new(0, None, None, 0));

        let is_reparented_to_init = ppid == 1;

        // Multi-factor abandonment corroboration:
        // A process is not considered abandoned merely because PPID == 1.
        // It must satisfy multi-factor evidence:
        // 1. Reparented to PID 1
        // 2. Detached from controlling terminal (tty_nr == 0)
        // 3. Match known development server, LSP, or agent process signature
        let is_dev_signature = comm.contains("node")
            || comm.contains("python")
            || comm.contains("rust-analyzer")
            || comm.contains("tsserver")
            || comm.contains("vite")
            || raw_cmdline.iter().any(|arg| {
                arg.contains("vite")
                    || arg.contains("tsserver")
                    || arg.contains("language-server")
                    || arg.contains("antigravity")
                    || arg.contains("claude")
            });

        let is_abandoned = is_reparented_to_init && tty_nr == 0 && is_dev_signature;

        let associated_agent = if raw_cmdline.iter().any(|a| a.contains("antigravity")) {
            Some("Google Antigravity".to_string())
        } else if raw_cmdline.iter().any(|a| a.contains("claude")) {
            Some("Claude Code".to_string())
        } else if comm.contains("rust-analyzer")
            || raw_cmdline.iter().any(|a| a.contains("rust-analyzer"))
        {
            Some("Rust Analyzer".to_string())
        } else if comm.contains("tsserver") || raw_cmdline.iter().any(|a| a.contains("tsserver")) {
            Some("TypeScript Server".to_string())
        } else {
            None
        };

        // Process identity composite: combining PID with start_time_ticks and real_uid
        // provides robust protection against PID recycling attacks.
        // In future phases, pidfd_open will pin the process descriptor directly.
        let identity = ProcessIdentity {
            pid,
            ppid,
            real_uid,
            name: comm,
            executable,
            cmdline,
            start_time_ticks,
            tty_nr,
        };

        Ok(Some(ProcessCandidate {
            identity,
            state,
            memory,
            is_reparented_to_init,
            is_abandoned,
            associated_agent,
        }))
    }
}
