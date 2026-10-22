//! Pure parsing helpers for Darwin interfaces. They take plain bytes or strings so they can be
//! tested on any host; the macOS adapters feed them real kernel output.

use root_core::model::ProcessState;

/// BSD `p_stat` values from `<sys/proc.h>`.
pub fn process_state_from_bsd_status(status: u32) -> ProcessState {
    match status {
        1 => ProcessState::Sleeping, // SIDL: being created; not yet runnable
        2 => ProcessState::Running,  // SRUN
        3 => ProcessState::Sleeping, // SSLEEP
        4 => ProcessState::Stopped,  // SSTOP
        5 => ProcessState::Zombie,   // SZOMB
        _ => ProcessState::Unknown,
    }
}

/// Process start time as microseconds since the Unix epoch. Compared only for equality against
/// the same platform, so the unit never leaks into cross-platform logic.
pub fn start_ticks_from_timeval(tv_sec: u64, tv_usec: u64) -> u64 {
    tv_sec.saturating_mul(1_000_000).saturating_add(tv_usec)
}

/// Converts a NUL-terminated fixed buffer (such as `pbi_comm`) to a `String`.
pub fn fixed_buffer_to_string(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).to_string()
}

/// `struct xsw_usage` returned by `sysctl vm.swapusage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapUsage {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

/// Parses the 32-byte `xsw_usage` layout (three `u64`, one `u32`, one 32-bit boolean).
/// Returns `None` when the buffer is shorter than the three leading counters.
pub fn parse_swap_usage(bytes: &[u8]) -> Option<SwapUsage> {
    if bytes.len() < 24 {
        return None;
    }
    let read = |i: usize| u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
    Some(SwapUsage {
        total_bytes: read(0),
        available_bytes: read(8),
        used_bytes: read(16),
    })
}

/// Parses `pmset -g batt` output. `None` when the source cannot be determined (desktop Macs
/// report "AC Power" with no battery; unknown text yields `None` rather than a guess).
pub fn parse_pmset_power_source(output: &str) -> Option<bool> {
    if output.contains("'AC Power'") {
        Some(true)
    } else if output.contains("'Battery Power'") {
        Some(false)
    } else {
        None
    }
}

/// Lower-bound estimate of available memory: free plus speculative pages. Purgeable and
/// file-backed pages are intentionally not added, so the value never overstates availability.
pub fn available_memory_lower_bound(
    free_pages: u64,
    speculative_pages: u64,
    page_size: u64,
) -> u64 {
    free_pages
        .saturating_add(speculative_pages)
        .saturating_mul(page_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_bsd_status() {
        assert_eq!(process_state_from_bsd_status(2), ProcessState::Running);
        assert_eq!(process_state_from_bsd_status(5), ProcessState::Zombie);
        assert_eq!(process_state_from_bsd_status(99), ProcessState::Unknown);
    }

    #[test]
    fn start_ticks_distinguish_reused_pid() {
        let a = start_ticks_from_timeval(1_700_000_000, 5);
        let b = start_ticks_from_timeval(1_700_000_000, 6);
        assert_ne!(a, b);
        assert_eq!(a, 1_700_000_000_000_005);
    }

    #[test]
    fn fixed_buffer_stops_at_nul() {
        assert_eq!(fixed_buffer_to_string(b"node\0garbage"), "node");
        assert_eq!(fixed_buffer_to_string(b"full"), "full");
    }

    #[test]
    fn swap_usage_roundtrip_and_short_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1000u64.to_ne_bytes());
        buf.extend_from_slice(&400u64.to_ne_bytes());
        buf.extend_from_slice(&600u64.to_ne_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        let u = parse_swap_usage(&buf).unwrap();
        assert_eq!(
            (u.total_bytes, u.available_bytes, u.used_bytes),
            (1000, 400, 600)
        );
        assert!(parse_swap_usage(&buf[..10]).is_none());
    }

    #[test]
    fn pmset_parsing_never_guesses() {
        assert_eq!(
            parse_pmset_power_source("Now drawing from 'AC Power'\n -InternalBattery-0"),
            Some(true)
        );
        assert_eq!(
            parse_pmset_power_source("Now drawing from 'Battery Power'"),
            Some(false)
        );
        assert_eq!(parse_pmset_power_source("unexpected"), None);
    }

    #[test]
    fn available_memory_is_a_lower_bound() {
        assert_eq!(available_memory_lower_bound(10, 5, 4096), 15 * 4096);
        assert_eq!(available_memory_lower_bound(u64::MAX, 1, 4096), u64::MAX);
    }
}
