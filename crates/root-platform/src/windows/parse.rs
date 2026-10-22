//! Pure conversions for Win32 data. They take plain integers so they run on any host.

use root_core::model::{FileIdentity, SystemMemorySummary};

const WINDOWS_TO_UNIX_EPOCH_SECS: i64 = 11_644_473_600;

/// Converts a `FILETIME` (100 ns ticks since 1601-01-01) to Unix seconds.
pub fn filetime_to_unix_secs(filetime: u64) -> i64 {
    (filetime / 10_000_000) as i64 - WINDOWS_TO_UNIX_EPOCH_SECS
}

pub fn filetime_from_parts(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

/// Builds an identity from the 64-bit file index of `GetFileInformationByHandle`. A volume serial
/// and index of zero means the filesystem did not supply an identity.
pub fn identity_from_basic_info(
    volume_serial: u32,
    index_high: u32,
    index_low: u32,
) -> FileIdentity {
    let index = filetime_from_parts(index_high, index_low);
    if volume_serial == 0 && index == 0 {
        return FileIdentity::unavailable();
    }
    FileIdentity::windows(volume_serial as u64, index as u128)
}

/// Builds an identity from `FILE_ID_INFO` (128-bit file id, little-endian bytes).
pub fn identity_from_id_info(volume_serial: u64, file_id: [u8; 16]) -> FileIdentity {
    let id = u128::from_le_bytes(file_id);
    if volume_serial == 0 && id == 0 {
        return FileIdentity::unavailable();
    }
    FileIdentity::windows(volume_serial, id)
}

/// Decodes a NUL-terminated UTF-16 buffer.
pub fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// PIDs that are never inspected: the idle pseudo-process and the kernel `System` process.
pub fn is_reserved_pid(pid: u32) -> bool {
    pid == 0 || pid == 4
}

/// Derives a memory summary from `MEMORYSTATUSEX` counters.
///
/// Windows reports commit limits, not swap usage: `total_page - total_phys` is the page-file
/// commit capacity, and the matching difference for available counters is an approximation of
/// unused page-file commit. It is labeled as such wherever displayed.
pub fn memory_summary(
    total_phys: u64,
    avail_phys: u64,
    total_page: u64,
    avail_page: u64,
) -> SystemMemorySummary {
    SystemMemorySummary {
        total_bytes: total_phys,
        available_bytes: avail_phys.min(total_phys),
        cached_bytes: 0,
        free_bytes: avail_phys.min(total_phys),
        swap_total_bytes: total_page.saturating_sub(total_phys),
        swap_free_bytes: avail_page.saturating_sub(avail_phys),
    }
}

/// `SYSTEM_POWER_STATUS.ACLineStatus`: 0 offline, 1 online, 255 unknown.
pub fn ac_line_status_to_bool(status: u8) -> Option<bool> {
    match status {
        1 => Some(true),
        0 => Some(false),
        _ => None,
    }
}

/// UTF-16LE with byte-order mark, as required by `schtasks /Create /XML`.
pub fn encode_utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use root_core::model::IdentityKind;

    #[test]
    fn filetime_epoch_conversion() {
        // 1970-01-01 expressed as a FILETIME
        assert_eq!(filetime_to_unix_secs(116_444_736_000_000_000), 0);
        assert_eq!(filetime_to_unix_secs(116_444_736_010_000_000), 1);
    }

    #[test]
    fn identity_paths() {
        let id = identity_from_basic_info(0xABCD, 1, 2);
        assert_eq!(id.kind, IdentityKind::WindowsFileId);
        assert_eq!(id.object, (1u128 << 32) | 2);
        assert!(!identity_from_basic_info(0, 0, 0).is_usable());

        let mut bytes = [0u8; 16];
        bytes[15] = 0x80; // high bit of the 128-bit id
        let wide = identity_from_id_info(7, bytes);
        assert_eq!(wide.object, 1u128 << 127);
        assert!(!identity_from_id_info(0, [0; 16]).is_usable());
    }

    #[test]
    fn wide_buffer_decoding_handles_unicode() {
        let text = "projet-\u{00e9}t\u{00e9}-\u{0434}\u{0430}";
        let mut buf: Vec<u16> = text.encode_utf16().collect();
        buf.extend_from_slice(&[0, 65, 65]);
        assert_eq!(wide_to_string(&buf), text);
    }

    #[test]
    fn reserved_pids() {
        assert!(is_reserved_pid(0) && is_reserved_pid(4));
        assert!(!is_reserved_pid(1234));
    }

    #[test]
    fn memory_summary_never_exceeds_total() {
        let m = memory_summary(100, 150, 300, 120);
        assert_eq!(m.available_bytes, 100);
        assert_eq!(m.swap_total_bytes, 200);
        assert_eq!(m.swap_free_bytes, 0);
    }

    #[test]
    fn ac_status_unknown_is_none() {
        assert_eq!(ac_line_status_to_bool(1), Some(true));
        assert_eq!(ac_line_status_to_bool(0), Some(false));
        assert_eq!(ac_line_status_to_bool(255), None);
    }

    #[test]
    fn utf16_bom_encoding() {
        let bytes = encode_utf16le_with_bom("A");
        assert_eq!(bytes, vec![0xFF, 0xFE, 0x41, 0x00]);
    }
}
