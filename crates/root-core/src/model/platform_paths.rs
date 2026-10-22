//! Platform-aware path classification.
//!
//! Everything here operates on path *strings*, so Windows and macOS rules can be tested on any
//! host. Nothing touches the filesystem, and none of these functions decide that two paths are the
//! same resource: that is the job of `FileIdentity`.

use serde::{Deserialize, Serialize};

/// Operating system family Root is running on (or reasoning about).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl PlatformKind {
    /// Platform this binary was compiled for.
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            PlatformKind::Linux
        } else if cfg!(target_os = "macos") {
            PlatformKind::MacOs
        } else if cfg!(target_os = "windows") {
            PlatformKind::Windows
        } else {
            PlatformKind::Other
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            PlatformKind::Linux => "Linux",
            PlatformKind::MacOs => "macOS",
            PlatformKind::Windows => "Windows",
            PlatformKind::Other => "Unsupported platform",
        }
    }
}

/// Syntactic form of a Windows path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsPathKind {
    /// `C:\dir\file`
    DriveAbsolute,
    /// `C:file` (relative to the current directory of drive C)
    DriveRelative,
    /// `\\server\share\dir`
    Unc,
    /// `\\?\C:\dir` (extended-length, no normalization by the OS)
    VerbatimDrive,
    /// `\\?\UNC\server\share\dir`
    VerbatimUnc,
    /// `\\.\COM1`, `\\?\GLOBALROOT\...`, `\\?\pipe\...`: device namespace, never a scan target
    DeviceNamespace,
    /// `\dir` (rooted on the current drive)
    RootRelative,
    Relative,
}

fn is_sep(c: char) -> bool {
    c == '\\' || c == '/'
}

/// Classifies a Windows path string without consulting the filesystem.
pub fn classify_windows_path(path: &str) -> WindowsPathKind {
    let bytes: Vec<char> = path.chars().collect();
    let starts_two_seps = bytes.len() >= 2 && is_sep(bytes[0]) && is_sep(bytes[1]);

    if starts_two_seps
        && bytes.len() >= 4
        && (bytes[2] == '?' || bytes[2] == '.')
        && is_sep(bytes[3])
    {
        if bytes[2] == '.' {
            return WindowsPathKind::DeviceNamespace;
        }
        let rest: String = bytes[4..].iter().collect();
        let lower = rest.to_ascii_lowercase();
        if lower == "unc" || lower.starts_with("unc\\") || lower.starts_with("unc/") {
            return WindowsPathKind::VerbatimUnc;
        }
        if lower.starts_with("globalroot")
            || lower.starts_with("pipe")
            || lower.starts_with("volume{")
        {
            return WindowsPathKind::DeviceNamespace;
        }
        let r: Vec<char> = rest.chars().collect();
        if r.len() >= 2 && r[0].is_ascii_alphabetic() && r[1] == ':' {
            return WindowsPathKind::VerbatimDrive;
        }
        return WindowsPathKind::DeviceNamespace;
    }
    if starts_two_seps {
        return WindowsPathKind::Unc;
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == ':' {
        if bytes.len() >= 3 && is_sep(bytes[2]) {
            return WindowsPathKind::DriveAbsolute;
        }
        return WindowsPathKind::DriveRelative;
    }
    if !bytes.is_empty() && is_sep(bytes[0]) {
        return WindowsPathKind::RootRelative;
    }
    WindowsPathKind::Relative
}

/// Result of comparing two Windows path strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMatch {
    /// Byte-identical after separator normalization.
    Identical,
    /// Equal only if the volume or directory is case-insensitive. Root cannot tell from the
    /// string alone, so this is a hint, never proof of identity.
    EquivalentIfCaseInsensitive,
    Different,
}

fn normalize_windows(path: &str) -> String {
    let mut s: String = path
        .chars()
        .map(|c| if c == '/' { '\\' } else { c })
        .collect();
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\unc\\") {
        s = format!("\\\\{}", &s[8..]);
    } else if lower.starts_with("\\\\?\\") && s.len() > 5 && s.as_bytes()[5] == b':' {
        s = s[4..].to_string();
    }
    while s.len() > 3 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// Compares two Windows path strings conservatively.
pub fn compare_windows_paths(a: &str, b: &str) -> PathMatch {
    let na = normalize_windows(a);
    let nb = normalize_windows(b);
    if na == nb {
        PathMatch::Identical
    } else if na.eq_ignore_ascii_case(&nb) {
        PathMatch::EquivalentIfCaseInsensitive
    } else {
        PathMatch::Different
    }
}

/// Maximum path length (UTF-16 units) the legacy Win32 API accepts without an extended prefix.
pub const WINDOWS_LEGACY_MAX_PATH: usize = 260;

/// Converts an absolute drive or UNC path to extended-length form when it is long enough to need
/// it. Returns `None` for relative, device, or already-verbatim paths (callers must not guess).
pub fn to_extended_length_path(path: &str) -> Option<String> {
    match classify_windows_path(path) {
        WindowsPathKind::DriveAbsolute => {
            let backslashed: String = path
                .chars()
                .map(|c| if c == '/' { '\\' } else { c })
                .collect();
            Some(format!("\\\\?\\{}", backslashed))
        }
        WindowsPathKind::Unc => {
            let backslashed: String = path
                .chars()
                .map(|c| if c == '/' { '\\' } else { c })
                .collect();
            Some(format!("\\\\?\\UNC\\{}", &backslashed[2..]))
        }
        _ => None,
    }
}

/// Whether a path of this length needs the extended-length form.
pub fn needs_extended_length(path: &str) -> bool {
    path.encode_utf16().count() >= WINDOWS_LEGACY_MAX_PATH
}

const UNIX_PSEUDO: [&str; 4] = ["/proc", "/sys", "/dev", "/run"];
const MACOS_PSEUDO: [&str; 2] = ["/dev", "/System/Volumes/VM"];
const LINUX_PROTECTED: [&str; 7] = ["/etc", "/boot", "/usr", "/var", "/lib", "/lib64", "/opt"];
// `/var` is deliberately absent on macOS: per-user temporary and cache directories live under
// `/var/folders`. The system databases under it are listed explicitly.
const MACOS_PROTECTED: [&str; 12] = [
    "/System",
    "/Library",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/private/etc",
    "/private/var/db",
    "/private/var/root",
    "/var/db",
    "/var/root",
    "/cores",
];
const WINDOWS_PROTECTED_BELOW_DRIVE: [&str; 6] = [
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "$recycle.bin",
    "system volume information",
];

fn under_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .map(|rest| rest.starts_with('/'))
            .unwrap_or(false)
}

/// Returns the pseudo-filesystem or device namespace the path resides in, if any.
pub fn pseudo_filesystem_prefix(platform: PlatformKind, path: &str) -> Option<String> {
    match platform {
        PlatformKind::Windows => match classify_windows_path(path) {
            WindowsPathKind::DeviceNamespace => Some("\\\\.\\ (device namespace)".to_string()),
            _ => None,
        },
        PlatformKind::MacOs => MACOS_PSEUDO
            .iter()
            .find(|p| under_prefix(path, p))
            .map(|p| p.to_string()),
        _ => UNIX_PSEUDO
            .iter()
            .find(|p| under_prefix(path, p))
            .map(|p| p.to_string()),
    }
}

/// Returns the protected system directory the path resides in, if any.
pub fn protected_system_prefix(platform: PlatformKind, path: &str) -> Option<String> {
    match platform {
        PlatformKind::Windows => {
            let normalized = normalize_windows(path)
                .to_ascii_lowercase()
                .replace('\\', "/");
            let b = normalized.as_bytes();
            if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'/' {
                let below = &normalized[3..];
                for name in WINDOWS_PROTECTED_BELOW_DRIVE {
                    if under_prefix(below, name) {
                        return Some(format!("<drive>:\\{}", name));
                    }
                }
            }
            None
        }
        PlatformKind::MacOs => MACOS_PROTECTED
            .iter()
            .find(|p| under_prefix(path, p))
            .map(|p| p.to_string()),
        _ => LINUX_PROTECTED
            .iter()
            .find(|p| under_prefix(path, p))
            .map(|p| p.to_string()),
    }
}

/// Whether the path is a filesystem root that must never be scanned, scheduled, or monitored.
pub fn is_filesystem_root(platform: PlatformKind, path: &str) -> bool {
    match platform {
        PlatformKind::Windows => {
            let n = normalize_windows(path);
            let b = n.as_bytes();
            (b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
                || (b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\')
                || n == "\\"
        }
        _ => path == "/",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_windows_paths() {
        assert_eq!(
            classify_windows_path("C:\\Users\\a"),
            WindowsPathKind::DriveAbsolute
        );
        assert_eq!(
            classify_windows_path("c:/Users/a"),
            WindowsPathKind::DriveAbsolute
        );
        assert_eq!(
            classify_windows_path("C:file"),
            WindowsPathKind::DriveRelative
        );
        assert_eq!(
            classify_windows_path("\\\\srv\\share\\x"),
            WindowsPathKind::Unc
        );
        assert_eq!(
            classify_windows_path("\\\\?\\C:\\x"),
            WindowsPathKind::VerbatimDrive
        );
        assert_eq!(
            classify_windows_path("\\\\?\\UNC\\srv\\s\\x"),
            WindowsPathKind::VerbatimUnc
        );
        assert_eq!(
            classify_windows_path("\\\\.\\COM1"),
            WindowsPathKind::DeviceNamespace
        );
        assert_eq!(
            classify_windows_path("\\\\?\\GLOBALROOT\\Device\\X"),
            WindowsPathKind::DeviceNamespace
        );
        assert_eq!(classify_windows_path("\\x"), WindowsPathKind::RootRelative);
        assert_eq!(classify_windows_path("a\\b"), WindowsPathKind::Relative);
    }

    #[test]
    fn path_comparison_never_claims_case_equivalence_as_identity() {
        assert_eq!(
            compare_windows_paths("C:\\A\\b", "C:/A/b"),
            PathMatch::Identical
        );
        assert_eq!(
            compare_windows_paths("C:\\A\\b", "c:\\a\\B"),
            PathMatch::EquivalentIfCaseInsensitive
        );
        assert_eq!(
            compare_windows_paths("C:\\A", "C:\\B"),
            PathMatch::Different
        );
        assert_eq!(
            compare_windows_paths("\\\\?\\C:\\A", "C:\\A"),
            PathMatch::Identical
        );
        assert_eq!(
            compare_windows_paths("\\\\?\\UNC\\srv\\s\\x", "\\\\srv\\s\\x"),
            PathMatch::Identical
        );
    }

    #[test]
    fn extended_length_conversion_is_explicit() {
        assert_eq!(
            to_extended_length_path("C:\\a\\b").as_deref(),
            Some("\\\\?\\C:\\a\\b")
        );
        assert_eq!(
            to_extended_length_path("\\\\srv\\share\\x").as_deref(),
            Some("\\\\?\\UNC\\srv\\share\\x")
        );
        assert_eq!(to_extended_length_path("rel\\x"), None);
        assert_eq!(to_extended_length_path("\\\\?\\C:\\x"), None);
        assert!(needs_extended_length(&format!("C:\\{}", "a".repeat(300))));
        assert!(!needs_extended_length("C:\\short"));
    }

    #[test]
    fn windows_protected_and_pseudo_paths() {
        let w = PlatformKind::Windows;
        assert!(protected_system_prefix(w, "C:\\Windows\\System32").is_some());
        assert!(protected_system_prefix(w, "d:/program files/x").is_some());
        assert!(protected_system_prefix(w, "\\\\?\\C:\\ProgramData\\x").is_some());
        assert!(protected_system_prefix(w, "C:\\Users\\dev\\project").is_none());
        assert!(protected_system_prefix(w, "C:\\WindowsApps").is_none());
        assert!(pseudo_filesystem_prefix(w, "\\\\.\\PhysicalDrive0").is_some());
        assert!(pseudo_filesystem_prefix(w, "C:\\Users").is_none());
        assert!(is_filesystem_root(w, "C:\\"));
        assert!(is_filesystem_root(w, "c:"));
        assert!(!is_filesystem_root(w, "C:\\Users"));
    }

    #[test]
    fn macos_paths_allow_per_user_var_folders() {
        let m = PlatformKind::MacOs;
        assert!(protected_system_prefix(m, "/System/Library").is_some());
        assert!(protected_system_prefix(m, "/Library/Preferences").is_some());
        assert!(protected_system_prefix(m, "/private/var/db/x").is_some());
        assert!(protected_system_prefix(m, "/var/folders/ab/T/x").is_none());
        assert!(protected_system_prefix(m, "/Users/dev/Library").is_none());
        assert!(pseudo_filesystem_prefix(m, "/dev/disk0").is_some());
    }

    #[test]
    fn linux_rules_are_unchanged() {
        let l = PlatformKind::Linux;
        assert_eq!(
            pseudo_filesystem_prefix(l, "/proc/1").as_deref(),
            Some("/proc")
        );
        assert_eq!(
            protected_system_prefix(l, "/var/lib/x").as_deref(),
            Some("/var")
        );
        assert!(protected_system_prefix(l, "/home/u").is_none());
        assert!(protected_system_prefix(l, "/variable").is_none());
        assert!(is_filesystem_root(l, "/"));
    }
}
