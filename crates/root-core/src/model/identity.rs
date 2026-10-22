use serde::{Deserialize, Serialize};
use std::fmt;

/// How a platform identifies a filesystem object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// `st_dev` + `st_ino` (Linux, macOS).
    #[default]
    PosixDeviceInode,
    /// Volume serial number + file id (Windows).
    WindowsFileId,
    /// The platform or filesystem did not provide a usable identity (for example FAT or some
    /// network shares). Two objects with this kind must never be considered the same or distinct
    /// on identity grounds alone.
    Unavailable,
}

impl IdentityKind {
    pub fn describe(&self) -> &'static str {
        match self {
            IdentityKind::PosixDeviceInode => "device/inode",
            IdentityKind::WindowsFileId => "volume serial/file id",
            IdentityKind::Unavailable => "unavailable",
        }
    }
}

/// Strongest practical identity of a filesystem object on the current platform.
///
/// Identity is only meaningful within a single observation session: it is not assumed stable
/// across moves, remounts, filesystem replacement, or network filesystems, and a path alone never
/// identifies a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    pub kind: IdentityKind,
    /// Device number (`st_dev`) or Windows volume serial number.
    pub volume: u64,
    /// Inode number or Windows file id (128-bit capable for ReFS).
    pub object: u128,
}

impl FileIdentity {
    pub fn posix(device: u64, inode: u64) -> Self {
        Self {
            kind: IdentityKind::PosixDeviceInode,
            volume: device,
            object: inode as u128,
        }
    }

    pub fn windows(volume_serial: u64, file_id: u128) -> Self {
        Self {
            kind: IdentityKind::WindowsFileId,
            volume: volume_serial,
            object: file_id,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            kind: IdentityKind::Unavailable,
            volume: 0,
            object: 0,
        }
    }

    /// Whether this identity can support equality decisions.
    pub fn is_usable(&self) -> bool {
        self.kind != IdentityKind::Unavailable
    }

    /// Low 64 bits of the object id, as stored in legacy `inode` fields.
    pub fn object_low64(&self) -> u64 {
        self.object as u64
    }

    /// Returns `Some(true/false)` when both identities are usable and of the same kind;
    /// `None` when equality cannot be decided.
    pub fn same_object(&self, other: &FileIdentity) -> Option<bool> {
        if !self.is_usable() || !other.is_usable() || self.kind != other.kind {
            return None;
        }
        Some(self.volume == other.volume && self.object == other.object)
    }
}

impl fmt::Display for FileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.volume, self.object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_identity_matches_legacy_format() {
        let id = FileIdentity::posix(64768, 12345);
        assert_eq!(id.to_string(), "64768:12345");
        assert_eq!(id.object_low64(), 12345);
    }

    #[test]
    fn unavailable_identity_never_decides_equality() {
        let a = FileIdentity::unavailable();
        assert_eq!(a.same_object(&a), None);
        let p = FileIdentity::posix(1, 2);
        assert_eq!(p.same_object(&FileIdentity::posix(1, 2)), Some(true));
        assert_eq!(p.same_object(&FileIdentity::posix(1, 3)), Some(false));
        assert_eq!(p.same_object(&FileIdentity::windows(1, 2)), None);
    }

    #[test]
    fn windows_128_bit_ids_are_preserved() {
        let big = (1u128 << 100) | 7;
        let id = FileIdentity::windows(0xDEAD_BEEF, big);
        assert_eq!(id.object, big);
        assert_eq!(id.object_low64(), 7);
    }
}
