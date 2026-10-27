use root_core::error::{Result, RootError};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use crate::transaction::TransactionState;

/// Magic bytes identifying a Root Transaction Journal Record (`RTJR`).
pub const JOURNAL_MAGIC: [u8; 4] = *b"RTJR";

/// Active framed journal record format version.
pub const JOURNAL_VERSION_1: u16 = 1;

/// Fixed length in bytes of the binary record framing header.
pub const HEADER_SIZE: usize = 16;

/// Maximum permitted payload size (64 KiB) to prevent unbounded memory allocation from malformed headers.
pub const MAX_RECORD_PAYLOAD_SIZE: usize = 65_536;

/// Precomputed compile-time lookup table for IEEE 802.3 CRC-32 (reversed polynomial `0xEDB8_8320`).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Computes the IEEE 802.3 CRC-32 checksum of the provided byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ (byte as u32)) & 0xFF) as usize];
    }
    !crc
}

/// Discovered format family of a journal file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalFormat {
    /// Framed binary header with CRC-32 and JSON payload (Version 1).
    FramedV1,
    /// Unframed line-delimited JSON Lines (Legacy Version 0).
    LegacyJsonl,
    /// Empty journal file (zero bytes).
    Empty,
    /// Unrecognized or corrupted header.
    Unknown,
}

/// Detailed classification of journal record defects and corruption modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "defect_type", rename_all = "snake_case")]
pub enum JournalCorruption {
    /// Incomplete binary header at the end of the journal (< 16 bytes available).
    TruncatedTrailingHeader { offset: u64, bytes_present: usize },
    /// Incomplete payload at the end of the journal (fewer bytes available than declared in header).
    TruncatedTrailingPayload {
        offset: u64,
        declared_length: u32,
        available_bytes: usize,
    },
    /// Incomplete trailing newline delimiter at the end of a record.
    TruncatedTrailingDelimiter { offset: u64 },
    /// Record header magic did not match `RTJR`.
    InvalidMagic { offset: u64, found: [u8; 4] },
    /// Header declares an unsupported format version.
    UnsupportedVersion { offset: u64, version: u16 },
    /// Header declares a payload size exceeding `MAX_RECORD_PAYLOAD_SIZE`.
    OversizedPayload {
        offset: u64,
        declared: u32,
        max_allowed: usize,
    },
    /// CRC-32 checksum verification failed over the record payload.
    ChecksumMismatch {
        offset: u64,
        expected: u32,
        actual: u32,
    },
    /// Payload is not valid JSON or does not deserialize into `JournalRecord`.
    InvalidPayload { offset: u64, reason: String },
    /// Legacy JSONL line deserialization failure.
    LegacyLineError { line_number: usize, reason: String },
}

/// Comprehensive scan report produced by scanning and validating a journal file.
#[derive(Debug, Clone)]
pub struct JournalScanReport {
    pub path: PathBuf,
    pub format: JournalFormat,
    pub records: Vec<JournalRecord>,
    pub is_clean: bool,
    pub trailing_torn_write: Option<JournalCorruption>,
    pub unrecoverable_corruption: Option<JournalCorruption>,
}

/// Serializes and frames a `JournalRecord` into a versioned binary buffer.
///
/// Binary Layout (Big-Endian):
/// - Bytes 0..4: Magic `RTJR`
/// - Bytes 4..6: Format Version `1`
/// - Bytes 6..8: Header Flags `0` (reserved)
/// - Bytes 8..12: CRC-32 checksum over payload
/// - Bytes 12..16: Payload Length in bytes
/// - Bytes 16..(16+len): UTF-8 JSON Payload
/// - Trailing Byte: `\n` (0x0A)
pub fn encode_framed_record(record: &JournalRecord) -> Result<Vec<u8>> {
    let payload =
        serde_json::to_vec(record).map_err(|e| RootError::Serialization(e.to_string()))?;

    if payload.len() > MAX_RECORD_PAYLOAD_SIZE {
        return Err(RootError::JournalError {
            path: PathBuf::new(),
            reason: format!(
                "Payload size ({} bytes) exceeds maximum permitted limit ({} bytes)",
                payload.len(),
                MAX_RECORD_PAYLOAD_SIZE
            ),
        });
    }

    let checksum = crc32(&payload);
    let length = payload.len() as u32;

    let mut buffer = Vec::with_capacity(HEADER_SIZE + payload.len() + 1);
    buffer.extend_from_slice(&JOURNAL_MAGIC);
    buffer.extend_from_slice(&JOURNAL_VERSION_1.to_be_bytes());
    buffer.extend_from_slice(&0u16.to_be_bytes()); // Flags
    buffer.extend_from_slice(&checksum.to_be_bytes());
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(&payload);
    buffer.push(b'\n');

    Ok(buffer)
}

/// Decodes a single framed journal record from a byte buffer.
///
/// Returns the parsed record and total bytes consumed (including delimiter).
pub fn decode_framed_record(bytes: &[u8]) -> Result<(JournalRecord, usize)> {
    if bytes.len() < HEADER_SIZE {
        return Err(RootError::JournalError {
            path: PathBuf::new(),
            reason: format!(
                "Truncated header: expected {} bytes, found {}",
                HEADER_SIZE,
                bytes.len()
            ),
        });
    }

    let magic = &bytes[0..4];
    if magic != JOURNAL_MAGIC {
        return Err(RootError::JournalError {
            path: PathBuf::new(),
            reason: format!("Invalid magic bytes: {:?}", magic),
        });
    }

    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != JOURNAL_VERSION_1 {
        return Err(RootError::JournalError {
            path: PathBuf::new(),
            reason: format!("Unsupported journal version: {}", version),
        });
    }

    let expected_crc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;

    if length > MAX_RECORD_PAYLOAD_SIZE {
        return Err(RootError::JournalError {
            path: PathBuf::new(),
            reason: format!(
                "Declared payload size {} exceeds limit {}",
                length, MAX_RECORD_PAYLOAD_SIZE
            ),
        });
    }

    let payload_start = HEADER_SIZE;
    let payload_end = payload_start + length;

    if bytes.len() < payload_end {
        return Err(RootError::JournalError {
            path: PathBuf::new(),
            reason: format!(
                "Truncated payload: declared {} bytes, but only {} bytes available",
                length,
                bytes.len() - payload_start
            ),
        });
    }

    let payload = &bytes[payload_start..payload_end];
    let actual_crc = crc32(payload);
    if actual_crc != expected_crc {
        return Err(RootError::JournalError {
            path: PathBuf::new(),
            reason: format!(
                "CRC-32 checksum mismatch: expected 0x{:08x}, actual 0x{:08x}",
                expected_crc, actual_crc
            ),
        });
    }

    let record: JournalRecord =
        serde_json::from_slice(payload).map_err(|e| RootError::JournalError {
            path: PathBuf::new(),
            reason: format!("Payload deserialization failed: {}", e),
        })?;

    let mut consumed = payload_end;
    if consumed < bytes.len() && bytes[consumed] == b'\n' {
        consumed += 1;
    } else if consumed + 1 < bytes.len() && bytes[consumed..consumed + 2] == *b"\r\n" {
        consumed += 2;
    }

    Ok((record, consumed))
}

/// An immutable, auditable log entry recorded during quarantine or restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub transaction_id: String,
    pub timestamp_epoch_secs: i64,
    pub state: TransactionState,
    pub original_path: PathBuf,
    pub quarantine_path: Option<PathBuf>,
    pub device_id: u64,
    pub inode: u64,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub reason: String,
    pub failure_reason: Option<String>,
}

/// Deterministic fault injection options for journal append operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalFault {
    None,
    FailLockAcquisition,
    FailOpen,
    FailHeaderWrite,
    FailPayloadWrite,
    FailDelimiterWrite,
    FailFlush,
    FailSyncData,
    FailParentDirSync,
    CrashAfterWriteBeforeSync,
    CrashAfterSyncBeforeReturn,
}

/// A durable, append-only recovery journal tracking transactional operations.
#[derive(Debug)]
pub struct RecoveryJournal {
    journal_path: PathBuf,
}

impl RecoveryJournal {
    pub fn new(journal_path: &Path) -> Result<Self> {
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RootError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        Ok(Self {
            journal_path: journal_path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.journal_path
    }

    /// Detects the storage format family of the underlying journal file.
    pub fn detect_format(&self) -> Result<JournalFormat> {
        if !self.journal_path.exists() {
            return Ok(JournalFormat::Empty);
        }

        let mut file = File::open(&self.journal_path).map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        let mut buf = [0u8; 16];
        let bytes_read = file.read(&mut buf).map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        if bytes_read == 0 {
            return Ok(JournalFormat::Empty);
        }

        if bytes_read >= 4 && &buf[0..4] == JOURNAL_MAGIC.as_slice() {
            return Ok(JournalFormat::FramedV1);
        }

        // Check for legacy JSONL format (first non-whitespace byte is '{')
        for &b in &buf[..bytes_read] {
            if b.is_ascii_whitespace() {
                continue;
            }
            if b == b'{' {
                return Ok(JournalFormat::LegacyJsonl);
            }
            break;
        }

        Ok(JournalFormat::Unknown)
    }

    /// Scans all journal records with thorough integrity verification and diagnostic categorization.
    pub fn scan_records(&self) -> Result<JournalScanReport> {
        let format = self.detect_format()?;

        match format {
            JournalFormat::Empty => Ok(JournalScanReport {
                path: self.journal_path.clone(),
                format: JournalFormat::Empty,
                records: Vec::new(),
                is_clean: true,
                trailing_torn_write: None,
                unrecoverable_corruption: None,
            }),

            JournalFormat::Unknown => {
                let mut file = File::open(&self.journal_path).map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;
                let mut buf = [0u8; 4];
                let _ = file.read(&mut buf);
                Ok(JournalScanReport {
                    path: self.journal_path.clone(),
                    format: JournalFormat::Unknown,
                    records: Vec::new(),
                    is_clean: false,
                    trailing_torn_write: None,
                    unrecoverable_corruption: Some(JournalCorruption::InvalidMagic {
                        offset: 0,
                        found: buf,
                    }),
                })
            }

            JournalFormat::LegacyJsonl => {
                let file = File::open(&self.journal_path).map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;
                let reader = BufReader::new(file);
                let mut records = Vec::new();
                let mut corruption = None;

                for (idx, line_res) in reader.lines().enumerate() {
                    let line = line_res.map_err(|e| RootError::Io {
                        path: self.journal_path.clone(),
                        source: e,
                    })?;

                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<JournalRecord>(trimmed) {
                        Ok(rec) => records.push(rec),
                        Err(e) => {
                            corruption = Some(JournalCorruption::LegacyLineError {
                                line_number: idx + 1,
                                reason: e.to_string(),
                            });
                            break;
                        }
                    }
                }

                let is_clean = corruption.is_none();
                Ok(JournalScanReport {
                    path: self.journal_path.clone(),
                    format: JournalFormat::LegacyJsonl,
                    records,
                    is_clean,
                    trailing_torn_write: None,
                    unrecoverable_corruption: corruption,
                })
            }

            JournalFormat::FramedV1 => {
                let mut file = File::open(&self.journal_path).map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;

                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;

                let mut records = Vec::new();
                let mut offset = 0usize;
                let mut trailing_torn_write = None;
                let mut unrecoverable_corruption = None;

                while offset < bytes.len() {
                    // Check for remaining bytes being only trailing whitespace or newlines
                    if bytes[offset..].iter().all(|b| b.is_ascii_whitespace()) {
                        break;
                    }

                    // Check if enough bytes exist for the 16-byte binary header
                    if offset + HEADER_SIZE > bytes.len() {
                        trailing_torn_write = Some(JournalCorruption::TruncatedTrailingHeader {
                            offset: offset as u64,
                            bytes_present: bytes.len() - offset,
                        });
                        break;
                    }

                    let magic = &bytes[offset..offset + 4];
                    if magic != JOURNAL_MAGIC {
                        unrecoverable_corruption = Some(JournalCorruption::InvalidMagic {
                            offset: offset as u64,
                            found: [magic[0], magic[1], magic[2], magic[3]],
                        });
                        break;
                    }

                    let version = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]);
                    if version != JOURNAL_VERSION_1 {
                        unrecoverable_corruption = Some(JournalCorruption::UnsupportedVersion {
                            offset: offset as u64,
                            version,
                        });
                        break;
                    }

                    let expected_crc = u32::from_be_bytes([
                        bytes[offset + 8],
                        bytes[offset + 9],
                        bytes[offset + 10],
                        bytes[offset + 11],
                    ]);

                    let length = u32::from_be_bytes([
                        bytes[offset + 12],
                        bytes[offset + 13],
                        bytes[offset + 14],
                        bytes[offset + 15],
                    ]) as usize;

                    if length > MAX_RECORD_PAYLOAD_SIZE {
                        unrecoverable_corruption = Some(JournalCorruption::OversizedPayload {
                            offset: offset as u64,
                            declared: length as u32,
                            max_allowed: MAX_RECORD_PAYLOAD_SIZE,
                        });
                        break;
                    }

                    let payload_start = offset + HEADER_SIZE;
                    let payload_end = payload_start + length;

                    if payload_end > bytes.len() {
                        trailing_torn_write = Some(JournalCorruption::TruncatedTrailingPayload {
                            offset: offset as u64,
                            declared_length: length as u32,
                            available_bytes: bytes.len() - payload_start,
                        });
                        break;
                    }

                    let payload = &bytes[payload_start..payload_end];
                    let actual_crc = crc32(payload);
                    if actual_crc != expected_crc {
                        unrecoverable_corruption = Some(JournalCorruption::ChecksumMismatch {
                            offset: offset as u64,
                            expected: expected_crc,
                            actual: actual_crc,
                        });
                        break;
                    }

                    match serde_json::from_slice::<JournalRecord>(payload) {
                        Ok(rec) => records.push(rec),
                        Err(e) => {
                            unrecoverable_corruption = Some(JournalCorruption::InvalidPayload {
                                offset: offset as u64,
                                reason: e.to_string(),
                            });
                            break;
                        }
                    }

                    offset = payload_end;
                    if offset < bytes.len() && bytes[offset] == b'\n' {
                        offset += 1;
                    } else if offset + 1 < bytes.len() && bytes[offset..offset + 2] == *b"\r\n" {
                        offset += 2;
                    }
                }

                let is_clean = trailing_torn_write.is_none() && unrecoverable_corruption.is_none();

                Ok(JournalScanReport {
                    path: self.journal_path.clone(),
                    format: JournalFormat::FramedV1,
                    records,
                    is_clean,
                    trailing_torn_write,
                    unrecoverable_corruption,
                })
            }
        }
    }

    /// Reads all records in chronological sequence, returning an explicit error if any corruption exists.
    pub fn read_all(&self) -> Result<Vec<JournalRecord>> {
        let report = self.scan_records()?;

        if let Some(err) = report.unrecoverable_corruption {
            return Err(RootError::JournalError {
                path: self.journal_path.clone(),
                reason: format!("Journal corruption encountered: {:?}", err),
            });
        }

        if let Some(err) = report.trailing_torn_write {
            return Err(RootError::JournalError {
                path: self.journal_path.clone(),
                reason: format!("Incomplete trailing write encountered: {:?}", err),
            });
        }

        Ok(report.records)
    }

    /// Reads verified records even if an incomplete trailing torn write is present at EOF.
    ///
    /// Still fails if unrecoverable middle corruption or checksum mismatches occur.
    pub fn read_verified_records(&self) -> Result<Vec<JournalRecord>> {
        let report = self.scan_records()?;

        if let Some(err) = report.unrecoverable_corruption {
            return Err(RootError::JournalError {
                path: self.journal_path.clone(),
                reason: format!("Unrecoverable journal corruption: {:?}", err),
            });
        }

        Ok(report.records)
    }

    /// Finds the most recent journal record associated with a given transaction ID.
    pub fn find_latest(&self, transaction_id: &str) -> Result<Option<JournalRecord>> {
        let records = self.read_verified_records()?;
        Ok(records
            .into_iter()
            .rev()
            .find(|r| r.transaction_id == transaction_id))
    }

    /// Scans the journal for interrupted transactions that did not reach a terminal or verified state.
    pub fn get_interrupted_transactions(&self) -> Result<Vec<JournalRecord>> {
        let records = self.read_verified_records()?;
        let mut latest_by_id: HashMap<String, JournalRecord> = HashMap::new();

        for record in records {
            latest_by_id.insert(record.transaction_id.clone(), record);
        }

        let mut interrupted = Vec::new();
        for (_id, record) in latest_by_id {
            match record.state {
                TransactionState::Prepared | TransactionState::Quarantined => {
                    interrupted.push(record);
                }
                _ => {}
            }
        }

        Ok(interrupted)
    }

    /// Appends a new framed journal record and synchronizes to physical storage.
    pub fn append(&mut self, record: &JournalRecord) -> Result<()> {
        self.append_with_fault_injection(record, JournalFault::None)
    }

    /// Appends a new framed journal record with deterministic fault-injection interception.
    pub fn append_with_fault_injection(
        &mut self,
        record: &JournalRecord,
        fault: JournalFault,
    ) -> Result<()> {
        let framed_bytes = encode_framed_record(record)?;

        // Ensure legacy journals are not silently mixed with framed records
        if self.journal_path.exists() {
            let meta = std::fs::metadata(&self.journal_path).map_err(|e| RootError::Io {
                path: self.journal_path.clone(),
                source: e,
            })?;
            if meta.len() > 0 {
                let format = self.detect_format()?;
                if format == JournalFormat::LegacyJsonl {
                    return Err(RootError::JournalError {
                        path: self.journal_path.clone(),
                        reason: "Legacy v0 JSONL journal detected; appending framed records without explicit migration is prohibited".into(),
                    });
                }
                if format == JournalFormat::Unknown {
                    return Err(RootError::JournalError {
                        path: self.journal_path.clone(),
                        reason: "Cannot append to journal of unknown or corrupt format".into(),
                    });
                }
            }
        }

        if fault == JournalFault::FailLockAcquisition {
            return Err(RootError::Io {
                path: self.journal_path.with_extension("lock"),
                source: std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Injected lock acquisition failure",
                ),
            });
        }

        // Advisory exclusive locking to prevent concurrent process write interleaving
        let lock_path = self.journal_path.with_extension("lock");
        let _lock_guard = root_platform::AdvisoryLock::acquire(&lock_path)?;

        if fault == JournalFault::FailOpen {
            return Err(RootError::Io {
                path: self.journal_path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Injected journal open failure",
                ),
            });
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .map_err(|e| RootError::Io {
                path: self.journal_path.clone(),
                source: e,
            })?;

        match fault {
            JournalFault::FailHeaderWrite => {
                file.write_all(&framed_bytes[..8])
                    .map_err(|e| RootError::Io {
                        path: self.journal_path.clone(),
                        source: e,
                    })?;
                file.flush().map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;
                return Err(RootError::Io {
                    path: self.journal_path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Injected header write failure",
                    ),
                });
            }
            JournalFault::FailPayloadWrite => {
                let partial_len = (HEADER_SIZE + 5).min(framed_bytes.len());
                file.write_all(&framed_bytes[..partial_len])
                    .map_err(|e| RootError::Io {
                        path: self.journal_path.clone(),
                        source: e,
                    })?;
                file.flush().map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;
                return Err(RootError::Io {
                    path: self.journal_path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Injected payload write failure",
                    ),
                });
            }
            JournalFault::FailDelimiterWrite => {
                let without_delim = framed_bytes.len().saturating_sub(1);
                file.write_all(&framed_bytes[..without_delim])
                    .map_err(|e| RootError::Io {
                        path: self.journal_path.clone(),
                        source: e,
                    })?;
                file.flush().map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;
                return Err(RootError::Io {
                    path: self.journal_path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Injected delimiter write failure",
                    ),
                });
            }
            _ => {
                file.write_all(&framed_bytes).map_err(|e| RootError::Io {
                    path: self.journal_path.clone(),
                    source: e,
                })?;
            }
        }

        if fault == JournalFault::FailFlush {
            return Err(RootError::Io {
                path: self.journal_path.clone(),
                source: std::io::Error::other("Injected flush failure"),
            });
        }

        file.flush().map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        if fault == JournalFault::CrashAfterWriteBeforeSync {
            return Err(RootError::Io {
                path: self.journal_path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Injected crash after write before sync",
                ),
            });
        }

        if fault == JournalFault::FailSyncData {
            return Err(RootError::Io {
                path: self.journal_path.clone(),
                source: std::io::Error::other("Injected sync_data failure"),
            });
        }

        // Synchronize data to physical storage
        file.sync_data().map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        if fault == JournalFault::FailParentDirSync {
            return Err(RootError::Io {
                path: self.journal_path.clone(),
                source: std::io::Error::other("Injected parent directory sync failure"),
            });
        }

        // Synchronize parent directory metadata where supported
        if let Some(parent) = self.journal_path.parent() {
            if let Ok(pfile) = File::open(parent) {
                let _ = pfile.sync_all();
            }
        }

        if fault == JournalFault::CrashAfterSyncBeforeReturn {
            return Err(RootError::Io {
                path: self.journal_path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Injected crash after sync before return",
                ),
            });
        }

        Ok(())
    }

    /// Appends raw bytes directly to the journal file for fault-injection testing.
    pub fn append_raw_bytes_for_testing(&mut self, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .map_err(|e| RootError::Io {
                path: self.journal_path.clone(),
                source: e,
            })?;

        file.write_all(bytes).map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        file.sync_data().map_err(|e| RootError::Io {
            path: self.journal_path.clone(),
            source: e,
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_standard_vector() {
        // Standard IEEE 802.3 test vector
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_framed_record_round_trip() {
        let record = JournalRecord {
            transaction_id: "tx_test_123".into(),
            timestamp_epoch_secs: 1700000000,
            state: TransactionState::Prepared,
            original_path: PathBuf::from("/tmp/test.txt"),
            quarantine_path: Some(PathBuf::from("/tmp/quarantine/test.txt")),
            device_id: 100,
            inode: 200,
            size_bytes: 4096,
            sha256: Some("abcd1234".into()),
            reason: "test reason".into(),
            failure_reason: None,
        };

        let encoded = encode_framed_record(&record).expect("Encode");
        assert_eq!(&encoded[0..4], JOURNAL_MAGIC.as_slice());
        assert_eq!(encoded.last(), Some(&b'\n'));

        let (decoded, consumed) = decode_framed_record(&encoded).expect("Decode");
        assert_eq!(decoded, record);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_checksum_mismatch_detected() {
        let record = JournalRecord {
            transaction_id: "tx_corrupt_test".into(),
            timestamp_epoch_secs: 1000,
            state: TransactionState::Prepared,
            original_path: PathBuf::from("/a"),
            quarantine_path: None,
            device_id: 1,
            inode: 1,
            size_bytes: 10,
            sha256: None,
            reason: "ok".into(),
            failure_reason: None,
        };

        let mut encoded = encode_framed_record(&record).unwrap();
        // Corrupt a byte in payload
        let payload_idx = HEADER_SIZE + 2;
        encoded[payload_idx] ^= 0xFF;

        let res = decode_framed_record(&encoded);
        assert!(matches!(res, Err(RootError::JournalError { .. })));
    }
}
