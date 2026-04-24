//! Credentials file for flic-cli. One JSON file per paired button, rewritten
//! atomically as event continuity advances.

use std::path::Path;

use flic_core::{hex, EventResumeState, PairingCredentials};
use serde::{Deserialize, Serialize};

/// Current on-disk schema version. Bump when the shape changes incompatibly.
pub const SCHEMA_VERSION: u32 = 1;

/// Serialized form of [`PairingCredentials`] + event-resume continuity values +
/// metadata. The file is written once at pair time and then rewritten each time
/// event continuity advances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCreds {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    pub pairing_id: u32,
    pub pairing_key_hex: String,
    pub serial_number: String,
    pub button_uuid_hex: String,
    pub firmware_version: u32,
    pub peripheral_id: String,

    #[serde(default)]
    pub resume_event_count: u32,
    #[serde(default)]
    pub resume_boot_id: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated_utc: Option<String>,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

impl StoredCreds {
    pub fn from_pairing(creds: &PairingCredentials, peripheral_id: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            pairing_id: creds.pairing_id,
            pairing_key_hex: hex::encode(&creds.pairing_key),
            serial_number: creds.serial_number.clone(),
            button_uuid_hex: hex::encode(&creds.button_uuid),
            firmware_version: creds.firmware_version,
            peripheral_id: peripheral_id.to_string(),
            resume_event_count: 0,
            resume_boot_id: 0,
            last_updated_utc: None,
        }
    }

    pub fn to_pairing(&self) -> anyhow::Result<PairingCredentials> {
        let pairing_key = hex::decode_fixed::<16>(&self.pairing_key_hex)
            .ok_or_else(|| anyhow::anyhow!("pairing_key_hex is not 32 lowercase hex chars"))?;
        let button_uuid = hex::decode_fixed::<16>(&self.button_uuid_hex)
            .ok_or_else(|| anyhow::anyhow!("button_uuid_hex is not 32 lowercase hex chars"))?;
        Ok(PairingCredentials {
            pairing_id: self.pairing_id,
            pairing_key,
            serial_number: self.serial_number.clone(),
            button_uuid,
            firmware_version: self.firmware_version,
        })
    }

    pub fn resume_state(&self) -> EventResumeState {
        EventResumeState {
            event_count: self.resume_event_count,
            boot_id: self.resume_boot_id,
        }
    }

    pub fn update_resume(&mut self, resume: EventResumeState) {
        self.resume_event_count = resume.event_count;
        self.resume_boot_id = resume.boot_id;
        self.last_updated_utc = Some(chrono::Utc::now().to_rfc3339());
    }
}

/// Atomically writes `creds` as pretty-printed JSON to `path` — writes a sibling
/// temp file, fsyncs it, and renames over `path`. A partial write or crash mid-
/// update leaves either the old contents or the new contents, never a
/// truncated file.
pub fn write_atomic(creds: &StoredCreds, path: &Path) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| Path::new("."), |p| p);

    let json = serde_json::to_string_pretty(creds)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(json.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("persist creds: {e}"))?;
    Ok(())
}

/// Reads and parses a creds file.
pub fn read(path: &Path) -> anyhow::Result<StoredCreds> {
    use anyhow::Context;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading credentials file {}", path.display()))?;
    let creds: StoredCreds = serde_json::from_str(&raw)
        .with_context(|| format!("parsing credentials file {}", path.display()))?;
    Ok(creds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_creds() -> StoredCreds {
        StoredCreds {
            schema_version: SCHEMA_VERSION,
            pairing_id: 0xDEAD_BEEF,
            pairing_key_hex: "00112233445566778899aabbccddeeff".into(),
            serial_number: "BC00-A00001".into(),
            button_uuid_hex: "ffeeddccbbaa99887766554433221100".into(),
            firmware_version: 10,
            peripheral_id: "4cd9f90f-1a53-8ca4-c05b-fb958e3c76c9".into(),
            resume_event_count: 0,
            resume_boot_id: 0,
            last_updated_utc: None,
        }
    }

    #[test]
    fn write_atomic_roundtrips_through_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let creds = sample_creds();

        write_atomic(&creds, &path).expect("write");
        let back = read(&path).expect("read");

        assert_eq!(back.pairing_id, creds.pairing_id);
        assert_eq!(back.pairing_key_hex, creds.pairing_key_hex);
        assert_eq!(back.serial_number, creds.serial_number);
        assert_eq!(back.resume_event_count, creds.resume_event_count);
    }

    #[test]
    fn read_accepts_file_without_schema_version() {
        // Existing paired buttons have files that pre-date the schema_version
        // field. Read must still succeed and treat them as v1.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let legacy = r#"{
            "pairing_id": 1030303098,
            "pairing_key_hex": "00112233445566778899aabbccddeeff",
            "serial_number": "BC00-A00001",
            "button_uuid_hex": "ffeeddccbbaa99887766554433221100",
            "firmware_version": 10,
            "peripheral_id": "abc",
            "resume_event_count": 42,
            "resume_boot_id": 3
        }"#;
        std::fs::write(&path, legacy).unwrap();
        let creds = read(&path).expect("legacy file must still parse");
        assert_eq!(creds.schema_version, SCHEMA_VERSION);
        assert_eq!(creds.resume_event_count, 42);
        assert_eq!(creds.resume_boot_id, 3);
        assert!(creds.last_updated_utc.is_none());
    }

    #[test]
    fn update_resume_sets_fields_and_timestamp() {
        let mut creds = sample_creds();
        assert!(creds.last_updated_utc.is_none());

        creds.update_resume(EventResumeState {
            event_count: 500,
            boot_id: 7,
        });

        assert_eq!(creds.resume_event_count, 500);
        assert_eq!(creds.resume_boot_id, 7);
        assert!(creds.last_updated_utc.is_some());
    }

    #[test]
    fn write_atomic_overwrites_existing_file_without_truncating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");

        let mut creds = sample_creds();
        write_atomic(&creds, &path).expect("first write");

        creds.update_resume(EventResumeState {
            event_count: 999,
            boot_id: 1,
        });
        write_atomic(&creds, &path).expect("second write");

        let back = read(&path).expect("read after overwrite");
        assert_eq!(back.resume_event_count, 999);
        assert_eq!(back.resume_boot_id, 1);
    }
}
