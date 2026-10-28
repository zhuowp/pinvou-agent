//! Bounded V2 snapshot metadata descriptors. No graph bodies are copied here.
use super::*;

pub(super) const VALUE_NAMES: [&str; 5] = [
    "Bootstrap",
    "MetadataGenesis",
    "MetadataHead",
    "WaterlogHead",
    "RolePolicy",
];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Descriptor {
    bootstrap: Blob,
    genesis: Blob,
    head: Blob,
    waterlog_head: Blob,
    role_policy: Blob,
}

impl Descriptor {
    pub(super) fn of(pins: &CapturedMetadataPins) -> Self {
        Self {
            bootstrap: Blob::of(&pins.bootstrap),
            genesis: Blob::of(&pins.genesis),
            head: Blob::of(&pins.head),
            waterlog_head: Blob::of(&pins.waterlog_head),
            role_policy: Blob::of(&pins.role_policy),
        }
    }
    pub(super) fn read_in(
        &self,
        key: &Key,
        event: &Event,
        host: &HostRegistration,
        original: &[u8],
    ) -> Result<CapturedMetadataPins> {
        let pins = CapturedMetadataPins {
            bootstrap: self.bootstrap.read(key, "Bootstrap", json::RECORD_MAX)?,
            genesis: self
                .genesis
                .read(key, "MetadataGenesis", json::RECORD_MAX)?,
            head: self.head.read(key, "MetadataHead", json::RECORD_MAX)?,
            waterlog_head: self
                .waterlog_head
                .read(key, "WaterlogHead", json::RECORD_MAX)?,
            role_policy: self.role_policy.read(key, "RolePolicy", json::RECORD_MAX)?,
        };
        super::super::super::metadata::member_source::validate_captured_pins(
            event, host, original, &pins,
        )?;
        Ok(pins)
    }
}

pub(super) fn write_in(key: &Key, pins: &CapturedMetadataPins) -> Result<()> {
    for (name, raw) in VALUE_NAMES.into_iter().zip([
        &pins.bootstrap,
        &pins.genesis,
        &pins.head,
        &pins.waterlog_head,
        &pins.role_policy,
    ]) {
        if raw.is_empty() || raw.len() > json::RECORD_MAX {
            return Err(Error::StateCorrupt);
        }
        write(key, name, raw)?;
    }
    Ok(())
}
