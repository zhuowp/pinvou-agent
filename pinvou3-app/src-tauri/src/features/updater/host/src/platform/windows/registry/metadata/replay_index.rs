//! Ephemeral protected high-water index. No transaction in this module commits.
use super::*;
use pinvou_upgrade_codec::{Document, InputKind, RootPolicyShape, decode_canonical_envelope};
use pinvou_upgrade_metadata_owner::{OwnedPriorWater, WaterUpdate};
use serde::{Deserialize, Serialize};
use serde_json::json;

const SCRATCH: &str = "metadata-replay-index-v1";

pub(super) struct Index {
    transaction: Handle,
    path: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseLink {
    batch: u64,
    context_sha256: String,
    water_sha256: String,
    original_sha256: String,
    root_sha256: String,
}

pub(super) fn document(raw: &[u8]) -> Result<Document> {
    Document::parse(raw, InputKind::Metadata).map_err(|_| Error::StateCorrupt)
}

pub(super) fn root(raw: &[u8]) -> Result<RootPolicyShape> {
    decode_canonical_envelope(raw, InputKind::Metadata)
        .map_err(|_| Error::StateCorrupt)?
        .check_full_schema()
        .map_err(|_| Error::StateCorrupt)?
        .envelope()
        .signed()
        .root_policy_shape()
        .map_err(|_| Error::StateCorrupt)
}

fn canonical(doc: &Document) -> Result<Vec<u8>> {
    doc.canonical_bytes().map_err(|_| Error::StateCorrupt)
}

fn checked_water(raw: &[u8], context: &[u8]) -> Result<Document> {
    let record = document(raw)?;
    if canonical(&record)? != raw
        || canonical(&document(&json::encode(&record.value()["scope"], false)?)?)? != context
        || record.value().as_object().is_none_or(|v| v.len() != 3)
        || !record.value()["version"]
            .as_f64()
            .is_some_and(|n| (1.0..=json::SAFE_MAX as f64).contains(&n) && n.fract() == 0.0)
        || !record.value()["envelopeSha256"]
            .as_str()
            .is_some_and(json::digest)
    {
        return Err(Error::StateCorrupt);
    }
    Ok(record)
}

fn context(raw: &[u8]) -> Result<Document> {
    let envelope = decode_canonical_envelope(raw, InputKind::Metadata)
        .map_err(|_| Error::StateCorrupt)?
        .check_full_schema()
        .map_err(|_| Error::StateCorrupt)?;
    let value = envelope.envelope().signed().value();
    document(&json::encode(
        &json!({"role":value["role"], "product":value["product"],
            "component":value["component"], "scope":value["scope"]}),
        false,
    )?)
}

fn check_original(raw: &[u8], expected_context: &[u8], record: &Document) -> Result<()> {
    let envelope = decode_canonical_envelope(raw, InputKind::Metadata)
        .map_err(|_| Error::StateCorrupt)?
        .check_full_schema()
        .map_err(|_| Error::StateCorrupt)?;
    let signed = envelope.envelope().signed().value();
    let version = match signed["role"].as_str() {
        Some("release") => &signed["revision"],
        Some("timestamp" | "snapshot" | "target") => &signed["version"],
        _ => return Err(Error::StateCorrupt),
    };
    if canonical(&context(raw)?)? != expected_context
        || *version != record.value()["version"]
        || record.value()["envelopeSha256"].as_str() != Some(json::sha256(raw).as_str())
    {
        return Err(Error::StateCorrupt);
    }
    pinvou_upgrade_codec::assert_supplied_high_water(envelope.envelope(), record)
        .map_err(|_| Error::StateCorrupt)
}

impl Index {
    #[allow(unsafe_code)]
    pub(super) fn new(store: &Store) -> Result<Self> {
        let transaction = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        // Reopen protected private through Store in the scratch transaction;
        // never transplant a handle from the source's held read transaction.
        let private = store
            .key(true, Some(&transaction))?
            .ok_or(Error::SetupIncomplete)?;
        let candidate = create(private.0, SCRATCH, &transaction, false, true)?;
        drop(candidate);
        drop(private);
        Ok(Self {
            transaction,
            path: format!("{}\\private\\{}", store.path, SCRATCH),
        })
    }

    fn key(&self, context: &[u8], writable: bool) -> Result<Option<Key>> {
        let scratch = open(
            HKEY_LOCAL_MACHINE,
            &self.path,
            writable,
            Some(&self.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let hash = json::sha256(context);
        let path = format!("{}\\{}", &hash[..2], &hash[2..]);
        if writable {
            let shard = create(scratch.0, &hash[..2], &self.transaction, false, false)?;
            Ok(Some(create(
                shard.0,
                &hash[2..],
                &self.transaction,
                false,
                false,
            )?))
        } else {
            open(scratch.0, &path, false, Some(&self.transaction))
        }
    }

    pub(super) fn read(&self, requested: &Document) -> Result<Option<OwnedPriorWater>> {
        let bytes = canonical(requested)?;
        let Some(key) = self.key(&bytes, false)? else {
            return Ok(None);
        };
        let release = requested.value()["role"] == "release";
        let expected = if release {
            &["Context", "Water", "Original", "Root", "Link"][..]
        } else {
            &["Context", "Water"][..]
        };
        exact_names(&names(&key, true, expected.len() as u32)?, expected)?;
        exact_names(&names(&key, false, 0)?, &[])?;
        if read_limited(&key, "Context", json::RECORD_MAX)? != bytes {
            return Err(Error::StateCorrupt);
        }
        let water = read_limited(&key, "Water", json::RECORD_MAX)?;
        let record = checked_water(&water, &bytes)?;
        let previous_release = if release {
            let raw = read_limited(&key, "Original", json::RECORD_MAX)?;
            let root_bytes = read_limited(&key, "Root", json::RECORD_MAX)?;
            let link_bytes = read_limited(&key, "Link", json::FRAME_MAX)?;
            let link: ReleaseLink = json::decode(&link_bytes, false)?;
            if json::encode(&link, false)? != link_bytes
                || link.batch == 0
                || link.batch > json::SAFE_MAX
                || link.context_sha256 != json::sha256(&bytes)
                || link.water_sha256 != json::sha256(&water)
                || link.original_sha256 != json::sha256(&raw)
                || link.root_sha256 != json::sha256(&root_bytes)
            {
                return Err(Error::StateCorrupt);
            }
            check_original(&raw, &bytes, &record)?;
            let accepting_root = root(&root_bytes)?;
            if requested.value()["product"].as_str() != Some(accepting_root.product()) {
                return Err(Error::StateCorrupt);
            }
            Some((raw, accepting_root))
        } else {
            None
        };
        Ok(Some(OwnedPriorWater {
            record,
            previous_release,
        }))
    }

    // Called only after the entire batch decision succeeds. No read performed
    // during that decision can observe the current batch's proposed updates.
    pub(super) fn put(
        &mut self,
        update: &WaterUpdate,
        original: &[u8],
        accepting_root: &[u8],
        batch: u64,
    ) -> Result<()> {
        let requested = document(update.context())?;
        let water = json::encode(
            &json!({"scope":requested.value(),
            "version":update.version(), "envelopeSha256":update.sha256()}),
            false,
        )?;
        let record = document(&water)?;
        check_original(original, update.context(), &record)?;
        // Preserve the original accepting Root for an idempotent Release.
        if let Some(old) = self.read(&requested)?
            && canonical(&old.record)? == water
        {
            return Ok(());
        }
        let key = self
            .key(update.context(), true)?
            .ok_or(Error::StateCorrupt)?;
        write(&key, "Context", update.context())?;
        write(&key, "Water", &water)?;
        if requested.value()["role"] == "release" {
            write(&key, "Original", original)?;
            write(&key, "Root", accepting_root)?;
            write(
                &key,
                "Link",
                &json::encode(
                    &ReleaseLink {
                        batch,
                        context_sha256: json::sha256(update.context()),
                        water_sha256: json::sha256(&water),
                        original_sha256: json::sha256(original),
                        root_sha256: json::sha256(accepting_root),
                    },
                    false,
                )?,
            )?;
        }
        drop(key);
        let checked = self.read(&requested)?.ok_or(Error::StateCorrupt)?;
        if canonical(&checked.record)? != water {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_water_requires_canonical_exact_context_version_and_hash() {
        let context = serde_json::json!({"role":"release","product":"pinvou","component":"app",
            "scope":{"releaseId":"release-a"}});
        let context_bytes = json::encode(&context, false).unwrap();
        let valid =
            serde_json::json!({"scope":context,"version":2,"envelopeSha256":"a".repeat(64)});
        let raw = json::encode(&valid, false).unwrap();
        assert!(checked_water(&raw, &context_bytes).is_ok());
        let mut other = context.clone();
        other["component"] = "other".into();
        assert!(checked_water(&raw, &json::encode(&other, false).unwrap()).is_err());
        for invalid in [
            serde_json::json!(0),
            serde_json::json!(1.5),
            serde_json::json!(-1),
            serde_json::json!(9_007_199_254_740_992u64),
        ] {
            let mut changed = valid.clone();
            changed["version"] = invalid;
            assert!(
                checked_water(&json::encode(&changed, false).unwrap(), &context_bytes).is_err()
            );
        }
        let mut changed = valid;
        changed["envelopeSha256"] = "A".repeat(64).into();
        assert!(checked_water(&json::encode(&changed, false).unwrap(), &context_bytes).is_err());
        let noncanonical = serde_json::to_vec_pretty(document(&raw).unwrap().value()).unwrap();
        assert!(checked_water(&noncanonical, &context_bytes).is_err());
    }
}
