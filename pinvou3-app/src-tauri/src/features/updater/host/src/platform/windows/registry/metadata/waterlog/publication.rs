//! Uncommitted append, finalized only with a genuine same-source observation.
use super::*;
use crate::platform::windows::{
    installed::StartedServiceContext,
    registry::time::{FinalMetadataObservation, LiveTimeReadSet},
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in super::super) struct Position {
    pub index: u64,
    pub record_sha256: String,
    pub timestamp_sha256: String,
    pub snapshot_sha256: String,
    pub member_count: u32,
    pub member_chain_sha256: String,
    pub head_sha256: String,
}

fn position(record: &Batch, genesis: &[u8]) -> Result<Position> {
    let record_sha256 = json::sha256(&json::encode(record, false)?);
    let head = Head {
        waterlog_version: 1,
        metadata_genesis_sha256: json::sha256(genesis),
        count: record.index,
        last_record_sha256: Some(record_sha256.clone()),
    };
    Ok(Position {
        index: record.index,
        record_sha256,
        timestamp_sha256: record.timestamp_sha256.clone(),
        snapshot_sha256: record.snapshot_sha256.clone(),
        member_count: record.member_count,
        member_chain_sha256: record.member_chain_sha256.clone(),
        head_sha256: json::sha256(&json::encode(&head, false)?),
    })
}

impl StructuralBatch<'_> {
    pub(in super::super) fn position(&self, genesis: &[u8]) -> Result<Position> {
        position(&self.record, genesis)
    }
}

pub(in super::super) struct Pending<'tx> {
    journal: Key,
    row: Key,
    members: Key,
    tx: &'tx Handle,
    genesis: Vec<u8>,
    before: Vec<u8>,
    record: Batch,
    hashes: Vec<String>,
}

/// Caller has completed all prior-water callbacks and old-prefix rechecks.
pub(in super::super) fn copy_in<'tx>(
    metadata: &Key,
    genesis: &[u8],
    tx: &'tx Handle,
    timestamp: &[u8],
    snapshot: &[u8],
    count: u32,
    mut member: impl FnMut(u32) -> Result<Vec<u8>>,
) -> Result<Pending<'tx>> {
    if count > 4096 {
        return Err(Error::StateCorrupt);
    }
    let journal = open(metadata.0, "waterlog", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let before = read(&journal, "Head")?;
    let head = parse_head(&before, genesis)?;
    let index = head
        .count
        .checked_add(1)
        .filter(|n| *n < json::SAFE_MAX)
        .ok_or(Error::Unavailable)?;
    let entries = open(journal.0, "entries", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    exact_counts(&entries, 0, head.count)?;
    let row = create(entries.0, &revision_name(index), tx, false, true)?;
    let members = create(row.0, "members", tx, false, true)?;
    write(&row, "Timestamp", timestamp)?;
    write(&row, "Snapshot", snapshot)?;
    let mut chain = member_chain_start();
    let mut hashes = Vec::with_capacity(count as usize);
    for i in 1..=count {
        super::super::super::super::time_cancel::check()?;
        let raw = member(i)?;
        chain = member_chain_step(&chain, i, &raw)?;
        hashes.push(json::sha256(&raw));
        let item = create(members.0, &revision_name(u64::from(i)), tx, false, true)?;
        write(&item, "Original", &raw)?;
    }
    let record = Batch {
        version: 1,
        index,
        previous_sha256: head
            .last_record_sha256
            .unwrap_or_else(|| json::sha256(&before)),
        sample_sha256: String::new(),
        global_policy_sha256: String::new(),
        role_policy_sha256: String::new(),
        timestamp_sha256: json::sha256(timestamp),
        snapshot_sha256: json::sha256(snapshot),
        member_count: count,
        member_chain_sha256: chain,
    };
    Ok(Pending {
        journal,
        row,
        members,
        tx,
        genesis: genesis.to_vec(),
        before,
        record,
        hashes,
    })
}

impl Pending<'_> {
    /// Reread actual final copies before final native counter acquisition.
    pub(in super::super) fn recheck_originals(&self) -> Result<()> {
        if read(&self.journal, "Head")? != self.before {
            return Err(Error::ScopeConflict);
        }
        check_object(
            &self.row,
            "Timestamp",
            json::RECORD_MAX,
            &self.record.timestamp_sha256,
        )?;
        check_object(
            &self.row,
            "Snapshot",
            json::RECORD_MAX,
            &self.record.snapshot_sha256,
        )?;
        exact_counts(&self.members, 0, u64::from(self.record.member_count))?;
        let mut chain = member_chain_start();
        for i in 1..=self.record.member_count {
            let raw = read_member_raw(&self.members, self.tx, i)?;
            if self.hashes.get(i as usize - 1) != Some(&json::sha256(&raw)) {
                return Err(Error::ScopeConflict);
            }
            chain = member_chain_step(&chain, i, &raw)?;
        }
        if chain != self.record.member_chain_sha256 {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }

    pub(in super::super) fn finish(
        mut self,
        private: &Key,
        host: &StartedServiceContext,
        source: &LiveTimeReadSet<'_>,
        sample: &FinalMetadataObservation<'_, '_, '_>,
        global: &[u8],
        roles: &[u8],
    ) -> Result<Position> {
        source.require_metadata_transaction(private, self.tx)?;
        let sample = sample.bytes_for(host, source)?;
        for (name, raw) in [
            ("Sample", sample.as_slice()),
            ("GlobalPolicy", global),
            ("RolePolicy", roles),
        ] {
            write(&self.row, name, raw)?;
        }
        self.record.sample_sha256 = json::sha256(&sample);
        self.record.global_policy_sha256 = json::sha256(global);
        self.record.role_policy_sha256 = json::sha256(roles);
        let raw = json::encode(&self.record, false)?;
        write(&self.row, "Record", &raw)?;
        let next = Head {
            waterlog_version: 1,
            metadata_genesis_sha256: json::sha256(&self.genesis),
            count: self.record.index,
            last_record_sha256: Some(json::sha256(&raw)),
        };
        write(&self.journal, "Head", &json::encode(&next, false)?)?;
        position(&self.record, &self.genesis)
    }
}
