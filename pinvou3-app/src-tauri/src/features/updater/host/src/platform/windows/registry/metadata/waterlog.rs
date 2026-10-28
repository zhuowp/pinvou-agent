//! Protected original-byte water history and atomic historical observations.
use super::*;
use serde::{Deserialize, Serialize};
pub(super) mod publication;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EmptyHead {
    waterlog_version: u8,
    metadata_genesis_sha256: String,
    count: u8,
}

fn empty_head(metadata_genesis: &[u8]) -> Result<Vec<u8>> {
    json::encode(
        &EmptyHead {
            waterlog_version: 1,
            metadata_genesis_sha256: json::sha256(metadata_genesis),
            count: 0,
        },
        false,
    )
}

/// Storage shape only: it does not authenticate signatures, time, policy,
/// watermarks or absence of a context. No writer or acceptance gate uses it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Head {
    waterlog_version: u8,
    metadata_genesis_sha256: String,
    count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_record_sha256: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Batch {
    version: u8,
    index: u64,
    previous_sha256: String,
    sample_sha256: String,
    global_policy_sha256: String,
    role_policy_sha256: String,
    timestamp_sha256: String,
    snapshot_sha256: String,
    member_count: u32,
    member_chain_sha256: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberLink<'a> {
    previous_sha256: &'a str,
    index: u32,
    size: usize,
    sha256: String,
}
fn member_chain_start() -> String {
    json::sha256(b"pinvou-waterlog-members-v1")
}
fn member_chain_step(previous: &str, index: u32, raw: &[u8]) -> Result<String> {
    if !json::digest(previous) || index == 0 || raw.is_empty() || raw.len() > json::RECORD_MAX {
        return Err(Error::StateCorrupt);
    }
    Ok(json::sha256(&json::encode(
        &MemberLink {
            previous_sha256: previous,
            index,
            size: raw.len(),
            sha256: json::sha256(raw),
        },
        false,
    )?))
}
fn parse_head(raw: &[u8], genesis: &[u8]) -> Result<Head> {
    let head: Head = json::decode(raw, false)?;
    if json::encode(&head, false)? != raw
        || head.waterlog_version != 1
        || head.metadata_genesis_sha256 != json::sha256(genesis)
        || head.count > json::SAFE_MAX
        || (head.count == 0) != head.last_record_sha256.is_none()
        || head
            .last_record_sha256
            .as_ref()
            .is_some_and(|v| !json::digest(v))
    {
        return Err(Error::StateCorrupt);
    }
    Ok(head)
}
fn parse_batch(raw: &[u8], index: u64, previous: &str) -> Result<Batch> {
    let batch: Batch = json::decode(raw, false)?;
    if json::encode(&batch, false)? != raw
        || batch.version != 1
        || batch.index != index
        || batch.previous_sha256 != previous
        || batch.member_count > 4096
        || [
            &batch.sample_sha256,
            &batch.global_policy_sha256,
            &batch.role_policy_sha256,
            &batch.timestamp_sha256,
            &batch.snapshot_sha256,
            &batch.member_chain_sha256,
        ]
        .iter()
        .any(|s| !json::digest(s))
    {
        return Err(Error::StateCorrupt);
    }
    Ok(batch)
}

/// Position DATA only. Matching Head cannot replace the complete traversal.
pub(super) fn head_bytes_in(metadata: &Key, genesis: &[u8], tx: &Handle) -> Result<Vec<u8>> {
    let key = open(metadata.0, "waterlog", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let raw = read(&key, "Head")?;
    parse_head(&raw, genesis)?;
    Ok(raw)
}
fn check_object(key: &Key, name: &str, limit: usize, expected: &str) -> Result<Vec<u8>> {
    let raw = read_limited(key, name, limit)?;
    if raw.is_empty() || json::sha256(&raw) != expected {
        return Err(Error::StateCorrupt);
    }
    Ok(raw)
}

/// One bounded native batch. Objects remain untrusted until the caller has
/// verified historical time, signatures, graph and all prior watermarks.
#[allow(dead_code)]
pub(super) struct StructuralBatch<'tx> {
    key: Key,
    members: Key,
    tx: &'tx Handle,
    record: Batch,
    member_hashes: Vec<String>,
}
fn read_member_raw(members: &Key, tx: &Handle, index: u32) -> Result<Vec<u8>> {
    let key = open(members.0, &revision_name(u64::from(index)), false, Some(tx))?
        .ok_or(Error::StateCorrupt)?;
    exact_counts(&key, 1, 0)?;
    let raw = read_limited(&key, "Original", json::RECORD_MAX)?;
    if raw.is_empty() {
        return Err(Error::StateCorrupt);
    }
    Ok(raw)
}
fn load_batch<'tx>(
    key: Key,
    members: Key,
    tx: &'tx Handle,
    record: Batch,
) -> Result<StructuralBatch<'tx>> {
    exact_counts(&members, 0, u64::from(record.member_count))?;
    let mut chain = member_chain_start();
    let mut member_hashes = Vec::with_capacity(record.member_count as usize);
    for index in 1..=record.member_count {
        let raw = read_member_raw(&members, tx, index)?;
        chain = member_chain_step(&chain, index, &raw)?;
        member_hashes.push(json::sha256(&raw));
    }
    if chain != record.member_chain_sha256 {
        return Err(Error::StateCorrupt);
    }
    Ok(StructuralBatch {
        key,
        members,
        tx,
        record,
        member_hashes,
    })
}
#[allow(dead_code)]
impl StructuralBatch<'_> {
    pub(super) fn index(&self) -> u64 {
        self.record.index
    }
    pub(super) fn count(&self) -> u32 {
        self.record.member_count
    }
    pub(super) fn sample(&self) -> Result<Vec<u8>> {
        check_object(
            &self.key,
            "Sample",
            json::FRAME_MAX,
            &self.record.sample_sha256,
        )
    }
    pub(super) fn global_policy(&self) -> Result<Vec<u8>> {
        check_object(
            &self.key,
            "GlobalPolicy",
            json::RECORD_MAX,
            &self.record.global_policy_sha256,
        )
    }
    pub(super) fn role_policy(&self) -> Result<Vec<u8>> {
        check_object(
            &self.key,
            "RolePolicy",
            json::RECORD_MAX,
            &self.record.role_policy_sha256,
        )
    }
    pub(super) fn timestamp(&self) -> Result<Vec<u8>> {
        check_object(
            &self.key,
            "Timestamp",
            json::RECORD_MAX,
            &self.record.timestamp_sha256,
        )
    }
    pub(super) fn snapshot(&self) -> Result<Vec<u8>> {
        check_object(
            &self.key,
            "Snapshot",
            json::RECORD_MAX,
            &self.record.snapshot_sha256,
        )
    }
    pub(super) fn member(&self, index: u32) -> Result<Vec<u8>> {
        if index == 0 || index > self.record.member_count {
            return Err(Error::StateCorrupt);
        }
        let raw = read_member_raw(&self.members, self.tx, index)?;
        if self.member_hashes.get(index as usize - 1) != Some(&json::sha256(&raw)) {
            return Err(Error::StateCorrupt);
        }
        Ok(raw)
    }
    fn verify_objects(&self) -> Result<()> {
        self.sample()?;
        self.global_policy()?;
        self.role_policy()?;
        self.timestamp()?;
        self.snapshot()?;
        exact_counts(&self.members, 0, u64::from(self.record.member_count))?;
        let mut chain = member_chain_start();
        for index in 1..=self.record.member_count {
            let raw = self.member(index)?;
            chain = member_chain_step(&chain, index, &raw)?;
        }
        if chain != self.record.member_chain_sha256 {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}

/// Stream the complete actual chain under the caller's held native TxR. The
/// visitor sees provisional data and must not publish or grant rights; any
/// scratch index it builds is usable only after this returns and after the
/// separate complete historical signature/time/watermark verification.
#[allow(dead_code)]
pub(super) fn visit_structure_in(
    metadata: &Key,
    genesis: &[u8],
    tx: &Handle,
    visit: impl FnMut(&StructuralBatch<'_>) -> Result<()>,
) -> Result<()> {
    visit_structure_bound_in(metadata, genesis, tx, None, visit)
}

/// Historical prefix DATA only. Authenticate the complete current structural
/// source, but expose batches only through the exact supplied retained Head.
/// The enclosing owner must independently authenticate that Head's provenance.
pub(super) fn visit_structure_prefix_in(
    metadata: &Key,
    genesis: &[u8],
    tx: &Handle,
    expected_head: &[u8],
    visit: impl FnMut(&StructuralBatch<'_>) -> Result<()>,
) -> Result<()> {
    visit_structure_bound_in(metadata, genesis, tx, Some(expected_head), visit)
}

fn visit_structure_bound_in(
    metadata: &Key,
    genesis: &[u8],
    tx: &Handle,
    expected_head: Option<&[u8]>,
    mut visit: impl FnMut(&StructuralBatch<'_>) -> Result<()>,
) -> Result<()> {
    let key = open(metadata.0, "waterlog", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    exact_counts(&key, 2, 1)?;
    let initial = empty_head(genesis)?;
    if read(&key, "Genesis")? != initial {
        return Err(Error::StateCorrupt);
    }
    let head_raw = read(&key, "Head")?;
    let head = parse_head(&head_raw, genesis)?;
    if head.count == 0 && head_raw != initial {
        return Err(Error::StateCorrupt);
    }
    let prefix = expected_head
        .map(|raw| parse_head(raw, genesis))
        .transpose()?;
    if let Some(prefix) = &prefix {
        if prefix.count > head.count
            || (prefix.count == 0 && expected_head != Some(initial.as_slice()))
        {
            return Err(Error::StateCorrupt);
        }
    }
    let entries = open(key.0, "entries", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    exact_counts(&entries, 0, head.count)?;
    let mut previous = json::sha256(&initial);
    for index in 1..=head.count {
        super::super::super::time_cancel::check()?;
        let row =
            open(entries.0, &revision_name(index), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        exact_counts(&row, 6, 1)?;
        let raw = read(&row, "Record")?;
        let record = parse_batch(&raw, index, &previous)?;
        let members = open(row.0, "members", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let batch = load_batch(row, members, tx, record)?;
        batch.verify_objects()?;
        if prefix.as_ref().is_none_or(|prefix| index <= prefix.count) {
            visit(&batch)?;
        }
        // Recheck after visitor reads: all source objects and ordering must
        // still match before the provisional batch can advance.
        batch.verify_objects()?;
        exact_counts(&batch.key, 6, 1)?;
        if read(&batch.key, "Record")? != raw {
            return Err(Error::ScopeConflict);
        }
        previous = json::sha256(&raw);
        require_prefix_terminal(prefix.as_ref(), index, &previous)?;
    }
    if head.count > 0 && head.last_record_sha256.as_deref() != Some(previous.as_str()) {
        return Err(Error::StateCorrupt);
    }
    // A later visitor must not be able to change a previously visited batch.
    // Revisit the whole protected source before accepting the traversal.
    exact_counts(&key, 2, 1)?;
    exact_counts(&entries, 0, head.count)?;
    if read(&key, "Genesis")? != initial {
        return Err(Error::ScopeConflict);
    }
    let mut second_previous = json::sha256(&initial);
    for index in 1..=head.count {
        super::super::super::time_cancel::check()?;
        let row =
            open(entries.0, &revision_name(index), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        exact_counts(&row, 6, 1)?;
        let raw = read(&row, "Record")?;
        let record = parse_batch(&raw, index, &second_previous)?;
        let members = open(row.0, "members", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        load_batch(row, members, tx, record)?.verify_objects()?;
        second_previous = json::sha256(&raw);
        require_prefix_terminal(prefix.as_ref(), index, &second_previous)?;
    }
    if second_previous != previous {
        return Err(Error::ScopeConflict);
    }
    exact_counts(&key, 2, 1)?;
    exact_counts(&entries, 0, head.count)?;
    if read(&key, "Head")? != head_raw || read(&key, "Genesis")? != initial {
        return Err(Error::ScopeConflict);
    }
    Ok(())
}

fn require_prefix_terminal(prefix: Option<&Head>, index: u64, digest: &str) -> Result<()> {
    if let Some(prefix) = prefix {
        if prefix.count == index && prefix.last_record_sha256.as_deref() != Some(digest) {
            return Err(Error::StateCorrupt);
        }
    }
    Ok(())
}

/// Native structural fixture only. The values are not signed metadata and
/// this test never treats successful traversal as an acceptance decision.
#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_test_structure_in(
    metadata: &Key,
    genesis: &[u8],
    tx: &Handle,
) -> Result<()> {
    let key = open(metadata.0, "waterlog", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let entries = open(key.0, "entries", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let row = create(entries.0, &revision_name(1), tx, false, true)?;
    let members = create(row.0, "members", tx, false, true)?;
    let item = create(members.0, &revision_name(1), tx, false, true)?;
    write(&item, "Original", b"member")?;
    for (name, raw) in [
        ("Sample", &b"sample"[..]),
        ("GlobalPolicy", &b"global"[..]),
        ("RolePolicy", &b"roles"[..]),
        ("Timestamp", &b"timestamp"[..]),
        ("Snapshot", &b"snapshot"[..]),
    ] {
        write(&row, name, raw)?;
    }
    let record = Batch {
        version: 1,
        index: 1,
        previous_sha256: json::sha256(&empty_head(genesis)?),
        sample_sha256: json::sha256(b"sample"),
        global_policy_sha256: json::sha256(b"global"),
        role_policy_sha256: json::sha256(b"roles"),
        timestamp_sha256: json::sha256(b"timestamp"),
        snapshot_sha256: json::sha256(b"snapshot"),
        member_count: 1,
        member_chain_sha256: member_chain_step(&member_chain_start(), 1, b"member")?,
    };
    let raw = json::encode(&record, false)?;
    write(&row, "Record", &raw)?;
    let head = Head {
        waterlog_version: 1,
        metadata_genesis_sha256: json::sha256(genesis),
        count: 1,
        last_record_sha256: Some(json::sha256(&raw)),
    };
    let captured_head = json::encode(&head, false)?;
    write(&key, "Head", &captured_head)?;
    let mut visited = 0;
    visit_structure_in(metadata, genesis, tx, |batch| {
        if batch.index() != 1 || batch.count() != 1 || batch.member(1)? != b"member" {
            return Err(Error::StateCorrupt);
        }
        visited += 1;
        Ok(())
    })?;
    if visited != 1 {
        return Err(Error::StateCorrupt);
    }
    // A visitor may hold a writable handle: replacement then restoration must
    // not let it consume bytes different from the prevalidated member.
    visit_structure_in(metadata, genesis, tx, |batch| {
        write(&item, "Original", b"temporary")?;
        let rejected = batch.member(1).is_err();
        write(&item, "Original", b"member")?;
        if !rejected {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    })?;
    write(&item, "Original", b"replaced")?;
    if visit_structure_in(metadata, genesis, tx, |_| Ok(())).is_ok() {
        return Err(Error::StateCorrupt);
    }
    write(&item, "Original", b"member")?;
    write(&row, "Timestamp", b"wrong")?;
    if visit_structure_in(metadata, genesis, tx, |_| Ok(())).is_ok() {
        return Err(Error::StateCorrupt);
    }
    write(&row, "Timestamp", b"timestamp")?;
    let second = create(entries.0, &revision_name(2), tx, false, true)?;
    let _second_members = create(second.0, "members", tx, false, true)?;
    for (name, body) in [
        ("Sample", &b"sample"[..]),
        ("GlobalPolicy", &b"global"[..]),
        ("RolePolicy", &b"roles"[..]),
        ("Timestamp", &b"timestamp"[..]),
        ("Snapshot", &b"snapshot"[..]),
    ] {
        write(&second, name, body)?;
    }
    let mut second_record: Batch = json::decode(&raw, false)?;
    second_record.index = 2;
    second_record.previous_sha256 = json::sha256(&raw);
    second_record.member_count = 0;
    second_record.member_chain_sha256 = member_chain_start();
    let second_raw = json::encode(&second_record, false)?;
    write(&second, "Record", &second_raw)?;
    let second_head = Head {
        count: 2,
        last_record_sha256: Some(json::sha256(&second_raw)),
        ..head
    };
    write(&key, "Head", &json::encode(&second_head, false)?)?;
    visit_structure_in(metadata, genesis, tx, |_| Ok(()))?;
    let mut prefix_visits = 0;
    visit_structure_prefix_in(metadata, genesis, tx, &captured_head, |batch| {
        assert_eq!(batch.index(), 1);
        prefix_visits += 1;
        Ok(())
    })?;
    assert_eq!(prefix_visits, 1);
    visit_structure_prefix_in(metadata, genesis, tx, &empty_head(genesis)?, |_| {
        Err(Error::StateCorrupt)
    })?;
    write(&second, "Timestamp", b"bad-suffix")?;
    assert!(
        visit_structure_prefix_in(metadata, genesis, tx, &empty_head(genesis)?, |_| Ok(()))
            .is_err()
    );
    write(&second, "Timestamp", b"timestamp")?;
    if visit_structure_in(metadata, genesis, tx, |batch| {
        if batch.index() == 2 {
            write(&row, "Timestamp", b"late mutation")?;
        }
        Ok(())
    })
    .is_ok()
    {
        return Err(Error::StateCorrupt);
    }
    write(&row, "Timestamp", b"timestamp")?;
    if visit_structure_in(metadata, genesis, tx, |batch| {
        if batch.index() == 2 {
            write(&key, "Genesis", b"changed")?;
        }
        Ok(())
    })
    .is_ok()
    {
        return Err(Error::StateCorrupt);
    }
    write(&key, "Genesis", &empty_head(genesis)?)?;
    if visit_structure_in(metadata, genesis, tx, |batch| {
        if batch.index() == 2 {
            drop(create(entries.0, "extra", tx, false, true)?);
        }
        Ok(())
    })
    .is_ok()
    {
        return Err(Error::StateCorrupt);
    }
    // Deliberately leave this test's TxR damaged; dropping it rolls it back.
    Ok(())
}

/// Called only by the original fresh-install transaction. Never heals missing
/// state on existing installs. The parent metadata Genesis binds the profile.
pub(super) fn initialize_in(metadata: &Key, genesis: &[u8], tx: &Handle) -> Result<()> {
    let key = create(metadata.0, "waterlog", tx, false, true)?;
    let _entries = create(key.0, "entries", tx, false, true)?;
    let initial = empty_head(genesis)?;
    write(&key, "Genesis", &initial)?;
    write(&key, "Head", &initial)?;
    require_empty_in(metadata, genesis, Some(tx))
}

/// Empty means the exact protected initial head and an actually empty native
/// entries directory, never a missing key, failed query or caller-supplied DTO.
/// This is only a first-install proof; accepting historical water entries
/// requires a separate complete replay and atomic publication implementation.
pub(super) fn require_empty_in(metadata: &Key, genesis: &[u8], tx: Option<&Handle>) -> Result<()> {
    let key = open(metadata.0, "waterlog", false, tx)?.ok_or(Error::StateCorrupt)?;
    let initial = empty_head(genesis)?;
    if read(&key, "Genesis")? != initial || read(&key, "Head")? != initial {
        return Err(Error::StateCorrupt);
    }
    exact_names(&names(&key, true, 2)?, &["Genesis", "Head"])?;
    exact_names(&names(&key, false, 1)?, &["entries"])?;
    let entries = open(key.0, "entries", false, tx)?.ok_or(Error::StateCorrupt)?;
    require_no_entries(&entries)
}

fn count_result(status: u32, values: u32, subkeys: u32) -> Result<()> {
    if status != 0 {
        return Err(Error::Unavailable);
    }
    if values != 0 || subkeys != 0 {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(super) fn exact_counts(key: &Key, expected_values: u64, expected_subkeys: u64) -> Result<()> {
    let mut values = 0;
    let mut subkeys = 0;
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            &mut subkeys,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut values,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(Error::Unavailable);
    }
    if u64::from(values) != expected_values || u64::from(subkeys) != expected_subkeys {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

/// Query native counts so the unnamed default value is also a confirmed extra.
/// A failed query never establishes absence. The key retains its TxR binding.
#[allow(unsafe_code)]
fn require_no_entries(entries: &Key) -> Result<()> {
    let mut values = 0;
    let mut subkeys = 0;
    let status = unsafe {
        RegQueryInfoKeyW(
            entries.0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            &mut subkeys,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut values,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    count_result(status, values, subkeys)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_head_binds_exact_genesis() {
        let first = empty_head(b"one").unwrap();
        assert_eq!(first, empty_head(b"one").unwrap());
        assert_ne!(first, empty_head(b"two").unwrap());
    }
    #[test]
    fn empty_counts_distinguish_confirmed_extras_from_failed_queries() {
        assert_eq!(count_result(0, 0, 0), Ok(()));
        assert_eq!(count_result(0, 1, 0), Err(Error::StateCorrupt));
        assert_eq!(count_result(0, 0, 1), Err(Error::StateCorrupt));
        assert_eq!(count_result(5, 0, 0), Err(Error::Unavailable));
    }
    #[test]
    fn retained_prefix_terminal_is_exact_and_does_not_deny_a_suffix() {
        let prefix = Head {
            waterlog_version: 1,
            metadata_genesis_sha256: "a".repeat(64),
            count: 2,
            last_record_sha256: Some("b".repeat(64)),
        };
        assert!(require_prefix_terminal(Some(&prefix), 1, &"c".repeat(64)).is_ok());
        assert!(require_prefix_terminal(Some(&prefix), 2, &"b".repeat(64)).is_ok());
        assert!(require_prefix_terminal(Some(&prefix), 2, &"c".repeat(64)).is_err());
        assert!(require_prefix_terminal(Some(&prefix), 3, &"c".repeat(64)).is_ok());
    }
    #[test]
    fn structural_head_and_member_chain_reject_reordering_and_wrong_binding() {
        let genesis = b"profile genesis";
        let empty = empty_head(genesis).unwrap();
        assert_eq!(parse_head(&empty, genesis).unwrap().count, 0);
        assert!(parse_head(&empty, b"other genesis").is_err());
        let first = member_chain_step(&member_chain_start(), 1, b"first").unwrap();
        let ordered = member_chain_step(&first, 2, b"second").unwrap();
        let swapped = member_chain_step(&member_chain_start(), 1, b"second").unwrap();
        assert_ne!(ordered, member_chain_step(&swapped, 2, b"first").unwrap());
        assert!(member_chain_step(&member_chain_start(), 0, b"first").is_err());
        assert!(member_chain_step(&member_chain_start(), 1, &[]).is_err());
        let head = Head {
            waterlog_version: 1,
            metadata_genesis_sha256: json::sha256(genesis),
            count: 1,
            last_record_sha256: Some("a".repeat(64)),
        };
        let raw = json::encode(&head, false).unwrap();
        assert_eq!(parse_head(&raw, genesis).unwrap().count, 1);
        let invalid = Head { count: 0, ..head };
        assert!(parse_head(&json::encode(&invalid, false).unwrap(), genesis).is_err());
        let batch = Batch {
            version: 1,
            index: 1,
            previous_sha256: "a".repeat(64),
            sample_sha256: "b".repeat(64),
            global_policy_sha256: "c".repeat(64),
            role_policy_sha256: "d".repeat(64),
            timestamp_sha256: "e".repeat(64),
            snapshot_sha256: "f".repeat(64),
            member_count: 4096,
            member_chain_sha256: ordered,
        };
        let raw = json::encode(&batch, false).unwrap();
        assert!(parse_batch(&raw, 1, &"a".repeat(64)).is_ok());
        assert!(parse_batch(&raw, 2, &"a".repeat(64)).is_err());
        assert!(parse_batch(&raw, 1, &"b".repeat(64)).is_err());
        let too_many = Batch {
            member_count: 4097,
            ..batch
        };
        assert!(parse_batch(&json::encode(&too_many, false).unwrap(), 1, &"a".repeat(64)).is_err());
    }
}
