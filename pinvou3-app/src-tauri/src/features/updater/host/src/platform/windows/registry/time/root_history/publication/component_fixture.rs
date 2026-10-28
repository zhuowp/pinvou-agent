//! Public signed DATA loaded in the existing isolated native component runner.
//! Historical rows use the production canonical/blob writers and journal format;
//! they do not claim SCM admission. No transaction in this module is committed.
use super::*;
use crate::platform::windows::registry::time::{self, HistoricalSample};
use crate::{
    identity::{FileTime, ProcessSelector},
    monotonic::CounterObservation,
};
use serde_json::{Value, json as value};

const FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/root-publication-fixture/fixture.json"
));

pub(in crate::platform::windows::registry) fn matches(seed: &Seed) -> bool {
    let fixture: Value = serde_json::from_slice(FIXTURE).expect("public fixture");
    fixture["original"].as_str().unwrap().as_bytes() == seed.original_root_bytes()
}

fn raw(value: &Value) -> Result<Vec<u8>> {
    value
        .as_str()
        .map(|s| s.as_bytes().to_vec())
        .ok_or(Error::StateCorrupt)
}
fn encode(value: Value) -> Result<Vec<u8>> {
    json::encode(&value, false)
}

fn counters(received: bool) -> Result<CounterEvidence> {
    let delta = if received { 200_000 } else { 0 };
    Ok(CounterEvidence::from_data(
        CounterObservation::from_bracket(
            10_000_000 + delta,
            9_000_000 + delta,
            9_000_000 + delta,
            10_000_000 + delta,
        )?,
    ))
}
fn incarnation() -> Incarnation {
    Incarnation {
        host_epoch: 1,
        instance_nonce: "c".repeat(64),
        process: ProcessSelector {
            process_id: 3,
            creation_file_time: FileTime::from_native(1, 2),
        },
    }
}
fn evidence(entry: &Value, policy: &[u8], floor: u64) -> Result<Evidence> {
    Ok(Evidence {
        incarnation: incarnation(),
        request: serde_json::to_string(&entry["request"]).map_err(|_| Error::StateCorrupt)?,
        response: String::from_utf8(raw(&entry["response"])?).map_err(|_| Error::StateCorrupt)?,
        sent: counters(false)?,
        received: counters(true)?,
        policy: String::from_utf8(policy.to_vec()).map_err(|_| Error::StateCorrupt)?,
        floor_before: floor,
        base_root_count: 0,
        denied_key_ids: vec![],
        earliest: entry["earliest"].as_u64().ok_or(Error::StateCorrupt)?,
        latest: entry["latest"].as_u64().ok_or(Error::StateCorrupt)?,
    })
}

/// Actual uncommitted scratch resource DATA, using the same native namespace,
/// shard writer and digest verification as Store::time_root_scratch. There is
/// no StartedServiceContext, acquisition authorization or clock acceptance.
#[allow(unsafe_code)]
fn scratch(store: &Store, roots: &[Value]) -> Result<RootScratch> {
    let transaction = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })?;
    let private = store
        .key(true, Some(&transaction))?
        .ok_or(Error::SetupIncomplete)?;
    let key =
        open(private.0, "trusted-time-v1", true, Some(&transaction))?.ok_or(Error::StateCorrupt)?;
    let candidate = create(key.0, "root-acquisition-v1", &transaction, false, true)?;
    drop(candidate);
    drop(key);
    drop(private);
    let mut result = RootScratch {
        transaction,
        path: format!(
            "{}\\private\\trusted-time-v1\\root-acquisition-v1",
            store.path
        ),
        count: 0,
        fingerprint: Sha256::new(),
    };
    for root in roots {
        result.push(&raw(root)?)?;
    }
    result.verify_all()?;
    Ok(result)
}

/// This writes historical DATA rows and then relies on the real member-source
/// reader to authenticate them. The record schemas/hash links below mirror
/// time::write_record, waterlog::{Batch,Head,MemberLink}, and
/// metadata::publication::{Record,Position}; no capability is deserialized.
fn load_alpha(
    private: &Key,
    seed: &Seed,
    host: &HostRegistration,
    tx: &Handle,
    fixture: &Value,
) -> Result<Evidence> {
    let time_key =
        open(private.0, "trusted-time-v1", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let policy = read(&time_key, "Policy")?;
    let admitted = evidence(&fixture["observations"][0], &policy, 0)?;
    let time_history = open(time_key.0, "history", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let initial = time::state_in(private, host, Some(tx))?;
    let mut state = initial.state.next_unknown(incarnation(), &initial.raw)?;
    initial
        .state
        .transition(&state, &initial.raw, seed.original_root_bytes())?;
    let row = create(time_history.0, &revision_name(2), tx, false, true)?;
    let previous = time::write_record(&row, &state)?;
    let prior = state.clone();
    state.revision = 3;
    state.previous_sha256 = Some(json::sha256(&previous));
    state.status = Status::CleanupPending;
    state.cleanup_pending = true;
    state.floor = Some(admitted.earliest);
    state.evidence = Some(admitted.clone());
    prior.transition(&state, &previous, seed.original_root_bytes())?;
    let row = create(time_history.0, &revision_name(3), tx, false, true)?;
    let accepted = time::write_record(&row, &state)?;
    write(&time_key, "Head", &accepted)?;
    let sample = HistoricalSample {
        revision: 3,
        head_sha256: json::sha256(&accepted),
        incarnation: incarnation(),
        counters: counters(true)?,
        earliest: admitted.earliest,
        latest: admitted.latest,
    };
    let sample = json::encode(&sample, false)?;
    let metadata =
        open(private.0, "metadata-state-v1", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let roles = read(&metadata, "Policy")?;
    let genesis = read(&metadata, "Genesis")?;
    let before_metadata = read(&metadata, "Head")?;
    let journal = open(metadata.0, "waterlog", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let before_waterlog = read(&journal, "Head")?;
    let entries = open(journal.0, "entries", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let row = create(entries.0, &revision_name(1), tx, false, true)?;
    let members = create(row.0, "members", tx, false, true)?;
    let alpha = &fixture["alpha"];
    let mut chain = json::sha256(b"pinvou-waterlog-members-v1");
    let originals = alpha["members"].as_array().ok_or(Error::StateCorrupt)?;
    for (index, item) in originals.iter().enumerate() {
        let bytes = raw(item)?;
        let number = index as u64 + 1;
        chain = json::sha256(&encode(
            value!({"previousSha256":chain,"index":number,"size":bytes.len(),"sha256":json::sha256(&bytes)}),
        )?);
        let member = create(members.0, &revision_name(number), tx, false, true)?;
        write(&member, "Original", &bytes)?;
    }
    let timestamp = raw(&alpha["timestamp"])?;
    let snapshot = raw(&alpha["snapshot"])?;
    for (name, bytes) in [
        ("Timestamp", &timestamp),
        ("Snapshot", &snapshot),
        ("Sample", &sample),
        ("GlobalPolicy", &policy),
        ("RolePolicy", &roles),
    ] {
        write(&row, name, bytes)?;
    }
    let record = encode(
        value!({"version":1,"index":1,"previousSha256":json::sha256(&before_waterlog),
        "sampleSha256":json::sha256(&sample),"globalPolicySha256":json::sha256(&policy),"rolePolicySha256":json::sha256(&roles),
        "timestampSha256":json::sha256(&timestamp),"snapshotSha256":json::sha256(&snapshot),"memberCount":originals.len(),"memberChainSha256":chain}),
    )?;
    write(&row, "Record", &record)?;
    let head = encode(
        value!({"waterlogVersion":1,"metadataGenesisSha256":json::sha256(&genesis),"count":1,"lastRecordSha256":json::sha256(&record)}),
    )?;
    write(&journal, "Head", &head)?;
    let position = value!({"index":1,"recordSha256":json::sha256(&record),"timestampSha256":json::sha256(&timestamp),
        "snapshotSha256":json::sha256(&snapshot),"memberCount":originals.len(),"memberChainSha256":chain,"headSha256":json::sha256(&head)});
    let record = encode(
        value!({"stateVersion":1,"revision":2,"previousSha256":json::sha256(&before_metadata),"active":position}),
    )?;
    let history = open(metadata.0, "history", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let row = create(history.0, &revision_name(2), tx, false, true)?;
    write(&row, "Record", &record)?;
    write(&metadata, "Head", &record)?;
    Ok(admitted)
}

pub(in crate::platform::windows::registry) fn run(
    seed: &Seed,
    host: &HostRegistration,
    guard: &ProductGuard,
    tx: &Handle,
    exit_old_key: bool,
) -> Result<()> {
    let fixture: Value = serde_json::from_slice(FIXTURE).map_err(|_| Error::StateCorrupt)?;
    if !matches(seed) {
        return Err(Error::ScopeConflict);
    }
    let store = Store::new(seed);
    let roots = fixture["successors"]
        .as_array()
        .ok_or(Error::StateCorrupt)?;
    // Establish candidate storage before the outer transaction writes time
    // history. Each case gets a new discarded outer TxR from the runner.
    let successors = scratch(&store, if exit_old_key { roots } else { &roots[..1] })?;
    let private = store.key(true, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    StagedV2Batch::component_test_tree_in(&private, tx)?;
    let admitted = load_alpha(&private, seed, host, tx, &fixture)?;
    let source_before = read(&private, METADATA_BOOTSTRAP_ROOT)?;
    let head_before = protected_head_in(seed, tx)?;
    let metadata =
        open(private.0, "metadata-state-v1", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let metadata_before = read(&metadata, "Head")?;
    let time_key =
        open(private.0, "trusted-time-v1", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let time_before = read(&time_key, "Head")?;
    let mut seen = 0;
    member_source::visit_metadata_members(seed, host, guard, tx, None, |member| {
        if member.batches() != 1 {
            return Err(Error::StateCorrupt);
        }
        member.visit_active(|_, _| {
            seen += 1;
            Ok(())
        })
    })?;
    if seen != 5 {
        return Err(Error::StateCorrupt);
    }
    // The valid new Time response covers both successors. Refusal must come
    // from the active old-key cache binding, before any staged/product writes.
    if exit_old_key {
        let candidate = evidence(
            &fixture["observations"][2],
            &read(&time_key, "Policy")?,
            admitted.earliest,
        )?;
        let result = StagedV2Batch::prepare(seed, host, guard, tx, None, &candidate, &successors);
        if !matches!(result, Err(Error::SourceUnavailable)) {
            return Err(Error::StateCorrupt);
        }
        if read(&private, METADATA_BOOTSTRAP_ROOT)? != source_before
            || protected_head_in(seed, tx)? != head_before
            || read(&metadata, "Head")? != metadata_before
            || read(&time_key, "Head")? != time_before
            || open(private.0, STAGING, false, Some(tx))?.is_some()
        {
            return Err(Error::StateCorrupt);
        }
        return Ok(());
    }
    let candidate = evidence(
        &fixture["observations"][1],
        &read(&time_key, "Policy")?,
        admitted.earliest,
    )?;
    let staged = StagedV2Batch::prepare(seed, host, guard, tx, None, &candidate, &successors)?;
    if staged.final_root()? != raw(&roots[0])? {
        return Err(Error::StateCorrupt);
    }
    staged.recheck_sources()?;
    // Native original corruption/missing values must invalidate the source,
    // even though all Heads are untouched, and restoration must recover it.
    let original = open(
        metadata.0,
        "waterlog\\entries\\0000000000000001\\members\\0000000000000001",
        true,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)?;
    let bytes = read(&original, "Original")?;
    write(&original, "Original", b"tampered")?;
    if staged.recheck_sources().is_ok() {
        return Err(Error::StateCorrupt);
    }
    write(&original, "Original", &bytes)?;
    staged.recheck_sources()?;
    remove_original(&original)?;
    if staged.recheck_sources().is_ok() {
        return Err(Error::StateCorrupt);
    }
    write(&original, "Original", &bytes)?;
    staged.recheck_sources()?;
    // Damage to the actual private staging tree is independently detected.
    let staged_roots =
        open(staged.stage.0, "roots", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let root_before = read_root_in(&staged_roots, 1, tx)?;
    write_root_damage(&staged_roots, tx)?;
    if staged.recheck_sources().is_ok() {
        return Err(Error::StateCorrupt);
    }
    restore_root(&staged_roots, tx, &root_before)?;
    staged.recheck_sources()?;
    if protected_head_in(seed, tx)? != head_before
        || read(&private, METADATA_BOOTSTRAP_ROOT)? != source_before
    {
        return Err(Error::StateCorrupt);
    }
    staged.publish_into_product()?;
    staged.discard_staging()?;
    // This is the actual completed lineage: only this reader can mint a prefix.
    let verified = VerifiedHistory::open(seed, host, guard, tx)?;
    let prefix = verified.prefix()?;
    prefix.verify_all_metadata()?;
    if verified.current_root() != raw(&roots[0])? {
        return Err(Error::StateCorrupt);
    }
    // A later, valid time header and today's stricter role policy must not
    // retroactively invalidate the historical Root2/Alpha snapshot prefix.
    let current = time::state_in(&private, host, Some(tx))?;
    let next = current.state.next_unknown(incarnation(), &current.raw)?;
    current
        .state
        .transition(&next, &current.raw, seed.original_root_bytes())?;
    let history = open(time_key.0, "history", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let row = create(history.0, &revision_name(next.revision), tx, false, true)?;
    write(&time_key, "Head", &time::write_record(&row, &next)?)?;
    let saved_roles = read(&metadata, "Policy")?;
    let mut roles: Value = serde_json::from_slice(&saved_roles).map_err(|_| Error::StateCorrupt)?;
    for role in ["timestamp", "snapshot", "target", "release", "package"] {
        roles[role] = value!([fixture["oldMetadataKeyId"]
            .as_str()
            .ok_or(Error::StateCorrupt)?]);
    }
    write(&metadata, "Policy", &encode(roles)?)?;
    prefix.verify_all_metadata()?;
    let current =
        member_source::visit_metadata_members(seed, host, guard, tx, Some(&prefix), |member| {
            member.visit_active(|_, _| Ok(()))
        });
    if current.is_ok() {
        return Err(Error::StateCorrupt);
    }
    write(&metadata, "Policy", &saved_roles)?;
    prefix.verify_all_metadata()?;
    Ok(())
}

#[allow(unsafe_code)]
fn remove_original(key: &Key) -> Result<()> {
    if unsafe { RegDeleteValueW(key.0, wide("Original").as_ptr()) } != 0 {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn root_object(roots: &Key, tx: &Handle) -> Result<Key> {
    open(
        roots.0,
        "0000000000000001\\0000000000000001",
        true,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)
}
fn write_root_damage(roots: &Key, tx: &Handle) -> Result<()> {
    write(&root_object(roots, tx)?, "Record", b"tampered")
}
fn restore_root(roots: &Key, tx: &Handle, bytes: &[u8]) -> Result<()> {
    write(&root_object(roots, tx)?, "Record", bytes)
}
