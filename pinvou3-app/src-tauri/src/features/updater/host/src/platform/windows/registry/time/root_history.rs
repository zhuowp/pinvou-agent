//! Format primitives for future protected product Root batch storage.
//! These records are data only: they do not authenticate the source, perform
//! a replay, or authorize committing any transaction.
#![allow(dead_code)]
use super::*;
mod publication;
use crate::trusted_time::{ProductRootBatch, ProductRootReplay};
pub(super) use publication::StagedV2Batch;
#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) use publication::component_fixture;
use sha2::{Digest, Sha256};
mod prefix;
#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) use prefix::component_test_captured_prefix;
pub(in crate::platform::windows::registry) use prefix::{CapturedRootMember, RootSignaturePrefix};

#[cfg(feature = "metadata-component-tests")]
static FAIL_EVIDENCE_AFTER_REQUEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Bind an ordered stream of separately bounded objects without retaining it.
struct ObjectChain {
    hash: Sha256,
    count: u64,
}
impl ObjectChain {
    fn new(domain: &'static [u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update((domain.len() as u64).to_be_bytes());
        hash.update(domain);
        Self { hash, count: 0 }
    }
    fn push(&mut self, raw: &[u8]) -> Result<()> {
        if raw.is_empty() || raw.len() > json::RECORD_MAX {
            return Err(Error::StateCorrupt);
        }
        let next = self.count.checked_add(1).ok_or(Error::Unavailable)?;
        self.hash.update(next.to_be_bytes());
        self.hash.update((raw.len() as u64).to_be_bytes());
        self.hash.update(raw);
        self.count = next;
        Ok(())
    }
    fn finish(self) -> (u64, String) {
        let digest = self.hash.finalize();
        (
            self.count,
            digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        )
    }
}

fn fingerprint_root_source(
    count: usize,
    read: &mut dyn FnMut(usize) -> Result<Vec<u8>>,
) -> Result<(u64, String)> {
    let mut chain = ObjectChain::new(ROOT_DOMAIN);
    for index in 0..count {
        chain.push(&read(index)?)?;
    }
    Ok(chain.finish())
}

// Per-object native TxR storage only. The enclosing owner authenticates the
// parent key, sequence, product guard and transaction; neither helper commits.
fn write_object_in(parent: &Key, name: &str, tx: &Handle, raw: &[u8]) -> Result<()> {
    let object = create(parent.0, name, tx, false, true)?;
    write(&object, "Record", raw)
}
fn read_object_in(parent: &Key, name: &str, tx: &Handle) -> Result<Vec<u8>> {
    let object = open(parent.0, name, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    super::super::product_catalog::exact(&object, true, &["Record"])?;
    super::super::product_catalog::exact(&object, false, &[])?;
    read(&object, "Record")
}

const ROOTS_PER_SHARD: u64 = 4096;
fn root_location(number: u64) -> Result<(u64, u64)> {
    let zero = number.checked_sub(1).ok_or(Error::StateCorrupt)?;
    Ok((zero / ROOTS_PER_SHARD + 1, zero % ROOTS_PER_SHARD + 1))
}
fn write_root_in(parent: &Key, number: u64, tx: &Handle, raw: &[u8]) -> Result<()> {
    let (shard_number, object_number) = root_location(number)?;
    let shard = create(parent.0, &revision_name(shard_number), tx, false, false)?;
    write_object_in(&shard, &revision_name(object_number), tx, raw)
}
fn read_root_in(parent: &Key, number: u64, tx: &Handle) -> Result<Vec<u8>> {
    let (shard_number, object_number) = root_location(number)?;
    let shard = open(parent.0, &revision_name(shard_number), false, Some(tx))?
        .ok_or(Error::StateCorrupt)?;
    read_object_in(&shard, &revision_name(object_number), tx)
}
fn exact_root_shards(parent: &Key, count: u64, tx: &Handle) -> Result<()> {
    let shards = count
        .checked_add(ROOTS_PER_SHARD - 1)
        .ok_or(Error::Unavailable)?
        / ROOTS_PER_SHARD;
    exact_numbered(parent, shards)?;
    for number in 1..=shards {
        let shard =
            open(parent.0, &revision_name(number), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        super::super::product_catalog::exact(&shard, true, &[])?;
        let used = if number == shards {
            (count - 1) % ROOTS_PER_SHARD + 1
        } else {
            ROOTS_PER_SHARD
        };
        exact_numbered(&shard, used)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchEvidence {
    version: u8,
    binding: Binding,
    successor_count: String,
    evidence: EvidenceHeader,
}

/// Split large evidence payloads into bounded native values in the same TxR.
/// The returned canonical header is the only value a batch head may bind.
fn write_evidence_in(parent: &Key, tx: &Handle, batch: &ProductRootBatch) -> Result<Vec<u8>> {
    let e = &batch.evidence;
    if batch.successor_count == 0
        || e.request.is_empty()
        || e.request.len() > json::FRAME_MAX
        || e.response.is_empty()
        || e.response.len() > json::FRAME_MAX
        || e.policy.is_empty()
        || e.policy.len() > json::RECORD_MAX
    {
        return Err(Error::StateCorrupt);
    }
    batch.binding.validate()?;
    let header = BatchEvidence {
        version: 1,
        binding: batch.binding.clone(),
        successor_count: batch.successor_count.to_string(),
        evidence: EvidenceHeader {
            request: Blob::of(e.request.as_bytes()),
            response: Blob::of(e.response.as_bytes()),
            policy: Blob::of(e.policy.as_bytes()),
            sent: e.sent.clone(),
            received: e.received.clone(),
            incarnation: e.incarnation.clone(),
            floor_before: e.floor_before,
            base_root_count: e.base_root_count,
            denied_key_ids: e.denied_key_ids.clone(),
            earliest: e.earliest,
            latest: e.latest,
        },
    };
    let raw = json::encode(&header, false)?;
    let key = create(parent.0, "evidence", tx, false, true)?;
    write(&key, "Request", e.request.as_bytes())?;
    #[cfg(feature = "metadata-component-tests")]
    if FAIL_EVIDENCE_AFTER_REQUEST.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(Error::Unavailable);
    }
    write(&key, "Response", e.response.as_bytes())?;
    write(&key, "Policy", e.policy.as_bytes())?;
    write(&key, "Record", &raw)?;
    Ok(raw)
}

fn read_evidence_in(parent: &Key, tx: &Handle, expected: &str) -> Result<ProductRootBatch> {
    let key = open(parent.0, "evidence", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    super::super::product_catalog::exact(&key, true, &["Request", "Response", "Policy", "Record"])?;
    super::super::product_catalog::exact(&key, false, &[])?;
    let raw = read(&key, "Record")?;
    if !json::digest(expected) || json::sha256(&raw) != expected {
        return Err(Error::StateCorrupt);
    }
    let h: BatchEvidence = json::decode(&raw, false)?;
    if h.version != 1 || counter(&h.successor_count)? == 0 || json::encode(&h, false)? != raw {
        return Err(Error::StateCorrupt);
    }
    h.binding.validate()?;
    fn utf8(raw: Vec<u8>) -> Result<String> {
        String::from_utf8(raw).map_err(|_| Error::StateCorrupt)
    }
    let e = h.evidence;
    Ok(ProductRootBatch {
        binding: h.binding,
        successor_count: usize::try_from(counter(&h.successor_count)?)
            .map_err(|_| Error::Unavailable)?,
        evidence: Evidence {
            request: utf8(e.request.read(&key, "Request", json::FRAME_MAX)?)?,
            response: utf8(e.response.read(&key, "Response", json::FRAME_MAX)?)?,
            policy: utf8(e.policy.read(&key, "Policy", json::RECORD_MAX)?)?,
            sent: e.sent,
            received: e.received,
            incarnation: e.incarnation,
            floor_before: e.floor_before,
            base_root_count: e.base_root_count,
            denied_key_ids: e.denied_key_ids,
            earliest: e.earliest,
            latest: e.latest,
        },
    })
}

const ROOT_DOMAIN: &[u8] = b"pinvou.product-root.successors.v1";
const MEMBER_DOMAIN: &[u8] = b"pinvou.product-root.members.v1";

// Enumerate independently of the expected count so an extra, missing, renamed
// or non-canonical entry is not silently ignored. Memory is bounded per name.
fn exact_numbered(parent: &Key, count: u64) -> Result<()> {
    let mut seen = 0u64;
    super::super::product_catalog::visit(parent, false, |name| {
        let number = name.parse::<u64>().map_err(|_| Error::StateCorrupt)?;
        if number == 0 || number > count || revision_name(number) != name {
            return Err(Error::StateCorrupt);
        }
        seen = seen.checked_add(1).ok_or(Error::Unavailable)?;
        Ok(())
    })?;
    if seen != count {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

// The enclosing caller authenticates the complete directory chain; this only
// checks the historical prefix identified by the protected batch head.
fn require_historical_directory(
    current_revision: u64,
    historical_revision: u64,
    member_count: u64,
    event_revision: u64,
    historical_raw: &[u8],
    expected_digest: &str,
) -> Result<()> {
    if historical_revision == 0
        || historical_revision != member_count
        || historical_revision > current_revision
        || event_revision != historical_revision
        || !json::digest(expected_digest)
        || json::sha256(historical_raw) != expected_digest
    {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

/// Called solely by the guard-and-TxR owner, which drops the transaction on
/// success and failure alike. This first-batch probe consumes only the actual
/// requesting member's protected state/evidence; it never publishes Head.
pub(super) fn probe_first_in(
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
) -> Result<()> {
    stage_first_in(seed, host, guard, tx, None, None).map(|_| ())
}

/// Stage a prospective first batch only. This is not a commit capability: the
/// owner must authenticate the policy/floor, recheck the complete read set,
/// and atomically publish both the product head and issuer state in this TxR.
pub(super) fn stage_prospective_first_in(
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
    proposed: &State,
) -> Result<Vec<u8>> {
    stage_first_in(seed, host, guard, tx, Some(proposed), None)
}

pub(super) fn stage_first_stream_in(
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
    evidence: &Evidence,
    count: usize,
    read: &mut dyn FnMut(usize) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    stage_first_in(seed, host, guard, tx, None, Some((evidence, count, read)))
}

fn stage_first_in(
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
    proposed: Option<&State>,
    mut stream: Option<(&Evidence, usize, &mut dyn FnMut(usize) -> Result<Vec<u8>>)>,
) -> Result<Vec<u8>> {
    guard.check_seed(seed)?;
    let private = Store::new(seed)
        .key(true, Some(tx))?
        .ok_or(Error::SetupIncomplete)?;
    let source = state_in(&private, host, Some(tx))?;
    let state = if let Some(next) = proposed {
        source
            .state
            .transition(next, &source.raw, &source.original_root)?;
        next
    } else {
        &source.state
    };
    let evidence = match stream.as_ref() {
        Some((evidence, _, _)) => (*evidence).clone(),
        None => state
            .evidence
            .clone()
            .ok_or(Error::PrerequisiteUnavailable)?,
    };
    let count = stream
        .as_ref()
        .map_or(state.roots.len(), |(_, count, _)| *count);
    if evidence.base_root_count != 0 || count == 0 {
        return Err(Error::PrerequisiteUnavailable);
    }
    let source_fingerprint = if let Some((_, _, read)) = stream.as_mut() {
        Some(fingerprint_root_source(count, *read)?)
    } else {
        None
    };
    let batch = ProductRootBatch {
        binding: state.binding.clone(),
        successor_count: count,
        evidence,
    };
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let catalog = open(
        HKEY_LOCAL_MACHINE,
        &format!("Software\\Pinvou\\{leaf}"),
        false,
        Some(tx),
    )?
    .ok_or(Error::SetupIncomplete)?;
    let products = open(catalog.0, "products", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let product = open(
        products.0,
        &json::sha256(seed.product.as_bytes()),
        false,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)?;
    let original = read(&product, "Root")?;
    if original != source.original_root {
        return Err(Error::StateCorrupt);
    }
    // This exact directory head identifies the historical membership snapshot.
    // The full directory visit below authenticates the chain ending at it.
    let catalog_head_raw = read(&product, "Head")?;
    let catalog_head = crate::product_catalog::ProductEvent::parse(&catalog_head_raw)?;
    let root_state =
        open(product.0, "root-state-v1", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let genesis = read(&root_state, "Head")?;
    let mut staged: Option<(Key, Key, Key)> = None;
    let mut members = ObjectChain::new(MEMBER_DOMAIN);
    let mut issuer_captured = false;
    super::super::product_catalog::visit_members_in(seed, host, tx, |event, actual| {
        if staged.is_none() {
            // A proposed advancement is staged in the actual product namespace
            // under the caller's transaction; the probe stays in scratch space.
            let candidate = if proposed.is_some() || stream.is_some() {
                create(root_state.0, "history-v2", tx, false, true)?
            } else {
                create(private.0, "root-history-candidate-v2", tx, false, true)?
            };
            let batches = create(candidate.0, "batches", tx, false, true)?;
            let batch = create(batches.0, &revision_name(1), tx, false, true)?;
            let member_dir = create(batch.0, "members", tx, false, true)?;
            staged = Some((candidate, batch, member_dir));
        }
        let (_, _, member_dir) = staged.as_ref().ok_or(Error::StateCorrupt)?;
        let next = members.count.checked_add(1).ok_or(Error::Unavailable)?;
        let snapshot = if event.profile_id == seed.profile_id {
            if issuer_captured {
                return Err(Error::StateCorrupt);
            }
            issuer_captured = true;
            match proposed {
                Some(proposed) => super::root_snapshot::capture_issuer_in(
                    member_dir,
                    &revision_name(next),
                    seed,
                    event,
                    actual,
                    tx,
                    proposed,
                )?,
                None => super::root_snapshot::capture_in(
                    member_dir,
                    &revision_name(next),
                    seed,
                    event,
                    actual,
                    tx,
                )?,
            }
        } else {
            super::root_snapshot::capture_in(
                member_dir,
                &revision_name(next),
                seed,
                event,
                actual,
                tx,
            )?
        };
        members.push(&snapshot)
    })?;
    let (candidate, batch_key, _member_dir) = staged.ok_or(Error::StateCorrupt)?;
    let (member_count, member_chain) = members.finish();
    if !issuer_captured
        || member_count != catalog_head.revision
        || read(&product, "Head")? != catalog_head_raw
    {
        return Err(Error::ScopeConflict);
    }
    let roots = create(batch_key.0, "roots", tx, false, true)?;
    let mut root_chain = ObjectChain::new(ROOT_DOMAIN);
    let mut root_sha256 = None;
    for index in 0..count {
        let root = if let Some((_, _, read)) = stream.as_mut() {
            read(index)?
        } else {
            state.roots[index].as_bytes().to_vec()
        };
        root_chain.push(&root)?;
        root_sha256 = Some(json::sha256(&root));
        write_root_in(&roots, (index as u64) + 1, tx, &root)?;
    }
    let (root_count, roots_chain) = root_chain.finish();
    if source_fingerprint
        .as_ref()
        .is_some_and(|expected| expected != &(root_count, roots_chain.clone()))
    {
        return Err(Error::ScopeConflict);
    }
    let evidence_raw = write_evidence_in(&batch_key, tx, &batch)?;
    let head = BatchHead {
        version: 1,
        batch: "1".into(),
        previous_sha256: json::sha256(&genesis),
        catalog_revision: catalog_head.revision.to_string(),
        catalog_head_sha256: json::sha256(&catalog_head_raw),
        root_count: root_count.to_string(),
        successor_count: root_count.to_string(),
        root_sha256: root_sha256.ok_or(Error::StateCorrupt)?,
        roots_chain_sha256: roots_chain,
        member_count: member_count.to_string(),
        members_chain_sha256: member_chain,
        evidence_sha256: json::sha256(&evidence_raw),
    };
    let raw = json::encode(&head, false)?;
    write(&batch_key, "Record", &raw)?;
    write(&candidate, "Head", &raw)?;
    let original = std::str::from_utf8(&original).map_err(|_| Error::StateCorrupt)?;
    replay_product_history_in(
        &candidate,
        tx,
        &product,
        &genesis,
        &raw,
        &seed.product,
        original,
        None,
    )?;
    if proposed.is_some() || stream.is_some() {
        if read(&root_state, "Head")? != genesis {
            return Err(Error::ScopeConflict);
        }
        // The caller must write the issuer state and commit the same TxR.
        write(&root_state, "Head", &raw)?;
    }
    Ok(raw)
}

/// Derive the issuer's compact reference from the exact staged batch Head.
/// This is data until the transaction owner replays and rechecks the batch.
pub(super) fn staged_position(raw: &[u8]) -> Result<ProductRootPosition> {
    let head = BatchHead::parse(raw)?;
    Ok(ProductRootPosition {
        head_sha256: json::sha256(raw),
        root_sha256: head.root_sha256,
        batch: counter(&head.batch)?,
        root_count: counter(&head.root_count)?,
    })
}

/// Stage one later product Root batch in the caller's guarded transaction.
/// The publisher must independently recheck the requester, policy, budget
/// floor and metadata census, then write its member Head in this same TxR.
pub(super) fn stage_next_in(
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
    expected_head: &[u8],
    successor_count: usize,
    mut read_successor: impl FnMut(usize) -> Result<Vec<u8>>,
    evidence: &Evidence,
) -> Result<Vec<u8>> {
    if successor_count == 0 {
        return Err(Error::StateCorrupt);
    }
    let mut expected_chain = ObjectChain::new(ROOT_DOMAIN);
    for index in 0..successor_count {
        expected_chain.push(&read_successor(index)?)?;
    }
    let expected_chain = expected_chain.finish();
    let view = VerifiedHistory::open(seed, host, guard, tx)?;
    if protected_head_in(seed, tx)? != expected_head {
        return Err(Error::ScopeConflict);
    }
    let previous = BatchHead::parse(expected_head)?;
    let base_count =
        usize::try_from(counter(&previous.root_count)?).map_err(|_| Error::Unavailable)?;
    if evidence.base_root_count != base_count {
        return Err(Error::ScopeConflict);
    }
    let mut local = evidence.clone();
    local.base_root_count = 0;
    local.verify_source(
        &Binding::from_host(host),
        view.current_root(),
        successor_count,
        |index| Ok(std::borrow::Cow::Owned(read_successor(index)?)),
    )?;
    let before = super::root_read_set::census(seed, host, guard, tx, true)?;
    let after = super::root_read_set::census(seed, host, guard, tx, true)?;
    super::root_read_set::require_unchanged(&before, &after)?;
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let path = format!(
        "Software\\Pinvou\\{leaf}\\products\\{}",
        json::sha256(seed.product.as_bytes())
    );
    let product = open(HKEY_LOCAL_MACHINE, &path, true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let catalog_head_raw = read(&product, "Head")?;
    let catalog_head = crate::product_catalog::ProductEvent::parse(&catalog_head_raw)?;
    let root_state =
        open(product.0, "root-state-v1", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let genesis = read(&root_state, "Genesis")?;
    let history = open(root_state.0, "history-v2", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let batches = open(history.0, "batches", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let batch_number = counter(&previous.batch)?
        .checked_add(1)
        .ok_or(Error::Unavailable)?;
    let batch_key = create(batches.0, &revision_name(batch_number), tx, false, true)?;
    let members = create(batch_key.0, "members", tx, false, true)?;
    let mut member_chain = ObjectChain::new(MEMBER_DOMAIN);
    let mut issuer_found = false;
    super::super::product_catalog::visit_history_directory_in(
        seed,
        host,
        guard,
        tx,
        |event, actual| {
            super::super::metadata::require_member_empty_for_root_transition_in(
                seed, event, actual, tx,
            )?;
            if event.profile_id == seed.profile_id {
                if issuer_found {
                    return Err(Error::StateCorrupt);
                }
                issuer_found = true;
            }
            let number = member_chain
                .count
                .checked_add(1)
                .ok_or(Error::Unavailable)?;
            let raw = super::root_snapshot::capture_history_in(
                &members,
                &revision_name(number),
                seed,
                event,
                actual,
                guard,
                tx,
                &view,
            )?;
            member_chain.push(&raw)
        },
    )?;
    let (member_count, members_chain_sha256) = member_chain.finish();
    if !issuer_found
        || member_count != catalog_head.revision
        || read(&product, "Head")? != catalog_head_raw
    {
        return Err(Error::ScopeConflict);
    }
    let roots = create(batch_key.0, "roots", tx, false, true)?;
    let mut root_chain = ObjectChain::new(ROOT_DOMAIN);
    let mut final_root_sha256 = None;
    for index in 0..successor_count {
        let root = read_successor(index)?;
        root_chain.push(&root)?;
        final_root_sha256 = Some(json::sha256(&root));
        write_root_in(&roots, index as u64 + 1, tx, &root)?;
    }
    let (successor_count, roots_chain_sha256) = root_chain.finish();
    if (successor_count, roots_chain_sha256.clone()) != expected_chain {
        return Err(Error::ScopeConflict);
    }
    let batch = ProductRootBatch {
        binding: Binding::from_host(host),
        evidence: evidence.clone(),
        successor_count: usize::try_from(successor_count).map_err(|_| Error::Unavailable)?,
    };
    let evidence_raw = write_evidence_in(&batch_key, tx, &batch)?;
    let root_count = counter(&previous.root_count)?
        .checked_add(successor_count)
        .ok_or(Error::Unavailable)?;
    let head = BatchHead {
        version: 1,
        batch: batch_number.to_string(),
        previous_sha256: json::sha256(expected_head),
        catalog_revision: catalog_head.revision.to_string(),
        catalog_head_sha256: json::sha256(&catalog_head_raw),
        root_count: root_count.to_string(),
        successor_count: successor_count.to_string(),
        root_sha256: final_root_sha256.ok_or(Error::StateCorrupt)?,
        roots_chain_sha256,
        member_count: member_count.to_string(),
        members_chain_sha256,
        evidence_sha256: json::sha256(&evidence_raw),
    };
    let raw = json::encode(&head, false)?;
    head.follows(expected_head, Some(&previous))?;
    write(&batch_key, "Record", &raw)?;
    write(&history, "Head", &raw)?;
    let original = read(&product, "Root")?;
    let original = std::str::from_utf8(&original).map_err(|_| Error::StateCorrupt)?;
    replay_product_history_in(
        &history,
        tx,
        &product,
        &genesis,
        &raw,
        &seed.product,
        original,
        None,
    )?;
    if read(&root_state, "Head")? != expected_head {
        return Err(Error::ScopeConflict);
    }
    write(&root_state, "Head", &raw)?;
    Ok(raw)
}

/// Position resolved during complete replay; private fields prevent callers
/// from constructing it from an unprotected member record. The owning read
/// set must still recheck its guard, transaction and protected Head before use.
pub(in crate::platform::windows::registry) struct ReplayedPosition {
    position: ProductRootPosition,
    root: Vec<u8>,
    binding: Binding,
    evidence: Option<Evidence>,
}
impl ReplayedPosition {
    pub(in crate::platform::windows::registry) fn matches(
        &self,
        expected: &ProductRootPosition,
    ) -> bool {
        self.position == *expected
    }
    pub(in crate::platform::windows::registry) fn root(&self) -> &[u8] {
        &self.root
    }
    pub(in crate::platform::windows::registry) fn authenticate_compact(
        &self,
        state: &State,
    ) -> Result<()> {
        state.validate_compact_shape()?;
        if state.product_root.as_ref() != Some(&self.position)
            || state.binding != self.binding
            || state.evidence != self.evidence
        {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}

/// Validate a bounded-object history against an authenticated protected head.
/// The owner authenticates the product directory and holds its guard and the
/// same transaction through this read and the final read-set recheck.
fn replay_product_history_in(
    history: &Key,
    tx: &Handle,
    product: &Key,
    genesis: &[u8],
    protected_head: &[u8],
    product_id: &str,
    original: &str,
    requested: Option<(&str, &Binding, Option<&Evidence>)>,
) -> Result<(Vec<u8>, Option<ReplayedPosition>, u64)> {
    use super::super::product_catalog::exact;
    exact(history, true, &["Head"])?;
    exact(history, false, &["batches"])?;
    if read(history, "Head")? != protected_head {
        return Err(Error::ScopeConflict);
    }
    let final_head = BatchHead::parse(protected_head)?;
    let count = counter(&final_head.batch)?;
    let batches = open(history.0, "batches", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    exact(&batches, true, &[])?;
    exact_numbered(&batches, count)?;
    let mut replay = ProductRootReplay::new(product_id, original)?;
    let mut previous_raw = genesis.to_vec();
    let mut previous = None;
    let mut matched = None;
    if let Some((position, binding, evidence)) = requested {
        if !json::digest(position) {
            return Err(Error::StateCorrupt);
        }
        binding.validate()?;
        if binding.product != product_id {
            return Err(Error::StateCorrupt);
        }
        if position == json::sha256(genesis) {
            if let Some(evidence) = evidence {
                if evidence.base_root_count != 0 {
                    return Err(Error::StateCorrupt);
                }
                let mut local = evidence.clone();
                local.base_root_count = 0;
                local.verify_source(binding, original.as_bytes(), 0, |_| {
                    Err(Error::StateCorrupt)
                })?;
            }
            matched = Some(ReplayedPosition {
                position: ProductRootPosition {
                    head_sha256: position.to_owned(),
                    root_sha256: json::sha256(original.as_bytes()),
                    batch: 0,
                    root_count: 0,
                },
                root: original.as_bytes().to_vec(),
                binding: binding.clone(),
                evidence: evidence.cloned(),
            });
        }
    }
    for index in 1..=count {
        let batch =
            open(batches.0, &revision_name(index), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let roots = open(batch.0, "roots", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let members = open(batch.0, "members", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let raw = read(&batch, "Record")?;
        let head = BatchHead::parse(&raw)?;
        if counter(&head.batch)? != index {
            return Err(Error::StateCorrupt);
        }
        replay = replay_batch_in(
            &batch,
            &roots,
            &members,
            tx,
            product,
            &previous_raw,
            previous.as_ref(),
            replay,
        )?;
        if let Some((position, binding, evidence)) = requested {
            if position == json::sha256(&raw) {
                if matched.is_some() {
                    return Err(Error::StateCorrupt);
                }
                let root_count =
                    usize::try_from(counter(&head.root_count)?).map_err(|_| Error::Unavailable)?;
                let root = replay.finish_root(index, root_count, &head.root_sha256)?;
                if let Some(evidence) = evidence {
                    crate::trusted_time::check_history_time_bound(
                        replay.finish_latest_issue(index, root_count, &head.root_sha256)?,
                        evidence.earliest,
                    )?;
                    let batch_evidence = read_evidence_in(&batch, tx, &head.evidence_sha256)?;
                    if batch_evidence.binding == *binding && batch_evidence.evidence == *evidence {
                        // The replay just checked this exact issuer and evidence.
                    } else {
                        if evidence.base_root_count != root_count {
                            return Err(Error::StateCorrupt);
                        }
                        let mut local = evidence.clone();
                        local.base_root_count = 0;
                        local.verify_source(binding, root, 0, |_| Err(Error::StateCorrupt))?;
                    }
                }
                matched = Some(ReplayedPosition {
                    position: ProductRootPosition {
                        head_sha256: position.to_owned(),
                        root_sha256: head.root_sha256.clone(),
                        batch: index,
                        root_count: u64::try_from(root_count).map_err(|_| Error::Unavailable)?,
                    },
                    root: root.to_vec(),
                    binding: binding.clone(),
                    evidence: evidence.cloned(),
                });
            }
        }
        previous_raw = raw;
        previous = Some(head);
    }
    if previous_raw != protected_head || read(history, "Head")? != protected_head {
        return Err(Error::ScopeConflict);
    }
    let count =
        usize::try_from(counter(&final_head.root_count)?).map_err(|_| Error::Unavailable)?;
    let current = replay
        .finish_root(counter(&final_head.batch)?, count, &final_head.root_sha256)?
        .to_vec();
    if requested.is_some() && matched.is_none() {
        return Err(Error::StateCorrupt);
    }
    {
        // Only after the complete protected chain has been replayed may its
        // compact snapshots be authenticated against exact ancestor positions.
        // Earlier positions are read directly from the already replayed prefix;
        // no nested full-history replay or detached authority is introduced.
        for batch_index in 1..=counter(&final_head.batch)? {
            let batch = open(batches.0, &revision_name(batch_index), false, Some(tx))?
                .ok_or(Error::StateCorrupt)?;
            let raw = read(&batch, "Record")?;
            let head = BatchHead::parse(&raw)?;
            let members = open(batch.0, "members", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
            for member_index in 1..=counter(&head.member_count)? {
                let member = open(members.0, &revision_name(member_index), false, Some(tx))?
                    .ok_or(Error::StateCorrupt)?;
                let member_raw = read(&member, "Record")?;
                let (_, state) = super::root_snapshot::read_shape_in(&member, tx, &member_raw)?
                    .replay_input()?;
                if let Some(position) = &state.product_root {
                    if position.batch >= batch_index {
                        return Err(Error::StateCorrupt);
                    }
                    // This batch is strictly earlier than the current one;
                    // it was validated in the first replay and every earlier
                    // compact member has passed this sequential second pass.
                    let verified = position_from_verified_prefix(
                        &batches, tx, genesis, original, position, &state,
                    )?;
                    verified.authenticate_compact(&state)?;
                }
            }
        }
    }
    let latest_issue =
        replay.finish_latest_issue(counter(&final_head.batch)?, count, &final_head.root_sha256)?;
    Ok((current, matched, latest_issue))
}

/// Resolve only a position in a prefix already verified in this same stable
/// TxR. This function is not an independent history reader or authority.
fn position_from_verified_prefix(
    batches: &Key,
    tx: &Handle,
    genesis: &[u8],
    original: &str,
    position: &ProductRootPosition,
    state: &State,
) -> Result<ReplayedPosition> {
    // The prefix was authenticated in this transaction before this helper is
    // called. Keep the historical bound at the member's own position.
    let mut latest_issue = crate::trusted_time::root_issue_bytes(original.as_bytes())?;
    for index in 1..=position.batch {
        let batch =
            open(batches.0, &revision_name(index), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let head = BatchHead::parse(&read(&batch, "Record")?)?;
        let roots = open(batch.0, "roots", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        for root_index in 1..=counter(&head.successor_count)? {
            latest_issue = latest_issue.max(crate::trusted_time::root_issue_bytes(&read_root_in(
                &roots, root_index, tx,
            )?)?);
        }
    }
    if let Some(evidence) = &state.evidence {
        crate::trusted_time::check_history_time_bound(latest_issue, evidence.earliest)?;
    }
    let root = if position.batch == 0 {
        if position.head_sha256 != json::sha256(genesis)
            || position.root_count != 0
            || position.root_sha256 != json::sha256(original.as_bytes())
        {
            return Err(Error::StateCorrupt);
        }
        if let Some(evidence) = &state.evidence {
            if evidence.base_root_count != 0 {
                return Err(Error::StateCorrupt);
            }
            let mut local = evidence.clone();
            local.base_root_count = 0;
            local.verify_source(&state.binding, original.as_bytes(), 0, |_| {
                Err(Error::StateCorrupt)
            })?;
        }
        original.as_bytes().to_vec()
    } else {
        let batch = open(batches.0, &revision_name(position.batch), false, Some(tx))?
            .ok_or(Error::StateCorrupt)?;
        let raw = read(&batch, "Record")?;
        let head = BatchHead::parse(&raw)?;
        if json::sha256(&raw) != position.head_sha256
            || counter(&head.batch)? != position.batch
            || counter(&head.root_count)? != position.root_count
            || head.root_sha256 != position.root_sha256
        {
            return Err(Error::StateCorrupt);
        }
        let roots = open(batch.0, "roots", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let root = read_root_in(&roots, counter(&head.successor_count)?, tx)?;
        if json::sha256(&root) != position.root_sha256 {
            return Err(Error::StateCorrupt);
        }
        if let Some(evidence) = &state.evidence {
            let batch_evidence = read_evidence_in(&batch, tx, &head.evidence_sha256)?;
            if batch_evidence.binding != state.binding || batch_evidence.evidence != *evidence {
                if u64::try_from(evidence.base_root_count).ok() != Some(position.root_count) {
                    return Err(Error::StateCorrupt);
                }
                let mut local = evidence.clone();
                local.base_root_count = 0;
                local.verify_source(&state.binding, &root, 0, |_| Err(Error::StateCorrupt))?;
            }
        }
        root
    };
    Ok(ReplayedPosition {
        position: position.clone(),
        root,
        binding: state.binding.clone(),
        evidence: state.evidence.clone(),
    })
}

/// A replayed product Root/time lineage tied to the caller's actual transaction
/// and product guard. It cannot be constructed by a member record or outlive
/// those native resources. The owner must recheck its complete read set before
/// using any result as authority. V2 metadata prefixes and final-Root active
/// binding require the separate prefix.verify_all_metadata traversal; this
/// lineage object alone does not attest to metadata completeness.
pub(in crate::platform::windows::registry) struct VerifiedHistory<'a> {
    seed: &'a Seed,
    guard: &'a super::super::product_catalog::ProductGuard,
    tx: &'a Handle,
    current_head: Vec<u8>,
    current_root: Vec<u8>,
    latest_issue: u64,
    source_fingerprint: [u8; 32],
}
impl<'a> VerifiedHistory<'a> {
    pub(super) fn open(
        seed: &'a Seed,
        host: &HostRegistration,
        guard: &'a super::super::product_catalog::ProductGuard,
        tx: &'a Handle,
    ) -> Result<Self> {
        super::super::product_catalog::visit_history_directory_in(
            seed,
            host,
            guard,
            tx,
            |_, _| Ok(()),
        )?;
        let source_fingerprint = prefix::fingerprint(seed, guard, tx)?;
        let current_head = protected_head_in(seed, tx)?;
        let (current_root, _, latest_issue) =
            replay_persisted_with_position_in(seed, guard, tx, None)?;
        if protected_head_in(seed, tx)? != current_head {
            return Err(Error::ScopeConflict);
        }
        super::root_read_set::require_unchanged(
            &source_fingerprint,
            &prefix::fingerprint(seed, guard, tx)?,
        )?;
        Ok(Self {
            seed,
            guard,
            tx,
            current_head,
            current_root,
            latest_issue,
            source_fingerprint,
        })
    }
    /// Root/time lineage only; metadata active-set authentication remains gated.
    pub(super) fn prefix(&self) -> Result<RootSignaturePrefix<'a>> {
        prefix::from_verified(self)
    }
    pub(super) fn check_context(
        &self,
        seed: &Seed,
        guard: &super::super::product_catalog::ProductGuard,
        tx: &Handle,
    ) -> Result<()> {
        if !std::ptr::eq(self.seed, seed)
            || !std::ptr::eq(self.guard, guard)
            || !std::ptr::eq(self.tx, tx)
        {
            return Err(Error::ScopeConflict);
        }
        self.guard.check_seed(self.seed)
    }
    pub(super) fn current_root(&self) -> &[u8] {
        &self.current_root
    }
    pub(super) fn latest_issue(&self) -> u64 {
        self.latest_issue
    }
    pub(super) fn recheck_head(&self) -> Result<()> {
        self.guard.check_seed(self.seed)?;
        if protected_head_in(self.seed, self.tx)? != self.current_head {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
    pub(super) fn authenticate(&self, state: &State) -> Result<Vec<u8>> {
        self.guard.check_seed(self.seed)?;
        let position = state.product_root.as_ref().ok_or(Error::StateCorrupt)?;
        if protected_head_in(self.seed, self.tx)? != self.current_head {
            return Err(Error::ScopeConflict);
        }
        let final_head = BatchHead::parse(&self.current_head)?;
        if position.batch > counter(&final_head.batch)? {
            return Err(Error::StateCorrupt);
        }
        let leaf = if self.seed.profile_kind == "production" {
            "UpgradeProductCatalogV1"
        } else {
            "UpgradeProductCatalogLabV1"
        };
        let path = format!(
            "Software\\Pinvou\\{leaf}\\products\\{}",
            json::sha256(self.seed.product.as_bytes())
        );
        let product =
            open(HKEY_LOCAL_MACHINE, &path, false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let original = read(&product, "Root")?;
        let root_state =
            open(product.0, "root-state-v1", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let genesis = read(&root_state, "Genesis")?;
        let history =
            open(root_state.0, "history-v2", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let batches =
            open(history.0, "batches", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let original = std::str::from_utf8(&original).map_err(|_| Error::StateCorrupt)?;
        let verified =
            position_from_verified_prefix(&batches, self.tx, &genesis, original, position, state)?;
        verified.authenticate_compact(state)?;
        if protected_head_in(self.seed, self.tx)? != self.current_head {
            return Err(Error::ScopeConflict);
        }
        Ok(verified.root().to_vec())
    }
}

/// Replay a committed product history inside the directory owner's guarded
/// transaction. The owner must authenticate the full current directory chain
/// in the same transaction before calling this function.
pub(super) fn replay_persisted_in(
    seed: &Seed,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
) -> Result<Vec<u8>> {
    Ok(replay_persisted_with_position_in(seed, guard, tx, None)?.0)
}

pub(super) fn replay_persisted_with_position_in(
    seed: &Seed,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
    requested: Option<(&str, &Binding, Option<&Evidence>)>,
) -> Result<(Vec<u8>, Option<ReplayedPosition>, u64)> {
    guard.check_seed(seed)?;
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let catalog = open(
        HKEY_LOCAL_MACHINE,
        &format!("Software\\Pinvou\\{leaf}"),
        false,
        Some(tx),
    )?
    .ok_or(Error::SetupIncomplete)?;
    let products = open(catalog.0, "products", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let product = open(
        products.0,
        &json::sha256(seed.product.as_bytes()),
        false,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)?;
    let events = open(product.0, "history", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let first_event = read_object_in(&events, &revision_name(1), tx)?;
    let original = read(&product, "Root")?;
    let genesis = super::super::product_catalog::product_root::check_history_base_in(
        &product,
        tx,
        &first_event,
        &original,
    )?;
    let root_state =
        open(product.0, "root-state-v1", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let protected_head = read(&root_state, "Head")?;
    let history = open(root_state.0, "history-v2", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let original = std::str::from_utf8(&original).map_err(|_| Error::StateCorrupt)?;
    let root = replay_product_history_in(
        &history,
        tx,
        &product,
        &genesis,
        &protected_head,
        &seed.product,
        original,
        requested,
    )?;
    if read(&root_state, "Head")? != protected_head {
        return Err(Error::ScopeConflict);
    }
    Ok(root)
}

// Flush all objects of the bounded-depth product history tree after commit.
// A malformed or unexpectedly deep tree is an unknown commit, never success.
#[allow(unsafe_code)]
pub(super) fn flush_persisted(seed: &Seed) -> Result<()> {
    fn flush_tree(key: &Key, depth: usize) -> Result<()> {
        if depth > 8 {
            return Err(Error::StateCommitUnknown);
        }
        super::super::product_catalog::visit(key, false, |name| {
            let child = open(key.0, name, false, None)?.ok_or(Error::StateCommitUnknown)?;
            flush_tree(&child, depth + 1)
        })?;
        if unsafe { RegFlushKey(key.0) } != 0 {
            return Err(Error::StateCommitUnknown);
        }
        Ok(())
    }
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let path = format!(
        "Software\\Pinvou\\{leaf}\\products\\{}\\root-state-v1",
        json::sha256(seed.product.as_bytes())
    );
    let root = open(HKEY_LOCAL_MACHINE, &path, false, None)?.ok_or(Error::StateCommitUnknown)?;
    flush_tree(&root, 0)
}

pub(super) fn protected_head_in(seed: &Seed, tx: &Handle) -> Result<Vec<u8>> {
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let path = format!(
        "Software\\Pinvou\\{leaf}\\products\\{}\\root-state-v1",
        json::sha256(seed.product.as_bytes())
    );
    let root = open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    read(&root, "Head")
}

/// Select a verifier only; these bytes are not an authenticated Root.
/// The selected genesis or history path must independently authenticate them.
pub(super) fn advanced_shape_in(seed: &Seed, tx: &Handle) -> Result<bool> {
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let path = format!(
        "Software\\Pinvou\\{leaf}\\products\\{}\\root-state-v1",
        json::sha256(seed.product.as_bytes())
    );
    let root = open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    Ok(read(&root, "Head")? != read(&root, "Genesis")?)
}

/// Replay one authenticated batch against the caller's existing cursor and
/// the immediately preceding protected head. The owner must first authenticate
/// the complete product directory and must commit only after rechecking it.
fn replay_batch_in(
    candidate: &Key,
    roots: &Key,
    members: &Key,
    tx: &Handle,
    product: &Key,
    previous_raw: &[u8],
    previous: Option<&BatchHead>,
    mut replay: ProductRootReplay,
) -> Result<ProductRootReplay> {
    use super::super::product_catalog::exact;
    exact(candidate, true, &["Record"])?;
    exact(candidate, false, &["evidence", "members", "roots"])?;
    exact(roots, true, &[])?;
    exact(members, true, &[])?;
    let raw = read(candidate, "Record")?;
    let head = BatchHead::parse(&raw)?;
    head.follows(previous_raw, previous)?;
    let root_count = counter(&head.successor_count)?;
    let member_count = counter(&head.member_count)?;
    let catalog_raw = read(product, "Head")?;
    let catalog = crate::product_catalog::ProductEvent::parse(&catalog_raw)?;
    let historical_revision = counter(&head.catalog_revision)?;
    if historical_revision == 0
        || historical_revision > catalog.revision
        || historical_revision != member_count
    {
        return Err(Error::StateCorrupt);
    }
    let catalog_history =
        open(product.0, "history", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    // The caller must authenticate the complete current directory chain in
    // this same transaction. A later enrollment changes its Head but must not
    // retroactively add that member to this historical batch.
    let historical_head =
        read_object_in(&catalog_history, &revision_name(historical_revision), tx)?;
    let historical = crate::product_catalog::ProductEvent::parse(&historical_head)?;
    require_historical_directory(
        catalog.revision,
        historical_revision,
        member_count,
        historical.revision,
        &historical_head,
        &head.catalog_head_sha256,
    )?;
    exact_root_shards(roots, root_count, tx)?;
    exact_numbered(members, member_count)?;
    let mut root_chain = ObjectChain::new(ROOT_DOMAIN);
    for index in 1..=root_count {
        root_chain.push(&read_root_in(roots, index, tx)?)?;
    }
    if root_chain.finish() != (root_count, head.roots_chain_sha256.clone()) {
        return Err(Error::StateCorrupt);
    }
    let batch = read_evidence_in(candidate, tx, &head.evidence_sha256)?;
    if batch.successor_count as u64 != root_count {
        return Err(Error::StateCorrupt);
    }
    let mut member_chain = ObjectChain::new(MEMBER_DOMAIN);
    let mut issuer_found = false;
    for index in 1..=member_count {
        let member =
            open(members.0, &revision_name(index), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let raw = read(&member, "Record")?;
        let catalog_event_raw = read_object_in(&catalog_history, &revision_name(index), tx)?;
        let catalog_event = crate::product_catalog::ProductEvent::parse(&catalog_event_raw)?;
        if catalog_event.revision != index
            || read(&member, "Enrollment")? != catalog_event.enrollment.as_bytes()
        {
            return Err(Error::StateCorrupt);
        }
        // The first pass binds every exact snapshot to this batch before any
        // member state is interpreted as evidence or deny policy.
        super::root_snapshot::read_shape_in(&member, tx, &raw)?;
        member_chain.push(&raw)?;
    }
    if member_chain.finish() != (member_count, head.members_chain_sha256.clone()) {
        return Err(Error::StateCorrupt);
    }
    // Re-read in the same transaction; the first pass binds the ordered
    // records to this batch, while this pass validates the legacy lineage.
    // The batch itself becomes trusted only after the full replay succeeds.
    let mut rechecked_chain = ObjectChain::new(MEMBER_DOMAIN);
    for index in 1..=member_count {
        let member =
            open(members.0, &revision_name(index), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let raw = read(&member, "Record")?;
        rechecked_chain.push(&raw)?;
        let input = super::root_snapshot::read_shape_in(&member, tx, &raw)?;
        let catchup = input.catchup().cloned();
        let (denials, state) = input.replay_input()?;
        if verify_issuer_state(&state, &batch, previous_raw, previous, catchup.as_ref())? {
            if !denials.matches_policy(&batch.evidence) {
                return Err(Error::StateCorrupt);
            }
            if issuer_found {
                return Err(Error::StateCorrupt);
            }
            issuer_found = true;
        }
    }
    if rechecked_chain.finish() != (member_count, head.members_chain_sha256.clone()) {
        return Err(Error::ScopeConflict);
    }
    require_issuer(issuer_found)?;
    replay.advance(
        &batch,
        |index| read_root_in(roots, (index as u64) + 1, tx),
        |visit| {
            for index in 1..=member_count {
                let member = open(members.0, &revision_name(index), false, Some(tx))?
                    .ok_or(Error::StateCorrupt)?;
                let raw = read(&member, "Record")?;
                let (denials, _) =
                    super::root_snapshot::read_shape_in(&member, tx, &raw)?.replay_input()?;
                denials.visit(visit)?;
            }
            Ok(())
        },
    )?;
    let total_roots =
        usize::try_from(counter(&head.root_count)?).map_err(|_| Error::Unavailable)?;
    replay.finish(counter(&head.batch)?, total_roots, &head.root_sha256)?;
    Ok(replay)
}

fn require_issuer(found: bool) -> Result<()> {
    if !found {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

/// The replay evidence must be the exact protected evidence of one member
/// already present in this historical directory prefix. The source state and
/// its successor bytes are authenticated by the member snapshot's record.
fn verify_issuer_state(
    state: &State,
    batch: &ProductRootBatch,
    previous_raw: &[u8],
    previous: Option<&BatchHead>,
    catchup: Option<&CatchupRecord>,
) -> Result<bool> {
    if state.binding != batch.binding {
        if catchup.is_some() {
            return Err(Error::StateCorrupt);
        }
        return Ok(false);
    }
    let base = batch.evidence.base_root_count;
    let previous_position = previous
        .map(|head| staged_position(&json::encode(head, false)?))
        .transpose()?;
    let cursor_matches = if let Some(cursor) = catchup {
        let expected_position = previous_position.as_ref().ok_or(Error::StateCorrupt)?;
        cursor.version == 1
            && cursor.binding == state.binding
            && cursor.state_sha256 == json::sha256(&json::encode(&header(state), false)?)
            && state.incarnation.as_ref() == Some(&cursor.incarnation)
            && &cursor.position == expected_position
            && cursor.position.head_sha256 == json::sha256(previous_raw)
            && usize::try_from(cursor.position.root_count).ok() == Some(base)
    } else {
        false
    };
    if catchup.is_some() && !cursor_matches {
        return Err(Error::StateCorrupt);
    }
    let base_matches = cursor_matches
        || if let Some(position) = &state.product_root {
            let (batch_count, root_count, root_hash) = match previous {
                Some(head) => (
                    counter(&head.batch)?,
                    counter(&head.root_count)?,
                    head.root_sha256.as_str(),
                ),
                None => (0, 0, position.root_sha256.as_str()),
            };
            position.batch == batch_count
                && position.root_count == root_count
                && usize::try_from(root_count).ok() == Some(base)
                && position.head_sha256 == json::sha256(previous_raw)
                && position.root_sha256 == root_hash
        } else {
            state.roots.len() == base
        };
    // A first observation may use the verified successor chain directly.
    // Existing evidence still requires a distinct request and nonce.
    if let Some(prior_time) = &state.evidence {
        let previous_request = pinvou_upgrade_codec::Document::parse(
            prior_time.request.as_bytes(),
            pinvou_upgrade_codec::InputKind::Credential,
        )
        .map_err(|_| Error::StateCorrupt)?
        .time_request_shape()
        .map_err(|_| Error::StateCorrupt)?;
        let next_request = pinvou_upgrade_codec::Document::parse(
            batch.evidence.request.as_bytes(),
            pinvou_upgrade_codec::InputKind::Credential,
        )
        .map_err(|_| Error::StateCorrupt)?
        .time_request_shape()
        .map_err(|_| Error::StateCorrupt)?;
        if prior_time.request == batch.evidence.request
            || previous_request.request_nonce() == next_request.request_nonce()
        {
            return Err(Error::PrerequisiteUnavailable);
        }
    } else if state.floor.is_some() || state.status != Status::Unknown {
        return Err(Error::StateCorrupt);
    }
    if !base_matches
        || state.incarnation.as_ref() != Some(&batch.evidence.incarnation)
        || batch.evidence.floor_before < state.floor.unwrap_or(0)
        || !state
            .denied_key_ids
            .iter()
            .all(|id| batch.evidence.denied_key_ids.contains(id))
    {
        return Err(Error::StateCorrupt);
    }
    if state.product_root.is_some() {
        return Ok(true);
    }
    if cursor_matches {
        return Ok(true);
    }
    match (base, previous) {
        (0, None) => {}
        (n, Some(head)) if n > 0 && counter(&head.root_count)? == n as u64 => {
            if json::sha256(state.roots[n - 1].as_bytes()) != head.root_sha256 {
                return Err(Error::StateCorrupt);
            }
        }
        _ => return Err(Error::StateCorrupt),
    }
    Ok(true)
}

/// Exercises the codec and native TxR only; synthetic payloads prove no signature.
#[cfg(feature = "metadata-component-tests")]
#[allow(unsafe_code)]
pub(in crate::platform::windows::registry) fn component_test(
    private: &Key,
    host: &HostRegistration,
    tx: &Handle,
) -> Result<()> {
    use crate::{
        identity::{FileTime, ProcessSelector},
        monotonic::CounterObservation,
    };
    use std::sync::atomic::Ordering;
    let parent = create(private.0, "root-evidence-test", tx, false, true)?;
    prefix::component_test_in(&parent, tx)?;
    let objects = create(parent.0, "objects", tx, false, true)?;
    write_object_in(&objects, &revision_name(1), tx, b"first")?;
    write_object_in(&objects, &revision_name(2), tx, b"second")?;
    exact_numbered(&objects, 2)?;
    let mut chain = ObjectChain::new(ROOT_DOMAIN);
    for index in 1..=2 {
        chain.push(&read_object_in(&objects, &revision_name(index), tx)?)?;
    }
    let expected_objects = chain.finish();
    let second = open(objects.0, &revision_name(2), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    write(&second, "Record", b"replaced")?;
    let mut changed = ObjectChain::new(ROOT_DOMAIN);
    for index in 1..=2 {
        changed.push(&read_object_in(&objects, &revision_name(index), tx)?)?;
    }
    assert_ne!(changed.finish(), expected_objects);
    assert_eq!(
        unsafe { RegDeleteValueW(second.0, wide("Record").as_ptr()) },
        0
    );
    assert!(read_object_in(&objects, &revision_name(2), tx).is_err());
    write(&second, "Record", b"second")?;
    write_object_in(&objects, &revision_name(3), tx, b"extra")?;
    assert!(exact_numbered(&objects, 2).is_err());
    let counter = CounterEvidence::from_data(
        CounterObservation::from_bracket(10, 9, 9, 10).map_err(|_| Error::StateCorrupt)?,
    );
    let batch = ProductRootBatch {
        binding: Binding::from_host(host),
        successor_count: 1,
        evidence: Evidence {
            incarnation: Incarnation {
                host_epoch: 1,
                instance_nonce: "c".repeat(64),
                process: ProcessSelector {
                    process_id: 3,
                    creation_file_time: FileTime::from_native(1, 2),
                },
            },
            request: "request".into(),
            response: "response".into(),
            policy: "policy".into(),
            sent: counter.clone(),
            received: counter,
            floor_before: 0,
            base_root_count: 0,
            denied_key_ids: Vec::new(),
            earliest: 1,
            latest: 2,
        },
    };
    let raw = write_evidence_in(&parent, tx, &batch)?;
    let digest = json::sha256(&raw);
    let decoded = read_evidence_in(&parent, tx, &digest)?;
    assert!(
        decoded.binding == batch.binding
            && decoded.successor_count == batch.successor_count
            && decoded.evidence == batch.evidence
    );
    let key = open(parent.0, "evidence", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    for name in ["Request", "Response", "Policy", "Record"] {
        let saved = read(&key, name)?;
        write(&key, name, b"damaged")?;
        assert!(read_evidence_in(&parent, tx, &digest).is_err());
        write(&key, name, &saved)?;
        assert_eq!(unsafe { RegDeleteValueW(key.0, wide(name).as_ptr()) }, 0);
        assert!(read_evidence_in(&parent, tx, &digest).is_err());
        write(&key, name, &saved)?;
    }
    write(&key, "Extra", b"x")?;
    assert!(read_evidence_in(&parent, tx, &digest).is_err());
    assert_eq!(unsafe { RegDeleteValueW(key.0, wide("Extra").as_ptr()) }, 0);
    let saved = read(&key, "Request")?;
    write(&key, "Request", &vec![b'x'; json::FRAME_MAX + 1])?;
    assert_eq!(
        read_limited(&key, "Request", json::FRAME_MAX),
        Err(Error::StateCorrupt)
    );
    assert!(read_evidence_in(&parent, tx, &digest).is_err());
    write(&key, "Request", &saved)?;
    read_evidence_in(&parent, tx, &digest)?;
    let partial = create(private.0, "root-evidence-partial-test", tx, false, true)?;
    FAIL_EVIDENCE_AFTER_REQUEST.store(true, Ordering::SeqCst);
    assert!(matches!(
        write_evidence_in(&partial, tx, &batch),
        Err(Error::Unavailable)
    ));
    let partial_key = open(partial.0, "evidence", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    assert_eq!(
        read(&partial_key, "Request")?,
        batch.evidence.request.as_bytes()
    );
    assert!(read(&partial_key, "Record").is_err());
    // Caller must immediately discard this transaction after the injected failure.
    Ok(())
}

/// Decimal strings preserve native counters without a JSON safe-integer cap.
fn counter(value: &str) -> Result<u64> {
    if value.is_empty()
        || value.len() > 20
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::StateCorrupt);
    }
    value.parse().map_err(|_| Error::StateCorrupt)
}

/// One bounded record per batch. Object digests are themselves rolling chains,
/// so neither this record nor a reader must buffer all members or all history.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BatchHead {
    version: u8,
    batch: String,
    previous_sha256: String,
    catalog_revision: String,
    catalog_head_sha256: String,
    root_count: String,
    successor_count: String,
    root_sha256: String,
    roots_chain_sha256: String,
    member_count: String,
    members_chain_sha256: String,
    evidence_sha256: String,
}
impl BatchHead {
    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > json::RECORD_MAX {
            return Err(Error::StateCorrupt);
        }
        let head: Self = json::decode(raw, false)?;
        if json::encode(&head, false)? != raw
            || head.version != 1
            || counter(&head.batch)? == 0
            || counter(&head.catalog_revision)? == 0
            || counter(&head.member_count)? == 0
            || counter(&head.successor_count)? == 0
            || ![
                &head.previous_sha256,
                &head.catalog_head_sha256,
                &head.root_sha256,
                &head.roots_chain_sha256,
                &head.members_chain_sha256,
                &head.evidence_sha256,
            ]
            .iter()
            .all(|value| json::digest(value))
        {
            return Err(Error::StateCorrupt);
        }
        counter(&head.root_count)?;
        Ok(head)
    }

    /// `previous_raw` must be the authenticated previous head, or the exact
    /// authenticated legacy genesis for the first batch. Callers must also
    /// verify the actual evidence, object chains and replay before acceptance.
    fn follows(&self, previous_raw: &[u8], previous: Option<&Self>) -> Result<()> {
        Self::parse(&json::encode(self, false)?)?;
        let (batch, roots) = match previous {
            Some(old) => {
                if json::encode(old, false)? != previous_raw {
                    return Err(Error::StateCorrupt);
                }
                let old_catalog_revision = counter(&old.catalog_revision)?;
                let new_catalog_revision = counter(&self.catalog_revision)?;
                if new_catalog_revision < old_catalog_revision
                    || (new_catalog_revision == old_catalog_revision
                        && self.catalog_head_sha256 != old.catalog_head_sha256)
                {
                    return Err(Error::StateCorrupt);
                }
                (counter(&old.batch)?, counter(&old.root_count)?)
            }
            None => (0, 0),
        };
        if self.previous_sha256 != json::sha256(previous_raw)
            || counter(&self.batch)? != batch.checked_add(1).ok_or(Error::Unavailable)?
            || counter(&self.root_count)?
                != roots
                    .checked_add(counter(&self.successor_count)?)
                    .ok_or(Error::Unavailable)?
        {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_positions_cross_shards_without_resetting_order() {
        assert_eq!(root_location(1), Ok((1, 1)));
        assert_eq!(root_location(4096), Ok((1, 4096)));
        assert_eq!(root_location(4097), Ok((2, 1)));
        assert_eq!(root_location(8192), Ok((2, 4096)));
        assert_eq!(root_location(8193), Ok((3, 1)));
        assert_eq!(root_location(0), Err(Error::StateCorrupt));
        let mut head = head(b"genesis", 1, 4097);
        head.successor_count = "4097".into();
        assert!(head.follows(b"genesis", None).is_ok());
        head.successor_count = "4096".into();
        assert_eq!(head.follows(b"genesis", None), Err(Error::StateCorrupt));
    }

    #[test]
    fn root_source_fingerprint_binds_4097_object_boundary_and_missing() {
        let expected =
            fingerprint_root_source(4097, &mut |i| Ok(format!("root-{i}").into_bytes())).unwrap();
        assert_eq!(expected.0, 4097);
        let swapped = fingerprint_root_source(4097, &mut |i| {
            let position = match i {
                4095 => 4096,
                4096 => 4095,
                _ => i,
            };
            Ok(format!("root-{position}").into_bytes())
        })
        .unwrap();
        assert_ne!(expected, swapped);
        assert_eq!(
            fingerprint_root_source(4097, &mut |i| {
                if i == 4096 {
                    Err(Error::Unavailable)
                } else {
                    Ok(format!("root-{i}").into_bytes())
                }
            }),
            Err(Error::Unavailable)
        );
    }

    #[test]
    fn root_source_fingerprint_detects_replacement_reorder_and_missing() {
        let expected = fingerprint_root_source(2, &mut |index| {
            Ok([b"first".as_slice(), b"second".as_slice()][index].to_vec())
        })
        .unwrap();
        let replaced = fingerprint_root_source(2, &mut |index| {
            Ok([b"first".as_slice(), b"changed".as_slice()][index].to_vec())
        })
        .unwrap();
        let reversed = fingerprint_root_source(2, &mut |index| {
            Ok([b"second".as_slice(), b"first".as_slice()][index].to_vec())
        })
        .unwrap();
        assert_ne!(expected, replaced);
        assert_ne!(expected, reversed);
        assert_eq!(
            fingerprint_root_source(2, &mut |index| if index == 0 {
                Ok(b"first".to_vec())
            } else {
                Err(Error::Unavailable)
            }),
            Err(Error::Unavailable)
        );
    }

    fn request(nonce: &str, version: u64) -> String {
        String::from_utf8(
            json::encode(
                &serde_json::json!({
                    "protocolVersion": 1, "product": "pinvou", "component": "app",
                    "requestNonce": nonce, "root": {"version": version, "sha256": "a".repeat(64)}
                }),
                false,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn issuer_fixture() -> (State, ProductRootBatch) {
        use crate::{
            identity::{FileTime, ProcessSelector},
            monotonic::CounterObservation,
        };
        let binding = Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-nsis-perMachine".into(),
            profile_kind: "production".into(),
            profile_id: "first".into(),
            genesis_seed_sha256: "a".repeat(64),
            genesis_manifest_sha256: "b".repeat(64),
            original_install_operation_id: "original".into(),
        };
        let incarnation = Incarnation {
            host_epoch: 1,
            instance_nonce: "c".repeat(64),
            process: ProcessSelector {
                process_id: 3,
                creation_file_time: FileTime::from_native(1, 2),
            },
        };
        let counter =
            CounterEvidence::from_data(CounterObservation::from_bracket(10, 9, 9, 10).unwrap());
        let evidence = Evidence {
            incarnation: incarnation.clone(),
            request: request("CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg", 1),
            response: "response".into(),
            policy: "policy".into(),
            sent: counter.clone(),
            received: counter,
            floor_before: 0,
            base_root_count: 0,
            denied_key_ids: Vec::new(),
            earliest: 1,
            latest: 2,
        };
        let state = State {
            protocol_version: 1,
            binding: binding.clone(),
            revision: 2,
            previous_sha256: Some("d".repeat(64)),
            incarnation: Some(incarnation),
            status: Status::CleanupPending,
            cleanup_pending: true,
            policy_fault: None,
            zero_retention: None,
            floor: Some(1),
            product_root: None,
            roots: vec!["root-one".into()],
            denied_key_ids: Vec::new(),
            evidence: Some(evidence.clone()),
        };
        (
            state,
            ProductRootBatch {
                binding,
                successor_count: 1,
                evidence,
            },
        )
    }

    #[test]
    fn replay_position_binds_compact_state_identity_and_evidence() {
        let (mut state, _) = issuer_fixture();
        let position = ProductRootPosition {
            head_sha256: "a".repeat(64),
            root_sha256: "b".repeat(64),
            batch: 1,
            root_count: 1,
        };
        state.roots.clear();
        state.product_root = Some(position.clone());
        let proof = ReplayedPosition {
            position,
            root: b"already-replayed-root".to_vec(),
            binding: state.binding.clone(),
            evidence: state.evidence.clone(),
        };
        assert!(proof.authenticate_compact(&state).is_ok());
        let mut bad = state.clone();
        bad.product_root.as_mut().unwrap().head_sha256 = "c".repeat(64);
        assert_eq!(proof.authenticate_compact(&bad), Err(Error::StateCorrupt));
        let mut bad = state.clone();
        bad.binding.profile_id = "other".into();
        assert_eq!(proof.authenticate_compact(&bad), Err(Error::StateCorrupt));
        let mut bad = state.clone();
        bad.evidence.as_mut().unwrap().response = "different".into();
        assert_eq!(proof.authenticate_compact(&bad), Err(Error::StateCorrupt));
    }

    #[test]
    fn issuer_binds_pre_state_incarnation_floor_and_denials() {
        let (mut state, mut batch) = issuer_fixture();
        state.roots.clear();
        batch.evidence.request = request("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk", 2);
        batch.evidence.floor_before = state.floor.unwrap();
        assert_eq!(
            verify_issuer_state(&state, &batch, b"genesis", None, None),
            Ok(true)
        );
        let mut unanchored = state.clone();
        unanchored.evidence = None;
        assert_eq!(
            verify_issuer_state(&unanchored, &batch, b"genesis", None, None),
            Err(Error::StateCorrupt)
        );
        unanchored.floor = None;
        unanchored.status = Status::Unknown;
        assert_eq!(
            verify_issuer_state(&unanchored, &batch, b"genesis", None, None),
            Ok(true)
        );
        let mut reused = batch.clone();
        reused.evidence.request = request("CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg", 2);
        assert_eq!(
            verify_issuer_state(&state, &reused, b"genesis", None, None),
            Err(Error::PrerequisiteUnavailable)
        );
        let mut other = batch.clone();
        other.binding.profile_id = "later-member".into();
        assert_eq!(
            verify_issuer_state(&state, &other, b"genesis", None, None),
            Ok(false)
        );
        state.floor = Some(batch.evidence.floor_before + 1);
        assert_eq!(
            verify_issuer_state(&state, &batch, b"genesis", None, None),
            Err(Error::StateCorrupt)
        );
        state.floor = Some(batch.evidence.floor_before);
        state.denied_key_ids = vec!["f".repeat(64)];
        assert_eq!(
            verify_issuer_state(&state, &batch, b"genesis", None, None),
            Err(Error::StateCorrupt)
        );
    }

    #[test]
    fn later_batch_issuer_state_binds_the_exact_previous_product_root() {
        let (mut state, mut batch) = issuer_fixture();
        state.roots = vec!["protected-previous".into()];
        batch.evidence.request = request("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk", 2);
        batch.evidence.floor_before = state.floor.unwrap();
        batch.evidence.base_root_count = 1;
        let mut previous = head(b"genesis", 1, 1);
        previous.root_sha256 = json::sha256(b"protected-previous");
        assert_eq!(
            verify_issuer_state(&state, &batch, b"previous", Some(&previous), None),
            Ok(true)
        );
        state.roots[0] = "other-predecessor".into();
        assert_eq!(
            verify_issuer_state(&state, &batch, b"previous", Some(&previous), None),
            Err(Error::StateCorrupt)
        );
        state.roots[0] = "protected-previous".into();
        previous.root_count = "2".into();
        assert_eq!(
            verify_issuer_state(&state, &batch, b"previous", Some(&previous), None),
            Err(Error::StateCorrupt)
        );
    }

    #[test]
    fn lagging_issuer_requires_exact_state_incarnation_and_previous_head_cursor() {
        let (mut state, mut batch) = issuer_fixture();
        state.roots.clear();
        batch.evidence.request = request("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk", 3);
        batch.evidence.floor_before = state.floor.unwrap();
        batch.evidence.base_root_count = 2;
        let previous = head(b"earlier", 2, 2);
        let previous_raw = json::encode(&previous, false).unwrap();
        let mut cursor = CatchupRecord {
            version: 1,
            binding: state.binding.clone(),
            state_sha256: json::sha256(&json::encode(&header(&state), false).unwrap()),
            incarnation: state.incarnation.clone().unwrap(),
            position: staged_position(&previous_raw).unwrap(),
        };
        assert_eq!(
            verify_issuer_state(
                &state,
                &batch,
                &previous_raw,
                Some(&previous),
                Some(&cursor)
            ),
            Ok(true)
        );
        cursor.state_sha256 = "f".repeat(64);
        assert_eq!(
            verify_issuer_state(
                &state,
                &batch,
                &previous_raw,
                Some(&previous),
                Some(&cursor)
            ),
            Err(Error::StateCorrupt)
        );
        cursor.state_sha256 = json::sha256(&json::encode(&header(&state), false).unwrap());
        cursor.incarnation.host_epoch += 1;
        assert_eq!(
            verify_issuer_state(
                &state,
                &batch,
                &previous_raw,
                Some(&previous),
                Some(&cursor)
            ),
            Err(Error::StateCorrupt)
        );
    }

    #[test]
    fn historical_membership_is_bound_to_the_recorded_directory_prefix() {
        let historical = b"authenticated earlier directory head";
        let digest = json::sha256(historical);
        // A later member may join without becoming part of this earlier batch.
        assert!(require_historical_directory(2, 1, 1, 1, historical, &digest).is_ok());
        assert!(require_historical_directory(2, 1, 2, 1, historical, &digest).is_err());
        assert!(require_historical_directory(1, 2, 2, 2, historical, &digest).is_err());
        assert!(require_historical_directory(2, 1, 1, 2, historical, &digest).is_err());
        assert!(require_historical_directory(2, 1, 1, 1, b"different", &digest).is_err());
    }

    #[test]
    fn batch_chain_never_moves_membership_backwards() {
        let genesis = b"genesis";
        let first = head(genesis, 1, 1);
        let first_raw = json::encode(&first, false).unwrap();
        let mut second = head(&first_raw, 2, 2);
        second.catalog_revision = "2".into();
        second.catalog_head_sha256 = "6".repeat(64);
        assert!(second.follows(&first_raw, Some(&first)).is_ok());
        let second_raw = json::encode(&second, false).unwrap();
        let mut third = head(&second_raw, 3, 3);
        assert_eq!(
            third.follows(&second_raw, Some(&second)),
            Err(Error::StateCorrupt)
        );
        third.catalog_revision = "2".into();
        assert_eq!(
            third.follows(&second_raw, Some(&second)),
            Err(Error::StateCorrupt)
        );
        third.catalog_head_sha256 = second.catalog_head_sha256.clone();
        assert!(third.follows(&second_raw, Some(&second)).is_ok());
    }

    fn head(previous: &[u8], batch: u64, roots: u64) -> BatchHead {
        BatchHead {
            version: 1,
            batch: batch.to_string(),
            previous_sha256: json::sha256(previous),
            catalog_revision: "1".into(),
            catalog_head_sha256: "5".repeat(64),
            root_count: roots.to_string(),
            successor_count: "1".into(),
            root_sha256: "1".repeat(64),
            roots_chain_sha256: "2".repeat(64),
            member_count: "1".into(),
            members_chain_sha256: "3".repeat(64),
            evidence_sha256: "4".repeat(64),
        }
    }
    #[test]
    fn read_set_rejects_changed_well_formed_successor_head() {
        use super::super::root_read_set::{bind_product_head, require_unchanged};
        let first_raw = json::encode(&head(b"genesis", 1, 1), false).unwrap();
        let first = BatchHead::parse(&first_raw).unwrap();
        first.follows(b"genesis", None).unwrap();
        let second_raw = json::encode(&head(&first_raw, 2, 2), false).unwrap();
        BatchHead::parse(&second_raw)
            .unwrap()
            .follows(&first_raw, Some(&first))
            .unwrap();
        let fingerprint = |raw: &[u8]| {
            let mut hash = Sha256::new();
            hash.update(b"unchanged-member-inputs");
            bind_product_head(&mut hash, raw);
            let digest: [u8; 32] = hash.finalize().into();
            digest
        };
        let before = fingerprint(&first_raw);
        assert!(require_unchanged(&before, &fingerprint(&first_raw)).is_ok());
        assert_eq!(
            require_unchanged(&before, &fingerprint(&second_raw)),
            Err(Error::ScopeConflict)
        );
    }
    #[test]
    fn bounded_heads_chain_without_json_safe_integer_limit() {
        let genesis = b"genesis";
        let first_raw = json::encode(&head(genesis, 1, 1), false).unwrap();
        let first = BatchHead::parse(&first_raw).unwrap();
        first.follows(genesis, None).unwrap();
        let mut invalid_catalog = head(genesis, 1, 1);
        invalid_catalog.catalog_revision = "0".into();
        assert!(BatchHead::parse(&json::encode(&invalid_catalog, false).unwrap()).is_err());
        invalid_catalog.catalog_revision = "1".into();
        invalid_catalog.catalog_head_sha256 = "bad".into();
        assert!(BatchHead::parse(&json::encode(&invalid_catalog, false).unwrap()).is_err());
        let second_raw = json::encode(&head(&first_raw, 2, 2), false).unwrap();
        let second = BatchHead::parse(&second_raw).unwrap();
        second.follows(&first_raw, Some(&first)).unwrap();
        assert!(second.follows(b"other", Some(&first)).is_err());
        assert!(
            head(&first_raw, 3, 2)
                .follows(&first_raw, Some(&first))
                .is_err()
        );
        assert!(
            head(&first_raw, 2, 3)
                .follows(&first_raw, Some(&first))
                .is_err()
        );
        assert_eq!(counter("9007199254740992").unwrap(), 9007199254740992);
        assert!(counter("01").is_err());
        assert!(counter("18446744073709551616").is_err());
    }
    #[test]
    fn object_chains_bind_domain_order_and_framing() {
        fn digest(domain: &'static [u8], values: &[&[u8]]) -> (u64, String) {
            let mut chain = ObjectChain::new(domain);
            for value in values {
                chain.push(value).unwrap();
            }
            chain.finish()
        }
        let a = digest(b"root", &[b"ab", b"c"]);
        assert_eq!(a.0, 2);
        assert_ne!(a, digest(b"member", &[b"ab", b"c"]));
        assert_ne!(a, digest(b"root", &[b"c", b"ab"]));
        assert_ne!(a, digest(b"root", &[b"a", b"bc"]));
        assert_ne!(a, digest(b"root", &[b"ab"]));
        assert_ne!(a, digest(b"root", &[b"ab", b"d"]));
        assert_ne!(a, digest(b"root", &[b"ab", b"c", b"c"]));
        assert!(ObjectChain::new(b"root").push(&[]).is_err());
    }
    #[test]
    fn counters_refuse_overflow() {
        let mut chain = ObjectChain::new(b"root");
        chain.count = u64::MAX;
        assert_eq!(chain.push(b"x"), Err(Error::Unavailable));
        let mut previous = head(b"genesis", u64::MAX, 1);
        let previous_raw = json::encode(&previous, false).unwrap();
        assert_eq!(
            head(&previous_raw, 1, 2).follows(&previous_raw, Some(&previous)),
            Err(Error::Unavailable)
        );
        previous.batch = "1".into();
        previous.root_count = u64::MAX.to_string();
        let previous_raw = json::encode(&previous, false).unwrap();
        assert_eq!(
            head(&previous_raw, 2, 1).follows(&previous_raw, Some(&previous)),
            Err(Error::Unavailable)
        );
    }
}
