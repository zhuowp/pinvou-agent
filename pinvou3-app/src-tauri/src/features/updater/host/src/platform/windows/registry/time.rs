//! Fixed native64 protected time sibling. Missing is never a fresh owner.
//! Its genesis is created exclusively inside original Store::commit(None).
pub(super) mod captured_history;
pub(super) mod member_history;
mod metadata_samples;
mod policy_fault;
pub(super) mod root_history;
mod root_publication;
pub(in crate::platform::windows) use root_publication::RootPublicationClock;
mod root_read_set;
pub(super) mod root_snapshot;
use super::super::installed::StartedServiceContext;
use super::*;
use crate::trusted_time::{
    Binding, CounterEvidence, Evidence, Incarnation, Policy, PolicyFault, ProductRootPosition,
    State, Status,
};
#[cfg(feature = "metadata-component-tests")]
pub(super) use root_read_set::RootReadSet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const NAMESPACE: &str = "trusted-time-v1";
#[allow(unsafe_code)]
fn commit_time_transaction(tx: &Handle) -> Result<()> {
    crate::platform::windows::time_cancel::check()?;
    if unsafe { CommitTransaction(tx.raw()) } == 0 {
        return Err(Error::StateCommitUnknown);
    }
    Ok(())
}
/// Actual read DATA, never a caller-created native source capability.
pub(crate) struct TimeSnapshot {
    pub(crate) raw: Vec<u8>,
    pub(crate) state: State,
    pub(crate) original_root: Vec<u8>,
}
pub(in crate::platform::windows) struct AcquisitionAnchor {
    pub(in crate::platform::windows) root: Vec<u8>,
    pub(in crate::platform::windows) root_count: usize,
    pub(in crate::platform::windows) latest_issue: u64,
}
/// Uncommitted, per-object candidate storage. Its transaction is never
/// committed; closing the last handle rolls it back. It conveys no authority.
pub(in crate::platform::windows) struct RootScratch {
    transaction: Handle,
    path: String,
    count: usize,
    fingerprint: Sha256,
}
impl RootScratch {
    pub(in crate::platform::windows) fn len(&self) -> usize {
        self.count
    }
    pub(in crate::platform::windows) fn read(&self, index: usize) -> Result<Vec<u8>> {
        self.read_candidate(index).map_err(scratch_error)
    }
    fn read_candidate(&self, index: usize) -> Result<Vec<u8>> {
        if index >= self.count {
            return Err(Error::StateCorrupt);
        }
        let root = open(
            HKEY_LOCAL_MACHINE,
            &self.path,
            false,
            Some(&self.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let shard = open(
            root.0,
            &revision_name((index / 4096) as u64 + 1),
            false,
            Some(&self.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let object = open(
            shard.0,
            &revision_name((index % 4096) as u64 + 1),
            false,
            Some(&self.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        super::product_catalog::exact(&object, true, &["Record", "Digest"])?;
        super::product_catalog::exact(&object, false, &[])?;
        let raw = read_limited(&object, "Record", json::RECORD_MAX)?;
        let stored = read_limited(&object, "Digest", 64)?;
        verify_scratch_digest(&stored, &raw)?;
        Ok(raw)
    }
    pub(in crate::platform::windows) fn verify_all(&self) -> Result<()> {
        let mut observed = Sha256::new();
        for index in 0..self.count {
            let raw = self.read(index)?;
            scratch_fingerprint(&mut observed, index, &raw);
        }
        if observed.finalize() != self.fingerprint.clone().finalize() {
            return Err(Error::SourceUnavailable);
        }
        Ok(())
    }
    pub(in crate::platform::windows) fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.push_candidate(bytes).map_err(scratch_error)
    }
    fn push_candidate(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > json::RECORD_MAX {
            return Err(Error::Unavailable);
        }
        let root = open(
            HKEY_LOCAL_MACHINE,
            &self.path,
            true,
            Some(&self.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let shard = create(
            root.0,
            &revision_name((self.count / 4096) as u64 + 1),
            &self.transaction,
            false,
            false,
        )?;
        let object = create(
            shard.0,
            &revision_name((self.count % 4096) as u64 + 1),
            &self.transaction,
            false,
            true,
        )?;
        write(&object, "Record", bytes)?;
        let digest = json::sha256(bytes);
        write(&object, "Digest", digest.as_bytes())?;
        if read_limited(&object, "Record", json::RECORD_MAX)? != bytes
            || read_limited(&object, "Digest", 64)? != digest.as_bytes()
        {
            return Err(Error::StateCorrupt);
        }
        scratch_fingerprint(&mut self.fingerprint, self.count, bytes);
        self.count = self.count.checked_add(1).ok_or(Error::Unavailable)?;
        Ok(())
    }
}
fn scratch_error(error: Error) -> Error {
    match error {
        Error::Busy
        | Error::TimeCanceled
        | Error::StagingCanceled
        | Error::InspectionCanceled
        | Error::RestartCanceled => error,
        _ => Error::SourceUnavailable,
    }
}
fn scratch_fingerprint(hash: &mut Sha256, index: usize, raw: &[u8]) {
    hash.update((index as u64).to_be_bytes());
    hash.update((raw.len() as u64).to_be_bytes());
    hash.update(raw);
}
fn verify_scratch_digest(expected: &[u8], raw: &[u8]) -> Result<()> {
    if expected != json::sha256(raw).as_bytes() {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}
pub(crate) struct PolicySnapshot {
    pub(crate) raw: Vec<u8>,
    pub(crate) policy: Policy,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Blob {
    size: usize,
    sha256: String,
}
impl Blob {
    fn of(bytes: &[u8]) -> Self {
        Self {
            size: bytes.len(),
            sha256: json::sha256(bytes),
        }
    }
    fn read(&self, key: &Key, name: &str, limit: usize) -> Result<Vec<u8>> {
        if self.size == 0 || self.size > limit || !json::digest(&self.sha256) {
            return Err(Error::StateCorrupt);
        }
        let raw = read_limited(key, name, limit)?;
        if raw.len() != self.size || json::sha256(&raw) != self.sha256 {
            return Err(Error::StateCorrupt);
        }
        Ok(raw)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceHeader {
    request: Blob,
    response: Blob,
    policy: Blob,
    sent: CounterEvidence,
    received: CounterEvidence,
    incarnation: Incarnation,
    floor_before: u64,
    base_root_count: usize,
    denied_key_ids: Vec<String>,
    earliest: u64,
    latest: u64,
}
/// Protected catch-up cursor; it never grants time or clears custody. It is
/// tied to one exact member state, SCM incarnation and product position.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatchupRecord {
    version: u8,
    binding: Binding,
    state_sha256: String,
    incarnation: Incarnation,
    position: ProductRootPosition,
}
fn catchup_bytes(
    current: &TimeSnapshot,
    incarnation: Incarnation,
    position: ProductRootPosition,
) -> Result<Vec<u8>> {
    json::encode(
        &CatchupRecord {
            version: 1,
            binding: current.state.binding.clone(),
            state_sha256: json::sha256(&current.raw),
            incarnation,
            position,
        },
        false,
    )
}
fn check_catchup_in(
    key: &Key,
    current: &TimeSnapshot,
    incarnation: Incarnation,
    position: &ProductRootPosition,
) -> Result<()> {
    let raw = read(key, "Catchup")?;
    if raw != catchup_bytes(current, incarnation, position.clone())? {
        return Err(Error::ScopeConflict);
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Header {
    protocol_version: u8,
    binding: Binding,
    revision: u64,
    previous_sha256: Option<String>,
    incarnation: Option<Incarnation>,
    status: Status,
    cleanup_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_fault: Option<PolicyFault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zero_retention: Option<crate::retention_custody::ZeroRetentionReference>,
    floor: Option<u64>,
    roots: Vec<Blob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    product_root: Option<ProductRootPosition>,
    denied_key_ids: Vec<String>,
    evidence: Option<EvidenceHeader>,
}
fn header(state: &State) -> Header {
    Header {
        protocol_version: state.protocol_version,
        binding: state.binding.clone(),
        revision: state.revision,
        previous_sha256: state.previous_sha256.clone(),
        incarnation: state.incarnation.clone(),
        status: state.status,
        cleanup_pending: state.cleanup_pending,
        policy_fault: state.policy_fault.clone(),
        zero_retention: state.zero_retention.clone(),
        floor: state.floor,
        roots: state.roots.iter().map(|s| Blob::of(s.as_bytes())).collect(),
        product_root: state.product_root.clone(),
        denied_key_ids: state.denied_key_ids.clone(),
        evidence: state.evidence.as_ref().map(|e| EvidenceHeader {
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
        }),
    }
}
fn root_capacity(roots: &[Blob]) -> Result<()> {
    if roots.len() > 4096 {
        return Err(Error::Unavailable);
    }
    let mut total = 0usize;
    for r in roots {
        if r.size == 0 || r.size > json::RECORD_MAX {
            return Err(Error::StateCorrupt);
        }
        total = total
            .checked_add(r.size)
            .filter(|n| *n <= json::RECORD_MAX)
            .ok_or(Error::Unavailable)?;
    }
    Ok(())
}
fn read_record_shape(key: &Key, raw: &[u8]) -> Result<State> {
    let h: Header = json::decode(raw, false)?;
    if json::encode(&h, false)? != raw {
        return Err(Error::StateCorrupt);
    }
    root_capacity(&h.roots)?;
    fn text(bytes: Vec<u8>) -> Result<String> {
        String::from_utf8(bytes).map_err(|_| Error::StateCorrupt)
    }
    let mut roots = Vec::with_capacity(h.roots.len());
    for (i, r) in h.roots.iter().enumerate() {
        roots.push(text(r.read(
            key,
            &format!("Root-{i}"),
            json::RECORD_MAX,
        )?)?);
    }
    let evidence = if let Some(e) = h.evidence {
        Some(Evidence {
            request: text(e.request.read(key, "Request", json::FRAME_MAX)?)?,
            response: text(e.response.read(key, "Response", json::FRAME_MAX)?)?,
            policy: text(e.policy.read(key, "PolicyEvidence", json::RECORD_MAX)?)?,
            sent: e.sent,
            received: e.received,
            incarnation: e.incarnation,
            floor_before: e.floor_before,
            base_root_count: e.base_root_count,
            denied_key_ids: e.denied_key_ids,
            earliest: e.earliest,
            latest: e.latest,
        })
    } else {
        None
    };
    let state = State {
        protocol_version: h.protocol_version,
        binding: h.binding,
        revision: h.revision,
        previous_sha256: h.previous_sha256,
        incarnation: h.incarnation,
        status: h.status,
        cleanup_pending: h.cleanup_pending,
        policy_fault: h.policy_fault,
        zero_retention: h.zero_retention,
        floor: h.floor,
        roots,
        product_root: h.product_root,
        denied_key_ids: h.denied_key_ids,
        evidence,
    };
    if state.product_root.is_some() {
        state.validate_compact_shape()?;
    } else {
        state.validate_common()?;
    }
    Ok(state)
}
fn read_record(key: &Key, raw: &[u8], original: &[u8]) -> Result<State> {
    let state = read_record_shape(key, raw)?;
    state.validate(original)?;
    Ok(state)
}
fn write_record(key: &Key, state: &State) -> Result<Vec<u8>> {
    let h = header(state);
    root_capacity(&h.roots)?;
    let raw = json::encode(&h, false)?;
    for (i, r) in state.roots.iter().enumerate() {
        write(key, &format!("Root-{i}"), r.as_bytes())?;
    }
    if let Some(e) = &state.evidence {
        if e.request.len() > json::FRAME_MAX || e.response.len() > json::FRAME_MAX {
            return Err(Error::Unavailable);
        }
        write(key, "Request", e.request.as_bytes())?;
        write(key, "Response", e.response.as_bytes())?;
        write(key, "PolicyEvidence", e.policy.as_bytes())?;
    }
    write(key, "Record", &raw)?;
    Ok(raw)
}
fn state_in(
    private: &Key,
    host: &HostRegistration,
    transaction: Option<&Handle>,
) -> Result<TimeSnapshot> {
    if !crate::bootstrap::initialized(&host.known_owner_namespaces) {
        return Err(Error::SetupIncomplete);
    }
    let original_root = read(private, METADATA_BOOTSTRAP_ROOT)?;
    let key = open(private.0, NAMESPACE, false, transaction)?.ok_or(Error::SetupIncomplete)?;
    let binding = Binding::from_host(host);
    let genesis_raw = read(&key, "Genesis")?;
    let genesis: Header = json::decode(&genesis_raw, false)?;
    let expected = State::genesis(binding.clone(), &original_root)?;
    if genesis_raw != json::encode(&header(&expected), false)? {
        return Err(Error::StateCorrupt);
    }
    let raw = read(&key, "Head")?;
    let h: Header = json::decode(&raw, false)?;
    let history = open(
        key.0,
        &format!("history\\{}", revision_name(h.revision)),
        false,
        transaction,
    )?
    .ok_or(Error::StateCorrupt)?;
    if read(&history, "Record")? != raw {
        return Err(Error::StateCorrupt);
    }
    let state = read_record(&history, &raw, &original_root)?;
    if state.binding != binding {
        return Err(Error::StateCorrupt);
    }
    if state.revision == 1 {
        if raw != genesis_raw {
            return Err(Error::StateCorrupt);
        }
    } else {
        let previous = open(
            key.0,
            &format!("history\\{}", revision_name(state.revision - 1)),
            false,
            transaction,
        )?
        .ok_or(Error::StateCorrupt)?;
        let prior_raw = read(&previous, "Record")?;
        let prior = read_record(&previous, &prior_raw, &original_root)?;
        prior.transition(&state, &prior_raw, &original_root)?;
    }
    if state.status == Status::CleanupVerifiedZero {
        retention::validate_completed_in(private, host, &state, transaction)?;
    } else if open(private.0, retention::NAMESPACE, false, transaction)?.is_some() {
        // Existing fresh custody must keep every historical completion linked,
        // even after the current state becomes Unknown or a new anchor arrives.
        // Missing legacy custody is deliberately neither initialized nor healed.
        retention::read_in(private, host, transaction)?;
    }
    // This is not an obligation census. Even the genuine genesis is Unknown
    // with a barrier; no absence of backups/secrets/budgets is inferred.
    let _ = genesis;
    Ok(TimeSnapshot {
        raw,
        state,
        original_root,
    })
}
#[allow(unsafe_code)]
fn policy_in(key: &Key, binding: &Binding) -> Result<PolicySnapshot> {
    let name = wide("Policy");
    let mut size = 0;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Err(Error::PrerequisiteUnavailable);
    }
    if status != 0 {
        return Err(Error::Unavailable);
    }
    let raw = read(key, "Policy")?;
    let policy = Policy::parse(&raw, binding)?;
    Ok(PolicySnapshot { raw, policy })
}

fn initial_policy_bytes(binding: &Binding) -> Result<Vec<u8>> {
    json::encode(&Policy::initial(binding.clone())?, false)
}

fn verify_initial_policy_in(key: &Key, binding: &Binding) -> Result<()> {
    if policy_in(key, binding)?.raw != initial_policy_bytes(binding)? {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

fn initialize_policy_in(key: &Key, binding: &Binding) -> Result<()> {
    require_absent_value(key, "Policy")?;
    write(key, "Policy", &initial_policy_bytes(binding)?)?;
    verify_initial_policy_in(key, binding)
}

/// Definitive original-commit readback only; this never creates or replaces
/// policy. Existing loads and refreshes keep their mandatory actual-policy read.
pub(super) fn verify_fresh_policy_in(private: &Key, host: &HostRegistration) -> Result<()> {
    let key = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCorrupt)?;
    verify_initial_policy_in(&key, &Binding::from_host(host))
}
// Bounded native adapter census capacity, not a retention or download policy.
// Overflow refuses the census; it never truncates or removes history.
const MAX_CENSUS_TIME_HEADERS: u32 = 16_384;

/// Streaming ledger structure DATA. Native callers supply all actual retained
/// rows; this does not validate signatures or construct a clock/cleanup permit.
struct RetainedCompletionCensus {
    binding: Binding,
    genesis_raw: Vec<u8>,
    head_revision: u64,
    head_sha256: String,
    next_revision: u64,
    previous_sha256: Option<String>,
    references: Vec<crate::retention_custody::ZeroRetentionReference>,
}
impl RetainedCompletionCensus {
    fn new(head_raw: &[u8], genesis_raw: &[u8], binding: &Binding) -> Result<Self> {
        let head: Header = json::decode(head_raw, false)?;
        if json::encode(&head, false)? != head_raw || head.binding != *binding || head.revision == 0
        {
            return Err(Error::StateCorrupt);
        }
        if head.revision > u64::from(MAX_CENSUS_TIME_HEADERS) {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            binding: binding.clone(),
            genesis_raw: genesis_raw.to_vec(),
            head_revision: head.revision,
            head_sha256: json::sha256(head_raw),
            next_revision: 1,
            previous_sha256: None,
            references: Vec::new(),
        })
    }
    fn observe(&mut self, name: &str, raw: &[u8]) -> Result<()> {
        let row: Header = json::decode(raw, false)?;
        if let Some(fault) = &row.policy_fault {
            fault.validate(
                row.revision,
                row.previous_sha256.as_deref(),
                row.status,
                row.incarnation.as_ref(),
            )?;
        }
        if name != revision_name(self.next_revision)
            || row.revision != self.next_revision
            || row.revision > self.head_revision
            || row.binding != self.binding
            || row.previous_sha256 != self.previous_sha256
            || json::encode(&row, false)? != raw
            || self.next_revision == 1 && raw != self.genesis_raw
        {
            return Err(Error::StateCorrupt);
        }
        match (row.status, row.cleanup_pending, row.zero_retention) {
            (Status::CleanupVerifiedZero, false, Some(reference)) => {
                reference.validate()?;
                if reference.completion_revision != row.revision {
                    return Err(Error::StateCorrupt);
                }
                if self.references.len() >= retention::MAX_COMPLETIONS as usize {
                    return Err(Error::Unavailable);
                }
                self.references.push(reference);
            }
            (Status::Unknown | Status::CleanupPending, true, None) => {}
            _ => return Err(Error::StateCorrupt),
        }
        self.previous_sha256 = Some(json::sha256(raw));
        self.next_revision = self
            .next_revision
            .checked_add(1)
            .ok_or(Error::Unavailable)?;
        Ok(())
    }
    fn finish(self) -> Result<Vec<crate::retention_custody::ZeroRetentionReference>> {
        if self.next_revision != self.head_revision + 1
            || self.previous_sha256.as_ref() != Some(&self.head_sha256)
        {
            return Err(Error::StateCorrupt);
        }
        Ok(self.references)
    }
}
/// Read the whole fixed history through actual protected native handles. Only
/// one bounded record body is resident at a time. No recursion into state_in.
pub(super) fn retained_completion_references_in(
    private: &Key,
    host: &HostRegistration,
    tx: Option<&Handle>,
) -> Result<Vec<crate::retention_custody::ZeroRetentionReference>> {
    let key = open(private.0, NAMESPACE, false, tx)?.ok_or(Error::StateCorrupt)?;
    let original_root = read(private, METADATA_BOOTSTRAP_ROOT)?;
    let binding = Binding::from_host(host);
    let expected_genesis = json::encode(
        &header(&State::genesis(binding.clone(), &original_root)?),
        false,
    )?;
    if read(&key, "Genesis")? != expected_genesis {
        return Err(Error::StateCorrupt);
    }
    let mut census =
        RetainedCompletionCensus::new(&read(&key, "Head")?, &expected_genesis, &binding)?;
    let history = open(key.0, "history", false, tx)?.ok_or(Error::StateCorrupt)?;
    if !names(&history, true, 0)?.is_empty() {
        return Err(Error::StateCorrupt);
    }
    let mut revisions = names(&history, false, MAX_CENSUS_TIME_HEADERS)?;
    revisions.sort_unstable();
    for name in revisions {
        let row = open(history.0, &name, false, tx)?.ok_or(Error::StateCorrupt)?;
        census.observe(&name, &read(&row, "Record")?)?;
    }
    census.finish()
}
/// Verify the actual two-way retained link without recursively reading current
/// Time state. Historical completions are not live UTC or a current clean gate.
pub(super) fn check_retained_completion_in(
    private: &Key,
    c: &crate::retention_custody::Completion,
    body: &[u8],
    tx: Option<&Handle>,
) -> Result<()> {
    let key = open(private.0, NAMESPACE, false, tx)?.ok_or(Error::StateCorrupt)?;
    let base = open(
        key.0,
        &format!("history\\{}", revision_name(c.anchor_time_revision)),
        false,
        tx,
    )?
    .ok_or(Error::StateCorrupt)?;
    let base_raw = read(&base, "Record")?;
    let anchor: Header = json::decode(&base_raw, false)?;
    if json::sha256(&base_raw) != c.anchor_time_sha256
        || json::encode(&anchor, false)? != base_raw
        || anchor.binding != c.binding
        || anchor.revision != c.anchor_time_revision
        || anchor.status != Status::CleanupPending
        || !anchor.cleanup_pending
        || anchor.zero_retention.is_some()
        || anchor.incarnation.as_ref() != Some(&c.incarnation)
    {
        return Err(Error::StateCorrupt);
    }
    crate::retention_custody::check_first_scan(
        &anchor
            .evidence
            .as_ref()
            .ok_or(Error::StateCorrupt)?
            .received,
        &c.final_counter,
    )
    .map_err(|_| Error::StateCorrupt)?;
    let completed = open(
        key.0,
        &format!("history\\{}", revision_name(c.completed_time_revision)),
        false,
        tx,
    )?
    .ok_or(Error::StateCorrupt)?;
    let completed_raw = read(&completed, "Record")?;
    let mut next: Header = json::decode(&completed_raw, false)?;
    if json::encode(&next, false)? != completed_raw
        || next.status != Status::CleanupVerifiedZero
        || next.cleanup_pending
        || next.zero_retention.as_ref() != Some(&c.reference()?)
        || next.previous_sha256.as_ref() != Some(&c.anchor_time_sha256)
        || next.revision != c.completed_time_revision
        || json::sha256(body) != c.reference()?.completion_sha256
    {
        return Err(Error::StateCorrupt);
    }
    // Completion changes no original anchor evidence, roots, floor, deny or
    // incarnation. Reverse the finite administrative transition and compare.
    PolicyFault::transition(
        anchor.policy_fault.as_ref(),
        next.policy_fault.as_ref(),
        Status::CleanupVerifiedZero,
        next.revision,
        &base_raw,
    )?;
    next.revision = anchor.revision;
    next.previous_sha256 = anchor.previous_sha256.clone();
    next.status = Status::CleanupPending;
    next.cleanup_pending = true;
    next.zero_retention = None;
    next.policy_fault = anchor.policy_fault.clone();
    if json::encode(&next, false)? != base_raw {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}
// Metadata damage requires repair; it is not evidence of a damaged time
// policy and must not trigger the policy-incident publisher.
fn metadata_root_transition_error(error: Error) -> Error {
    match error {
        Error::StateCorrupt => Error::RepairRequired,
        other => other,
    }
}

// The legacy member-state writer preserves its Root sequence. Shared Root
// changes belong exclusively to the protected V2 publication operation.
fn require_product_root_ready(current: &[String], next: &[String]) -> Result<()> {
    if next != current {
        return Err(Error::SourceUnavailable);
    }
    Ok(())
}

fn require_genesis_roots(roots: &[String]) -> Result<()> {
    if !roots.is_empty() {
        return Err(Error::SourceUnavailable);
    }
    Ok(())
}

// The current product Head is genesis-only. An older member may already have
// advanced independently, so a local genesis alone does not prove safety.
// The caller holds the product guard and supplies its existing transaction.
pub(super) fn require_product_members_at_genesis_in(
    seed: &Seed,
    host: &HostRegistration,
    tx: &Handle,
) -> Result<()> {
    super::product_catalog::visit_members_in(seed, host, tx, |event, member| {
        let path = format!(
            "Software\\Pinvou\\{}\\{}\\private",
            seed.updater_leaf(),
            event.profile_id
        );
        let private =
            open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
        require_genesis_roots(&state_in(&private, member, Some(tx))?.state.roots)
    })
    // Catalog and other members are not this profile's time Policy. Their
    // damage must not trigger the local policy-fault publisher.
    .map_err(metadata_root_transition_error)
}

/// `event` and `member` are authenticated by the same product visitor.
/// A missing or invalid policy/state refuses rather than contributing empty data.
fn check_member_denies_in(
    seed: &Seed,
    event: &crate::product_catalog::Event,
    member: &HostRegistration,
    next: &State,
    original: &[u8],
    tx: &Handle,
) -> Result<()> {
    let path = format!(
        "Software\\Pinvou\\{}\\{}\\private",
        seed.updater_leaf(),
        event.profile_id
    );
    let private = open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let member_state = state_in(&private, member, Some(tx))?;
    if member_state
        .state
        .policy_fault
        .as_ref()
        .is_some_and(PolicyFault::is_active)
    {
        return Err(Error::PrerequisiteUnavailable);
    }
    let time = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    let policy = policy_in(&time, &member_state.state.binding)?;
    let evidence = next.evidence.as_ref().ok_or(Error::StateCorrupt)?;
    for denied in [
        &member_state.state.denied_key_ids,
        &policy.policy.denied_key_ids,
    ] {
        evidence.check_additional_denied(&next.binding, original, &next.roots, denied)?;
    }
    Ok(())
}

/// Enrollment owns both the machine catalog and target product locks and has
/// authenticated the complete existing directory before calling this helper.
pub(super) fn verify_product_history_for_enrollment(
    seed: &Seed,
    guard: &super::product_catalog::ProductGuard,
    tx: &Handle,
) -> Result<()> {
    root_history::replay_persisted_in(seed, guard, tx).map(|_| ())
}

/// Compact state reader for an owner that has already authenticated the
/// complete product directory and retains its product guard and transaction.
/// It does not itself grant live time, installation or commit authority.
fn state_in_product(
    private: &Key,
    host: &HostRegistration,
    seed: &Seed,
    guard: &super::product_catalog::ProductGuard,
    tx: &Handle,
    verified_history: &root_history::VerifiedHistory<'_>,
) -> Result<TimeSnapshot> {
    if !crate::bootstrap::initialized(&host.known_owner_namespaces) {
        return Err(Error::SetupIncomplete);
    }
    verified_history.check_context(seed, guard, tx)?;
    let original = read(private, METADATA_BOOTSTRAP_ROOT)?;
    let key = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    let expected_genesis = State::genesis(Binding::from_host(host), &original)?;
    let genesis_raw = read(&key, "Genesis")?;
    if genesis_raw != json::encode(&header(&expected_genesis), false)? {
        return Err(Error::StateCorrupt);
    }
    let raw = read(&key, "Head")?;
    let h: Header = json::decode(&raw, false)?;
    let history = open(
        key.0,
        &format!("history\\{}", revision_name(h.revision)),
        false,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)?;
    if read(&history, "Record")? != raw {
        return Err(Error::StateCorrupt);
    }
    let state = read_record_shape(&history, &raw)?;
    if state.product_root.is_none() {
        return state_in(private, host, Some(tx));
    }
    if state.binding != Binding::from_host(host) || state.revision <= 1 {
        return Err(Error::StateCorrupt);
    }
    let previous = open(
        key.0,
        &format!("history\\{}", revision_name(state.revision - 1)),
        false,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)?;
    let prior_raw = read(&previous, "Record")?;
    let prior = read_record_shape(&previous, &prior_raw)?;
    let authenticate = |candidate: &State| -> Result<()> {
        if candidate.product_root.is_some() {
            let _ = verified_history.authenticate(candidate)?;
        } else {
            candidate.validate(&original)?;
        }
        Ok(())
    };
    authenticate(&prior)?;
    authenticate(&state)?;
    prior.transition_compact_shape(&state, &prior_raw)?;
    if state.status == Status::CleanupVerifiedZero {
        retention::validate_completed_in(private, host, &state, Some(tx))?;
    } else if open(private.0, retention::NAMESPACE, false, Some(tx))?.is_some() {
        retention::read_in(private, host, Some(tx))?;
    }
    Ok(TimeSnapshot {
        raw,
        state,
        original_root: original,
    })
}

fn product_root_denials_in(
    seed: &Seed,
    actual: &HostRegistration,
    guard: &super::product_catalog::ProductGuard,
    tx: &Handle,
    verified: Option<&root_history::VerifiedHistory<'_>>,
    scratch: &RootScratch,
    candidate: &[u8],
) -> Result<()> {
    let mut collect = |event: &crate::product_catalog::Event, member: &HostRegistration| {
        let path = format!(
            "Software\\Pinvou\\{}\\{}\\private",
            seed.updater_leaf(),
            event.profile_id
        );
        let private =
            open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let snapshot = match verified {
            Some(view) => state_in_product(&private, member, seed, guard, tx, view)?,
            None => state_in(&private, member, Some(tx))?,
        };
        let key = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let policy = policy_in(&key, &snapshot.state.binding)?;
        for denied in [
            &snapshot.state.denied_key_ids,
            &policy.policy.denied_key_ids,
        ] {
            check_transition_denials(
                scratch.len(),
                |index| scratch.read(index),
                candidate,
                &seed.product,
                denied,
            )?;
        }
        Ok(())
    };
    if verified.is_some() {
        super::product_catalog::visit_history_directory_in(seed, actual, guard, tx, &mut collect)?;
    } else {
        super::product_catalog::visit_members_in(seed, actual, tx, &mut collect)?;
    }
    Ok(())
}

fn check_transition_denials(
    count: usize,
    mut read: impl FnMut(usize) -> Result<Vec<u8>>,
    candidate: &[u8],
    product: &str,
    denied: &[String],
) -> Result<()> {
    for index in 0..count {
        let root = read(index)?;
        pinvou_upgrade_verifier::check_time_root_denials(&root, product, denied)
            .map_err(|_| Error::SourceUnavailable)?;
    }
    pinvou_upgrade_verifier::check_time_root_denials(candidate, product, denied)
        .map_err(|_| Error::SourceUnavailable)
}

fn stage_state_in(
    private: &Key,
    actual: &HostRegistration,
    current: &TimeSnapshot,
    next: &State,
    seed: &Seed,
    guard: &super::product_catalog::ProductGuard,
    tx: &Handle,
    verified: Option<&root_history::VerifiedHistory<'_>>,
) -> Result<Vec<u8>> {
    // This helper is reserved for cleanup-only transitions; it does not own
    // the metadata census required to accept a changed Root.
    if next.roots != current.state.roots || next.product_root != current.state.product_root {
        return Err(Error::ScopeConflict);
    }
    if current.state.product_root.is_some() {
        let view = verified.ok_or(Error::StateCorrupt)?;
        view.check_context(seed, guard, tx)?;
        let _ = view.authenticate(&current.state)?;
        let _ = view.authenticate(next)?;
        current.state.transition_compact_shape(next, &current.raw)?;
    } else {
        current
            .state
            .transition(next, &current.raw, &current.original_root)?;
    }
    let key = open(private.0, NAMESPACE, true, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    let history = open(key.0, "history", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let revision = create(history.0, &revision_name(next.revision), tx, false, true)?;
    let raw = write_record(&revision, next)?;
    write(&key, "Head", &raw)?;
    let observed = if let Some(view) = verified {
        state_in_product(private, actual, seed, guard, tx, view)?
    } else {
        state_in(private, actual, Some(tx))?
    };
    if observed.raw != raw {
        return Err(Error::StateCorrupt);
    }
    Ok(raw)
}
/// A native transaction-bound read set, minted only below from fixed protected
/// keys. Detached State/Policy values cannot construct this capability.
pub(in crate::platform::windows) struct LiveTimeReadSet<'tx> {
    private: &'tx Key,
    transaction: &'tx Handle,
    host_digest: String,
    snapshot: TimeSnapshot,
    policy: PolicySnapshot,
    current_root: Vec<u8>,
    product_guard: &'tx super::product_catalog::ProductGuard,
    verified_history: Option<root_history::VerifiedHistory<'tx>>,
}

// Checks only membership in a protected header chain. Signatures and separated
// evidence are checked independently after the entire chain reaches its Head.
struct HistoricalHeaders<'a> {
    binding: &'a Binding,
    genesis: &'a [u8],
    head: &'a [u8],
    head_revision: u64,
    next: u64,
    previous: Option<String>,
}
/// The count complements sequential opens and also catches the unnamed value.
#[allow(unsafe_code)]
fn exact_history_count(key: &Key, expected: u64) -> Result<()> {
    let mut subkeys = 0;
    let mut values = 0;
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
    if values != 0 || u64::from(subkeys) != expected {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}
impl<'a> HistoricalHeaders<'a> {
    fn new(binding: &'a Binding, genesis: &'a [u8], head: &'a [u8]) -> Result<Self> {
        let h: Header = json::decode(head, false)?;
        if json::encode(&h, false)? != head
            || h.binding != *binding
            || h.revision == 0
            || h.revision > json::SAFE_MAX
        {
            return Err(Error::StateCorrupt);
        }
        Ok(Self {
            binding,
            genesis,
            head,
            head_revision: h.revision,
            next: 1,
            previous: None,
        })
    }
    fn observe(&mut self, raw: &[u8]) -> Result<()> {
        let h: Header = json::decode(raw, false)?;
        if json::encode(&h, false)? != raw
            || h.binding != *self.binding
            || h.revision != self.next
            || h.previous_sha256 != self.previous
            || (self.next == 1 && raw != self.genesis)
        {
            return Err(Error::StateCorrupt);
        }
        self.previous = Some(json::sha256(raw));
        self.next = self.next.checked_add(1).ok_or(Error::StateCorrupt)?;
        Ok(())
    }
    fn finish(self) -> Result<()> {
        if self.next != self.head_revision + 1
            || self.previous.as_deref() != Some(json::sha256(self.head).as_str())
        {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}

/// A historical observation anchor, tied to the same guarded transaction as
/// the current time source. It is not a fresh time sample or authority to write.
#[allow(dead_code)] // Consumed by the forthcoming protected metadata replay.
pub(super) struct HistoricalTimeAnchor<'read, 'tx> {
    source: &'read LiveTimeReadSet<'tx>,
    state: State,
    root: Vec<u8>,
}

/// Serialized historical observation DATA. The protected metadata owner must
/// authenticate its entire transaction-bound history before using this record.
/// This value never proves current time or a running service by itself.
#[allow(dead_code)] // Direct prerequisite for protected metadata replay.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct HistoricalSample {
    revision: u64,
    head_sha256: String,
    incarnation: Incarnation,
    counters: CounterEvidence,
    earliest: u64,
    latest: u64,
}
#[allow(dead_code)]
impl HistoricalSample {
    /// Parse canonical observation DATA only; this does not authenticate its
    /// protected storage provenance or grant a current time interval.
    pub(super) fn parse(raw: &[u8]) -> Result<Self> {
        let sample = json::decode(raw, false)?;
        if json::encode(&sample, false)? != raw {
            return Err(Error::StateCorrupt);
        }
        Ok(sample)
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }
    pub(super) fn head_sha256(&self) -> &str {
        &self.head_sha256
    }
    /// Take an actual sample from the protected live source, never from caller
    /// supplied counters. Its caller still owns publication and final recheck.
    pub(super) fn capture<'read, 'tx>(
        host: &StartedServiceContext,
        source: &'read LiveTimeReadSet<'tx>,
    ) -> Result<CapturedHistoricalSample<'read, 'tx>> {
        let first = super::super::live_time::sample_live_time(host, source)?;
        let sampled = first.recheck(host)?;
        CapturedHistoricalSample::from_live(source, sampled)
    }
}
/// Non-cloneable capture tied to the exact original guarded transaction.
#[allow(dead_code)]
pub(super) struct CapturedHistoricalSample<'read, 'tx> {
    source: &'read LiveTimeReadSet<'tx>,
    sample: HistoricalSample,
    live: super::super::live_time::LiveTimeInterval<'read, 'tx>,
}
#[allow(dead_code)]
impl<'read, 'tx> CapturedHistoricalSample<'read, 'tx> {
    fn from_live(
        source: &'read LiveTimeReadSet<'tx>,
        live: super::super::live_time::LiveTimeInterval<'read, 'tx>,
    ) -> Result<Self> {
        if !live.belongs_to(source) {
            return Err(Error::ScopeConflict);
        }
        let bounds = live.bounds();
        let incarnation = source
            .state()
            .incarnation
            .clone()
            .ok_or(Error::SourceUnavailable)?;
        let sample = HistoricalSample {
            revision: source.state().revision,
            head_sha256: source.head_sha256(),
            incarnation,
            counters: live.counter_evidence(),
            earliest: bounds.earliest_millis(),
            latest: bounds.latest_millis(),
        };
        Ok(Self {
            source,
            sample,
            live,
        })
    }

    /// Observation DATA at this actual sample, not at return or commit time.
    pub(super) fn bounds(&self) -> crate::trusted_time::UtcInterval {
        self.live.bounds()
    }

    /// Resample the same native source, retaining actual monotonic continuity.
    /// No serialized sample, caller counter or copied interval can enter here.
    pub(super) fn refresh(&self, host: &StartedServiceContext) -> Result<Self> {
        Self::from_live(self.source, self.live.recheck(host)?)
    }

    pub(super) fn live_for(
        &self,
        source: &LiveTimeReadSet<'_>,
    ) -> Result<&super::super::live_time::LiveTimeInterval<'read, 'tx>> {
        if !std::ptr::eq(self.source, source) || !self.live.belongs_to(source) {
            return Err(Error::ScopeConflict);
        }
        Ok(&self.live)
    }

    pub(super) fn bytes_for(
        &self,
        host: &StartedServiceContext,
        source: &LiveTimeReadSet<'_>,
    ) -> Result<Vec<u8>> {
        if !std::ptr::eq(self.source, source) {
            return Err(Error::ScopeConflict);
        }
        source.recheck(host)?;
        json::encode(&self.sample, false)
    }
}
#[allow(dead_code)]
impl HistoricalTimeAnchor<'_, '_> {
    pub(super) fn state(&self) -> &State {
        &self.state
    }
    pub(super) fn root(&self) -> &[u8] {
        &self.root
    }
    pub(super) fn recheck(&self, host: &StartedServiceContext) -> Result<()> {
        self.source.recheck(host)?;
        self.replay_exact()?;
        self.source.recheck(host)
    }
    // A stable current Head does not authenticate an earlier revision again:
    // another holder may have changed an old row inside this same TxR. Replay
    // the complete retained chain and preserve the originally consumed target.
    fn replay_exact(&self) -> Result<()> {
        let expected = json::encode(&header(&self.state), false)?;
        let (state, root) = self
            .source
            .replay_historical(self.state.revision, &json::sha256(&expected))?;
        if json::encode(&header(&state), false)? != expected
            || state.roots != self.state.roots
            || state.evidence != self.state.evidence
            || root != self.root
        {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
    /// Recalculate historical DATA only; the caller must already have proven
    /// the sample was stored by the genuine protected owner in this same TxR.
    pub(super) fn verify_sample(
        &self,
        host: &StartedServiceContext,
        sample: &HistoricalSample,
    ) -> Result<crate::trusted_time::UtcInterval> {
        self.recheck(host)?;
        let interval = verify_historical_sample(&self.state, &self.root, sample)?;
        self.recheck(host)?;
        Ok(interval)
    }
}

fn verify_historical_sample(
    state: &State,
    root: &[u8],
    sample: &HistoricalSample,
) -> Result<crate::trusted_time::UtcInterval> {
    use crate::trusted_time::{advance_interval, check_root_interval};
    if sample.revision != state.revision
        || sample.head_sha256 != json::sha256(&json::encode(&header(state), false)?)
        || state.incarnation.as_ref() != Some(&sample.incarnation)
    {
        return Err(Error::StateCorrupt);
    }
    let evidence = state.evidence.as_ref().ok_or(Error::SourceUnavailable)?;
    state.anchor_for_live(evidence.policy.as_bytes(), &sample.incarnation)?;
    let interval = advance_interval(
        evidence.earliest,
        evidence.latest,
        evidence.received.data()?,
        sample.counters.data()?,
    )?;
    if sample.earliest != interval.earliest_millis() || sample.latest != interval.latest_millis() {
        return Err(Error::StateCorrupt);
    }
    check_root_interval(root, &state.binding.product, interval)?;
    Ok(interval)
}
impl<'tx> LiveTimeReadSet<'tx> {
    /// Authenticate an actual historical revision through the current Head.
    /// The returned data cannot outlive the held product guard and TxR.
    #[allow(dead_code)] // Direct prerequisite for protected metadata replay.
    pub(super) fn historical_anchor<'read>(
        &'read self,
        host: &StartedServiceContext,
        revision: u64,
        expected_sha256: &str,
    ) -> Result<HistoricalTimeAnchor<'read, 'tx>> {
        self.recheck(host)?;
        let (state, root) = self.replay_historical(revision, expected_sha256)?;
        self.recheck(host)?;
        Ok(HistoricalTimeAnchor {
            source: self,
            state,
            root,
        })
    }

    // Requires the same held guard and transaction as the source. This is
    // not an authorization boundary: callers must perform the SCM rechecks.
    fn replay_historical(&self, revision: u64, expected_sha256: &str) -> Result<(State, Vec<u8>)> {
        member_history::replay_historical_source(
            member_history::HistoricalSource {
                private: self.private,
                transaction: self.transaction,
                binding: &self.snapshot.state.binding,
                original: &self.snapshot.original_root,
                head: &self.snapshot.raw,
            },
            Some((revision, expected_sha256)),
            |state| {
                self.verified_history
                    .as_ref()
                    .ok_or(Error::StateCorrupt)?
                    .authenticate(state)
            },
        )?
        .selected
        .ok_or(Error::StateCorrupt)
    }
}

/// Exercise the same native transaction traversal as the production wrapper.
/// This fixture starts at genuine genesis and therefore cannot prove a
/// successful signed historical observation or SCM authentication.
#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_test_historical_genesis(source: &LiveTimeReadSet<'_>) -> Result<()> {
    member_history::replay_historical_source(
        member_history::HistoricalSource {
            private: source.private,
            transaction: source.transaction,
            binding: &source.snapshot.state.binding,
            original: &source.snapshot.original_root,
            head: &source.snapshot.raw,
        },
        None,
        |_| Err(Error::StateCorrupt),
    )?;
    let digest = json::sha256(&source.snapshot.raw);
    if !matches!(
        source.replay_historical(1, &digest),
        Err(Error::SourceUnavailable)
    ) {
        return Err(Error::StateCorrupt);
    }
    if !matches!(
        source.replay_historical(1, &"f".repeat(64)),
        Err(Error::StateCorrupt)
    ) {
        return Err(Error::StateCorrupt);
    }
    let key = open(source.private.0, NAMESPACE, false, Some(source.transaction))?
        .ok_or(Error::StateCorrupt)?;
    let history =
        open(key.0, "history", true, Some(source.transaction))?.ok_or(Error::StateCorrupt)?;
    let first = open(history.0, &revision_name(1), true, Some(source.transaction))?
        .ok_or(Error::StateCorrupt)?;
    write(&first, "Record", b"broken")?;
    if source.replay_historical(1, &digest).is_ok() {
        return Err(Error::StateCorrupt);
    }
    write(&first, "Record", &source.snapshot.raw)?;
    let _extra = create(history.0, "unexpected", source.transaction, false, true)?;
    if !matches!(
        source.replay_historical(1, &digest),
        Err(Error::StateCorrupt)
    ) {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

/// Real signed legacy Root/time evidence and TxR records. The test source is
/// intentionally constructed here because the production Root gate is closed;
/// it cannot be used to establish an SCM service or production capability.
#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_test_historical_legacy<'a>(
    private: &'a Key,
    seed: &'a Seed,
    host: &HostRegistration,
    guard: &'a super::product_catalog::ProductGuard,
    tx: &'a Handle,
) -> Result<()> {
    member_history::component_test_current(seed, host, guard, tx)?;
    use crate::{
        identity::{FileTime, ProcessSelector},
        monotonic::CounterObservation,
    };
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/product-root-history.json"
    )))
    .map_err(|_| Error::StateCorrupt)?;
    if fixture["original"]
        .as_str()
        .ok_or(Error::StateCorrupt)?
        .as_bytes()
        != seed.original_root_bytes()
    {
        return Err(Error::StateCorrupt);
    }
    let batch = &fixture["batches"][0];
    let key = open(private.0, NAMESPACE, true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let history = open(key.0, "history", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let binding = Binding::from_host(host);
    let policy = policy_in(&key, &binding)?;
    let incarnation = Incarnation {
        host_epoch: 1,
        instance_nonce: "c".repeat(64),
        process: ProcessSelector {
            process_id: 3,
            creation_file_time: FileTime::from_native(1, 2),
        },
    };
    let sent = CounterEvidence::from_data(CounterObservation::from_bracket(
        10_000_000, 9_000_000, 9_000_000, 10_000_000,
    )?);
    let received = CounterEvidence::from_data(CounterObservation::from_bracket(
        10_200_000, 9_200_000, 9_200_000, 10_200_000,
    )?);
    let evidence = Evidence {
        incarnation: incarnation.clone(),
        request: serde_json::to_string(&batch["request"]).map_err(|_| Error::StateCorrupt)?,
        response: batch["response"]
            .as_str()
            .ok_or(Error::StateCorrupt)?
            .into(),
        sent,
        received,
        policy: String::from_utf8(policy.raw.clone()).map_err(|_| Error::StateCorrupt)?,
        floor_before: 0,
        base_root_count: 0,
        denied_key_ids: Vec::new(),
        earliest: batch["earliest"].as_u64().ok_or(Error::StateCorrupt)?,
        latest: batch["latest"].as_u64().ok_or(Error::StateCorrupt)?,
    };
    let mut state = State::genesis(binding, seed.original_root_bytes())?;
    let mut raw = read(&key, "Head")?;
    state.revision = 2;
    state.previous_sha256 = Some(json::sha256(&raw));
    state.incarnation = Some(incarnation);
    let row = create(history.0, &revision_name(2), tx, false, true)?;
    raw = write_record(&row, &state)?;
    state.revision = 3;
    state.previous_sha256 = Some(json::sha256(&raw));
    state.status = Status::CleanupPending;
    state.floor = Some(evidence.earliest);
    state.roots = batch["successors"]
        .as_array()
        .ok_or(Error::StateCorrupt)?
        .iter()
        .map(|root| root.as_str().map(str::to_owned).ok_or(Error::StateCorrupt))
        .collect::<Result<Vec<_>>>()?;
    state.evidence = Some(evidence);
    let row = create(history.0, &revision_name(3), tx, false, true)?;
    raw = write_record(&row, &state)?;
    let old_digest = json::sha256(&raw);
    state.revision = 4;
    state.previous_sha256 = Some(old_digest.clone());
    state.status = Status::Unknown;
    let row = create(history.0, &revision_name(4), tx, false, true)?;
    raw = write_record(&row, &state)?;
    state.revision = 5;
    state.previous_sha256 = Some(json::sha256(&raw));
    let row = create(history.0, &revision_name(5), tx, false, true)?;
    raw = write_record(&row, &state)?;
    write(&key, "Head", &raw)?;
    let snapshot = state_in(private, host, Some(tx))?;
    let source = LiveTimeReadSet {
        private,
        transaction: tx,
        host_digest: host.digest()?,
        current_root: state.current_root(seed.original_root_bytes()).to_vec(),
        snapshot,
        policy,
        product_guard: guard,
        verified_history: None,
    };
    let (accepted, root) = source.replay_historical(3, &old_digest)?;
    if accepted.revision != 3 || root != state.current_root(seed.original_root_bytes()) {
        return Err(Error::StateCorrupt);
    }
    let cached = HistoricalTimeAnchor {
        source: &source,
        state: accepted.clone(),
        root: root.clone(),
    };
    cached.replay_exact()?;
    let old_row = open(history.0, &revision_name(3), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let signed_response = read(&old_row, "Response")?;
    write(&old_row, "Response", b"altered signed time response")?;
    // Current state loading validates separated evidence only for the current
    // and immediately prior rows. Retention's full header census also remains
    // valid. The cached anchor must still reject damage to earlier evidence.
    // This native fixture tests replay without fabricating a running SCM host.
    state_in(private, host, Some(tx))?;
    if source.replay_historical(3, &old_digest).is_ok() || cached.replay_exact().is_ok() {
        return Err(Error::StateCorrupt);
    }
    write(&old_row, "Response", &signed_response)?;
    source.replay_historical(3, &old_digest)?;
    cached.replay_exact()?;
    // Rebuild all affected records and hashes around a well-formed response with
    // an altered signature. This cannot be rejected merely by Blob/header
    // digest checks. Verify the precise cryptographic failure independently.
    let mut bad_state = accepted.clone();
    let bad_evidence = bad_state.evidence.as_mut().ok_or(Error::StateCorrupt)?;
    let mut response: serde_json::Value =
        serde_json::from_slice(&signed_response).map_err(|_| Error::StateCorrupt)?;
    let signature = response["signatures"][0]["signature"]
        .as_str()
        .ok_or(Error::StateCorrupt)?;
    let replacement = format!(
        "{}{}",
        if signature.starts_with('A') { 'B' } else { 'A' },
        &signature[1..]
    );
    response["signatures"][0]["signature"] = replacement.into();
    bad_evidence.response =
        String::from_utf8(json::encode(&response, false)?).map_err(|_| Error::StateCorrupt)?;
    {
        use pinvou_upgrade_codec::{Document, InputKind};
        use pinvou_upgrade_verifier::{
            SuppliedTimeObservation, TimeVerificationError, VerificationError,
            verify_time_response_source,
        };
        let request = Document::parse(bad_evidence.request.as_bytes(), InputKind::Credential)
            .map_err(|_| Error::StateCorrupt)?
            .time_request_shape()
            .map_err(|_| Error::StateCorrupt)?;
        let actual_policy = Policy::parse(bad_evidence.policy.as_bytes(), &bad_state.binding)?;
        let observation = SuppliedTimeObservation {
            sent_monotonic_millis: bad_evidence
                .sent
                .data()?
                .suspend_inclusive()
                .floor_millis()?,
            received_monotonic_millis: bad_evidence
                .received
                .data()?
                .suspend_inclusive()
                .ceil_millis()?,
            max_round_trip_millis: actual_policy.max_round_trip_ms,
            max_uncertainty_millis: actual_policy.max_uncertainty_ms,
            trusted_time_floor_millis: bad_evidence.floor_before,
        };
        let result = verify_time_response_source(
            bad_evidence.response.as_bytes(),
            seed.original_root_bytes(),
            bad_state.roots.len(),
            |index| {
                Ok(std::borrow::Cow::Borrowed(
                    bad_state.roots[index].as_bytes(),
                ))
            },
            &request,
            observation,
            &[],
        );
        if !matches!(
            result,
            Err(TimeVerificationError::Verification(
                VerificationError::InvalidSignature
            ))
        ) {
            return Err(Error::StateCorrupt);
        }
    }
    let bad_raw = write_record(&old_row, &bad_state)?;
    let bad_digest = json::sha256(&bad_raw);
    let middle_row =
        open(history.0, &revision_name(4), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let middle_raw = read(&middle_row, "Record")?;
    let middle = read_record_shape(&middle_row, &middle_raw)?;
    let mut bad_middle = middle.clone();
    bad_middle.previous_sha256 = Some(bad_digest.clone());
    bad_middle.evidence = bad_state.evidence.clone();
    let bad_middle_raw = write_record(&middle_row, &bad_middle)?;
    let mut bad_head_state = state.clone();
    bad_head_state.previous_sha256 = Some(json::sha256(&bad_middle_raw));
    bad_head_state.evidence = bad_state.evidence.clone();
    let last_row =
        open(history.0, &revision_name(5), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let bad_head = write_record(&last_row, &bad_head_state)?;
    write(&key, "Head", &bad_head)?;
    let bad_source = LiveTimeReadSet {
        private,
        transaction: tx,
        host_digest: host.digest()?,
        snapshot: TimeSnapshot {
            raw: bad_head,
            state: bad_head_state,
            original_root: seed.original_root_bytes().to_vec(),
        },
        policy: policy_in(&key, &Binding::from_host(host))?,
        current_root: root.clone(),
        product_guard: guard,
        verified_history: None,
    };
    if !matches!(
        bad_source.replay_historical(3, &bad_digest),
        Err(Error::StateCorrupt)
    ) {
        return Err(Error::StateCorrupt);
    }
    // Restore the valid complete chain before the remaining negative control.
    write_record(&old_row, &accepted)?;
    write_record(&middle_row, &middle)?;
    write_record(&last_row, &state)?;
    write(&key, "Head", &source.snapshot.raw)?;
    source.replay_historical(3, &old_digest)?;
    if !matches!(
        source.replay_historical(
            2,
            &json::sha256(&read(
                &open(history.0, &revision_name(2), false, Some(tx))?.ok_or(Error::StateCorrupt)?,
                "Record"
            )?)
        ),
        Err(Error::SourceUnavailable)
    ) {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}
impl LiveTimeReadSet<'_> {
    pub(in crate::platform::windows) fn state(&self) -> &State {
        &self.snapshot.state
    }
    pub(in crate::platform::windows) fn policy(&self) -> &PolicySnapshot {
        &self.policy
    }
    pub(in crate::platform::windows) fn original_root(&self) -> &[u8] {
        &self.snapshot.original_root
    }
    /// Root selected by the protected, transaction-bound source. Consumers
    /// must recheck this source before treating a sampled interval as current.
    pub(in crate::platform::windows) fn current_root(&self) -> &[u8] {
        &self.current_root
    }
    /// Detached identity DATA for a budget's historical observation record.
    pub(in crate::platform::windows) fn head_sha256(&self) -> String {
        json::sha256(&self.snapshot.raw)
    }
    pub(in crate::platform::windows) fn protected_floor_millis(&self) -> Result<u64> {
        let key = open(
            self.private.0,
            budgets::NAMESPACE,
            false,
            Some(self.transaction),
        )?
        .ok_or(Error::SetupIncomplete)?;
        let floor =
            budgets::floor_for_binding(&key, &self.snapshot.state.binding, Some(self.transaction))?;
        Ok(self
            .snapshot
            .state
            .floor
            .unwrap_or(0)
            .max(floor.unwrap_or(0)))
    }
    /// Recheck the exact read set in its original native transaction. The
    /// caller retains the original BootstrapGuard; this does not acquire a
    /// second guard or open a detached transaction around a captured DTO.
    pub(in crate::platform::windows) fn recheck(&self, host: &StartedServiceContext) -> Result<()> {
        let seed = &host.context.seed;
        let store = Store::new(seed);
        let actual = read_guarded_in(&store, seed, self.product_guard, self.transaction)?
            .ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        if actual.digest()? != self.host_digest {
            return Err(Error::ScopeConflict);
        }
        let observed = if let Some(verified) = &self.verified_history {
            verified.recheck_head()?;
            state_in_product(
                self.private,
                &actual,
                seed,
                self.product_guard,
                self.transaction,
                verified,
            )?
        } else {
            require_product_members_at_genesis_in(seed, &actual, self.transaction)?;
            state_in(self.private, &actual, Some(self.transaction))?
        };
        if observed.raw != self.snapshot.raw
            || observed.original_root != self.snapshot.original_root
            || if let Some(verified) = &self.verified_history {
                if observed.state.product_root.is_some() {
                    verified.authenticate(&observed.state)? != self.current_root
                } else {
                    observed.state.current_root(&observed.original_root) != self.current_root
                }
            } else {
                observed.state.current_root(&observed.original_root) != self.current_root
            }
        {
            return Err(Error::ScopeConflict);
        }
        let time = open(self.private.0, NAMESPACE, false, Some(self.transaction))?
            .ok_or(Error::SetupIncomplete)?;
        if policy_in(&time, &observed.state.binding)?.raw != self.policy.raw {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
}
/// Registry descendants alone can mint this source. This function does not
/// initialize missing state, repair policy or remove the recovery barrier.
pub(super) fn current_in<'tx>(
    private: &'tx Key,
    seed: &'tx Seed,
    actual: &HostRegistration,
    guard: &'tx super::product_catalog::ProductGuard,
    transaction: &'tx Handle,
) -> Result<LiveTimeReadSet<'tx>> {
    let (snapshot, verified_history) = if root_history::advanced_shape_in(seed, transaction)? {
        let verified = root_history::VerifiedHistory::open(seed, actual, guard, transaction)?;
        let snapshot = state_in_product(private, actual, seed, guard, transaction, &verified)?;
        (snapshot, Some(verified))
    } else {
        require_product_members_at_genesis_in(seed, actual, transaction)?;
        (state_in(private, actual, Some(transaction))?, None)
    };
    let time =
        open(private.0, NAMESPACE, false, Some(transaction))?.ok_or(Error::SetupIncomplete)?;
    let policy = policy_in(&time, &snapshot.state.binding)?;
    let current_root = if let Some(verified) = &verified_history {
        if snapshot.state.product_root.is_some() {
            verified.authenticate(&snapshot.state)?
        } else {
            snapshot
                .state
                .current_root(&snapshot.original_root)
                .to_vec()
        }
    } else {
        snapshot
            .state
            .current_root(&snapshot.original_root)
            .to_vec()
    };
    if verified_history
        .as_ref()
        .is_some_and(|verified| verified.current_root() != current_root)
    {
        // A member behind the product must first acquire its own fresh time
        // at the authenticated current product Root.
        return Err(Error::SourceUnavailable);
    }
    Ok(LiveTimeReadSet {
        private,
        transaction,
        host_digest: actual.digest()?,
        snapshot,
        policy,
        current_root,
        product_guard: guard,
        verified_history,
    })
}

/// Called only after the actual new original scope was proven absent in this
/// SAME transaction. It cannot adopt an existing/legacy/partial registration.
pub(super) fn initialize_in(
    private: &Key,
    transaction: &Handle,
    host: &HostRegistration,
) -> Result<()> {
    let actual_root = read(private, METADATA_BOOTSTRAP_ROOT)?;
    let state = State::genesis(Binding::from_host(host), &actual_root)?;
    let raw = json::encode(&header(&state), false)?;
    let key = create(private.0, NAMESPACE, transaction, false, true)?;
    let history = create(key.0, "history", transaction, false, true)?;
    let first = create(history.0, &revision_name(1), transaction, false, true)?;
    write(&key, "Genesis", &raw)?;
    write(&key, "Head", &raw)?;
    write_record(&first, &state)?;
    // Only this original-absence transaction provisions the approved limits.
    // Existing/legacy loads never enroll or heal a missing Policy value.
    initialize_policy_in(&key, &state.binding)?;
    state_in(private, host, Some(transaction))?;
    Ok(())
}
/// Registration read within the caller's held product guard and TxR.
/// An advanced product requires complete directory and Root replay.
pub(super) fn read_guarded_in(
    store: &Store,
    seed: &Seed,
    guard: &super::product_catalog::ProductGuard,
    tx: &Handle,
) -> Result<Option<HostRegistration>> {
    let original = match store.read_in(seed, Some(tx)) {
        Ok(value) => return Ok(value),
        Err(error @ (Error::StateCorrupt | Error::ScopeConflict)) => error,
        Err(error) => return Err(error),
    };
    if !root_history::advanced_shape_in(seed, tx)? {
        return Err(original);
    }
    let Some(actual) = store.read_for_root_history_in(seed, guard, tx)? else {
        return Err(original);
    };
    let verified = root_history::VerifiedHistory::open(seed, &actual, guard, tx)?;
    verified.recheck_head()?;
    Ok(Some(actual))
}

impl Store {
    #[allow(unsafe_code)]
    pub(in crate::platform::windows) fn time_root_scratch(
        &self,
        host: &StartedServiceContext,
        expected: &TimeSnapshot,
    ) -> Result<RootScratch> {
        let seed = &host.context.seed;
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let check = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual = read_guarded_in(self, seed, &guard, &check)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let private = self
            .key(false, Some(&check))?
            .ok_or(Error::SetupIncomplete)?;
        let key = open(private.0, NAMESPACE, false, Some(&check))?.ok_or(Error::SetupIncomplete)?;
        if read(&key, "Head")? != expected.raw {
            return Err(Error::ScopeConflict);
        }
        drop(key);
        drop(private);
        drop(check);
        let transaction = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let private = self
            .key(true, Some(&transaction))?
            .ok_or(Error::SetupIncomplete)?;
        let key =
            open(private.0, NAMESPACE, true, Some(&transaction))?.ok_or(Error::SetupIncomplete)?;
        let candidate = create(key.0, "root-acquisition-v1", &transaction, false, true)
            .map_err(scratch_error)?;
        drop(candidate);
        drop(key);
        drop(private);
        Ok(RootScratch {
            transaction,
            path: format!("{}\\private\\{}\\root-acquisition-v1", self.path, NAMESPACE),
            count: 0,
            fingerprint: Sha256::new(),
        })
    }
    /// Persist a new member's authenticated catch-up before requesting its own
    /// time. This fixed transition accepts no caller-provided Root or time.
    /// A genesis-only product remains on its existing path.
    #[allow(unsafe_code)]
    pub(in crate::platform::windows) fn time_catchup_new(
        &self,
        host: &StartedServiceContext,
        expected: &TimeSnapshot,
    ) -> Result<Option<TimeSnapshot>> {
        let seed = &host.context.seed;
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        if !root_history::advanced_shape_in(seed, &tx)? {
            return Ok(None);
        }
        let actual = read_guarded_in(self, seed, &guard, &tx)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let view = root_history::VerifiedHistory::open(seed, &actual, &guard, &tx)?;
        let private = self.key(true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let current = state_in(&private, &actual, Some(&tx))?;
        if current.raw != expected.raw || current.original_root != expected.original_root {
            return Err(Error::ScopeConflict);
        }
        if current.state.status != Status::Unknown
            || current.state.floor.is_some()
            || current.state.evidence.is_some()
            || current.state.product_root.is_some()
            || !current.state.roots.is_empty()
        {
            return Err(Error::PrerequisiteUnavailable);
        }
        let root_head = root_history::protected_head_in(seed, &tx)?;
        let mut next = current
            .state
            .next_unknown(Incarnation::from_host(&actual)?, &current.raw)?;
        next.product_root = Some(root_history::staged_position(&root_head)?);
        current
            .state
            .transition_compact_shape(&next, &current.raw)?;
        let _ = view.authenticate(&next)?;
        let time = open(private.0, NAMESPACE, true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let history = open(time.0, "history", true, Some(&tx))?.ok_or(Error::StateCorrupt)?;
        let revision = create(history.0, &revision_name(next.revision), &tx, false, true)?;
        let raw = write_record(&revision, &next)?;
        write(&time, "Head", &raw)?;
        if state_in_product(&private, &actual, seed, &guard, &tx, &view)?.raw != raw {
            return Err(Error::StateCorrupt);
        }
        view.recheck_head()?;
        host.authenticate_running(&actual)?;
        drop(revision);
        drop(history);
        drop(time);
        drop(private);
        drop(view);
        commit_time_transaction(&tx)?;
        drop(tx);
        let verify = || -> Result<TimeSnapshot> {
            let private = self.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
            let time = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
            let revision = open(
                time.0,
                &format!("history\\{}", revision_name(next.revision)),
                false,
                None,
            )?
            .ok_or(Error::StateCommitUnknown)?;
            if unsafe { RegFlushKey(time.0) } != 0 || unsafe { RegFlushKey(revision.0) } != 0 {
                return Err(Error::StateCommitUnknown);
            }
            let actual_after = self.read(seed)?.ok_or(Error::StateCommitUnknown)?;
            host.authenticate_running(&actual_after)?;
            let observed = self.time_load(seed, &actual_after)?;
            if observed.raw != raw {
                return Err(Error::StateCommitUnknown);
            }
            Ok(observed)
        };
        Ok(Some(verify().map_err(|_| Error::StateCommitUnknown)?))
    }
    /// Persist a member's verified catch-up without replacing its historical
    /// evidence, floor, deny list or retention/cleanup state. The cursor is
    /// consumed only by that member's subsequent signed time publication.
    #[allow(unsafe_code)]
    pub(in crate::platform::windows) fn time_catchup_existing(
        &self,
        host: &StartedServiceContext,
        expected: &TimeSnapshot,
    ) -> Result<bool> {
        let seed = &host.context.seed;
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        if !root_history::advanced_shape_in(seed, &tx)? {
            return Ok(false);
        }
        let actual = read_guarded_in(self, seed, &guard, &tx)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let view = root_history::VerifiedHistory::open(seed, &actual, &guard, &tx)?;
        let private = self.key(true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let current = state_in_product(&private, &actual, seed, &guard, &tx, &view)?;
        if current.raw != expected.raw
            || current.original_root != expected.original_root
            || current.state.incarnation != Some(Incarnation::from_host(&actual)?)
        {
            return Err(Error::ScopeConflict);
        }
        let position = root_history::staged_position(&root_history::protected_head_in(seed, &tx)?)?;
        if let Some(existing) = current.state.product_root.as_ref() {
            if existing == &position {
                return Ok(false);
            }
            if existing.batch >= position.batch {
                return Err(Error::PrerequisiteUnavailable);
            }
        } else if !current.state.roots.is_empty() {
            return Err(Error::StateCorrupt);
        }
        let key = open(private.0, NAMESPACE, true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let raw = catchup_bytes(&current, Incarnation::from_host(&actual)?, position)?;
        write(&key, "Catchup", &raw)?;
        if read(&key, "Catchup")? != raw {
            return Err(Error::StateCorrupt);
        }
        view.recheck_head()?;
        host.authenticate_running(&actual)?;
        drop(key);
        drop(private);
        drop(view);
        commit_time_transaction(&tx)?;
        drop(tx);
        let verify = || -> Result<()> {
            let private = self.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
            let key = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
            if unsafe { RegFlushKey(key.0) } != 0 || read(&key, "Catchup")? != raw {
                return Err(Error::StateCommitUnknown);
            }
            let actual = self.read(seed)?.ok_or(Error::StateCommitUnknown)?;
            host.authenticate_running(&actual)?;
            if self.time_load(seed, &actual)?.raw != current.raw {
                return Err(Error::StateCommitUnknown);
            }
            Ok(())
        };
        verify().map_err(|_| Error::StateCommitUnknown)?;
        Ok(true)
    }
    /// Before any time or Root request, ensure that the protected product
    /// still permits this member's current Root. The publisher repeats this
    /// check in its own transaction after network work; this observation does
    /// not confer time or Root authority.
    #[allow(unsafe_code)]
    pub(in crate::platform::windows) fn time_acquisition_preflight(
        &self,
        host: &StartedServiceContext,
        expected: &TimeSnapshot,
        transition: Option<(&RootScratch, &[u8])>,
    ) -> Result<AcquisitionAnchor> {
        let seed = &host.context.seed;
        let _guard = BootstrapGuard::acquire(seed, false)?;
        let product_guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let transaction = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual = read_guarded_in(self, seed, &product_guard, &transaction)?
            .ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        if Binding::from_host(&actual) != expected.state.binding {
            return Err(Error::ScopeConflict);
        }
        let private = self
            .key(false, Some(&transaction))?
            .ok_or(Error::SetupIncomplete)?;
        if !root_history::advanced_shape_in(seed, &transaction)? {
            let observed = state_in(&private, &actual, Some(&transaction))?;
            if observed.raw != expected.raw || observed.original_root != expected.original_root {
                return Err(Error::ScopeConflict);
            }
            require_product_members_at_genesis_in(seed, &actual, &transaction)?;
            if let Some((scratch, candidate)) = transition {
                product_root_denials_in(
                    seed,
                    &actual,
                    &product_guard,
                    &transaction,
                    None,
                    scratch,
                    candidate,
                )?;
            }
            return Ok(AcquisitionAnchor {
                root: observed.original_root,
                root_count: 0,
                latest_issue: 0,
            });
        }
        let verified =
            root_history::VerifiedHistory::open(seed, &actual, &product_guard, &transaction)?;
        let observed = state_in_product(
            &private,
            &actual,
            seed,
            &product_guard,
            &transaction,
            &verified,
        )?;
        if observed.raw != expected.raw || observed.original_root != expected.original_root {
            return Err(Error::ScopeConflict);
        }
        let position =
            root_history::staged_position(&root_history::protected_head_in(seed, &transaction)?)?;
        if observed.state.product_root.as_ref() != Some(&position) {
            let key = open(private.0, NAMESPACE, false, Some(&transaction))?
                .ok_or(Error::SetupIncomplete)?;
            check_catchup_in(&key, &observed, Incarnation::from_host(&actual)?, &position)?;
        }
        let root_count = usize::try_from(position.root_count).map_err(|_| Error::Unavailable)?;
        if let Some((scratch, candidate)) = transition {
            product_root_denials_in(
                seed,
                &actual,
                &product_guard,
                &transaction,
                Some(&verified),
                scratch,
                candidate,
            )?;
        }
        verified.recheck_head()?;
        host.authenticate_running(&actual)?;
        Ok(AcquisitionAnchor {
            root: verified.current_root().to_vec(),
            root_count,
            latest_issue: verified.latest_issue(),
        })
    }
    /// Complete ONLY fresh authenticated zero-obligation custody. There is no
    /// caller-provided source, numeric time, permission bool or owner callback.
    /// Existing legacy/missing custody remains paused and is never initialized.
    #[allow(unsafe_code)]
    pub(in crate::platform::windows) fn complete_zero_retention(
        &self,
        host: &StartedServiceContext,
    ) -> Result<()> {
        let seed = &host.context.seed;
        let _guard = BootstrapGuard::acquire(seed, false)?;
        let _product_guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual =
            read_guarded_in(self, seed, &_product_guard, &tx)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let private = self.key(true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let inventory = retention::read_in(&private, &actual, Some(&tx))?;
        let source = current_in(&private, seed, &actual, &_product_guard, &tx)?;
        let current = &source.snapshot;
        if current.state.status != Status::CleanupPending {
            return Err(Error::ScopeConflict);
        }
        let initial = super::super::live_time::sample_live_time(host, &source)?;
        // The full real census is repeated after initial sampling. There is no
        // nonzero cleanup fallback. Any registered producer forbids this profile.
        if retention::read_in(&private, &actual, Some(&tx))? != inventory {
            return Err(Error::ScopeConflict);
        }
        let final_result = initial.recheck(host);
        let (raw, next_revision, late_failure, saved_floor) = match final_result {
            Ok(final_sample) => {
                source.recheck(host)?;
                if retention::read_in(&private, &actual, Some(&tx))? != inventory {
                    return Err(Error::ScopeConflict);
                }
                budgets::retain_samples_floor_in(
                    &private,
                    &actual,
                    &tx,
                    &source,
                    &initial,
                    Some(&final_sample),
                )?;
                let within_scan = crate::retention_custody::check_first_scan(
                    &current
                        .state
                        .evidence
                        .as_ref()
                        .ok_or(Error::StateCorrupt)?
                        .received,
                    &final_sample.counter_evidence(),
                );
                if let Err(error) = within_scan {
                    // Late invocation/lock wait is not evidence that the first
                    // scan met its ceiling. Preserve BOTH successful samples,
                    // keep Unknown, and return the fixed failure after commit.
                    let next = current
                        .state
                        .next_unknown(Incarnation::from_host(&actual)?, &current.raw)?;
                    let raw = stage_state_in(
                        &private,
                        &actual,
                        current,
                        &next,
                        seed,
                        &_product_guard,
                        &tx,
                        source.verified_history.as_ref(),
                    )?;
                    (
                        raw,
                        next.revision,
                        Some(error),
                        final_sample.bounds().earliest_millis(),
                    )
                } else {
                    let next_revision = current
                        .state
                        .revision
                        .checked_add(1)
                        .filter(|n| *n <= json::SAFE_MAX)
                        .ok_or(Error::Unavailable)?;
                    let completion = crate::retention_custody::Completion {
                        protocol_version: 1,
                        binding: current.state.binding.clone(),
                        inventory_revision: 1,
                        inventory_sha256: json::sha256(&inventory),
                        anchor_time_revision: current.state.revision,
                        anchor_time_sha256: json::sha256(&current.raw),
                        completed_time_revision: next_revision,
                        policy_sha256: json::sha256(&source.policy().raw),
                        incarnation: Incarnation::from_host(&actual)?,
                        initial_counter: initial.counter_evidence(),
                        final_counter: final_sample.counter_evidence(),
                        earliest: final_sample.bounds().earliest_millis(),
                        latest: final_sample.bounds().latest_millis(),
                    };
                    completion.validate(&current.state.binding, &inventory)?;
                    let mut next = current.state.clone();
                    next.revision = next_revision;
                    next.previous_sha256 = Some(json::sha256(&current.raw));
                    next.status = Status::CleanupVerifiedZero;
                    next.cleanup_pending = false;
                    next.zero_retention = Some(completion.reference()?);
                    next.policy_fault = next
                        .policy_fault
                        .as_ref()
                        .map(|f| f.recovered(next_revision));
                    // Final fixed source/SCM/readset check precedes the two writes;
                    // both completion and Time Head publish under this one TxR.
                    source.recheck(host)?;
                    retention::stage_completion_in(&private, &tx, &completion, &inventory)?;
                    let raw = stage_state_in(
                        &private,
                        &actual,
                        current,
                        &next,
                        seed,
                        &_product_guard,
                        &tx,
                        source.verified_history.as_ref(),
                    )?;
                    (
                        raw,
                        next_revision,
                        None,
                        final_sample.bounds().earliest_millis(),
                    )
                }
            }
            Err(error @ (Error::SourceUnavailable | Error::Unavailable)) => {
                // A valid initial native sample remains knowledge even when a
                // later counter/root interval is unavailable. Authenticate the
                // original source/SCM and census, retain its lower watermark,
                // then publish Unknown with all original evidence intact.
                source.recheck(host)?;
                if retention::read_in(&private, &actual, Some(&tx))? != inventory {
                    return Err(Error::ScopeConflict);
                }
                budgets::retain_samples_floor_in(&private, &actual, &tx, &source, &initial, None)?;
                let next = current
                    .state
                    .next_unknown(Incarnation::from_host(&actual)?, &current.raw)?;
                let raw = stage_state_in(
                    &private,
                    &actual,
                    current,
                    &next,
                    seed,
                    &_product_guard,
                    &tx,
                    source.verified_history.as_ref(),
                )?;
                (
                    raw,
                    next.revision,
                    Some(error),
                    initial.bounds().earliest_millis(),
                )
            }
            Err(error) => return Err(error),
        };
        drop(initial);
        drop(source);
        drop(private);
        commit_time_transaction(&tx)?;
        drop(tx);
        let verify = || -> Result<()> {
            let actual_after = self.read(seed)?.ok_or(Error::StateCommitUnknown)?;
            host.authenticate_running(&actual_after)?;
            if actual_after.digest()? != actual.digest()? {
                return Err(Error::StateCommitUnknown);
            }
            let private = self.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
            let key = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
            let history = open(
                key.0,
                &format!("history\\{}", revision_name(next_revision)),
                false,
                None,
            )?
            .ok_or(Error::StateCommitUnknown)?;
            let custody = open(private.0, retention::NAMESPACE, false, None)?
                .ok_or(Error::StateCommitUnknown)?;
            let budget = open(private.0, budgets::NAMESPACE, false, None)?
                .ok_or(Error::StateCommitUnknown)?;
            if unsafe { RegFlushKey(key.0) } != 0
                || unsafe { RegFlushKey(history.0) } != 0
                || unsafe { RegFlushKey(custody.0) } != 0
                || unsafe { RegFlushKey(budget.0) } != 0
            {
                return Err(Error::StateCommitUnknown);
            }
            if self.time_load(seed, &actual_after)?.raw != raw
                || retention::read_in(&private, &actual_after, None)? != inventory
            {
                return Err(Error::StateCommitUnknown);
            }
            if budgets::floor_in(&private, &actual_after, None)?.map_or(true, |v| v < saved_floor) {
                return Err(Error::StateCommitUnknown);
            }
            Ok(())
        };
        verify().map_err(|_| Error::StateCommitUnknown)?;
        match late_failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    /// Read-only diagnostic under the same short native mutex/transaction as
    /// budget/time reads. No COMMIT, initialization, network or state repair.
    pub(in crate::platform::windows) fn diagnostic_time(
        &self,
        host: &StartedServiceContext,
    ) -> Result<crate::TrustedTimeState> {
        match self.diagnostic_time_checked(host) {
            Ok(state) => Ok(state),
            Err(Error::Busy) => Err(Error::Busy),
            Err(error) => Ok(protected_diagnostic_error(error)),
        }
    }
    #[allow(unsafe_code)]
    fn diagnostic_time_checked(
        &self,
        host: &StartedServiceContext,
    ) -> Result<crate::TrustedTimeState> {
        let seed = &host.context.seed;
        let _guard = BootstrapGuard::acquire(seed, false)?;
        let _product_guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let transaction = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual = read_guarded_in(self, seed, &_product_guard, &transaction)?
            .ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let private = self
            .key(false, Some(&transaction))?
            .ok_or(Error::SetupIncomplete)?;
        // Authenticate all protected sources even when no live interval can be
        // offered. A valid empty budget floor is not a missing budget namespace.
        let source = current_in(&private, seed, &actual, &_product_guard, &transaction)?;
        if source
            .state()
            .policy_fault
            .as_ref()
            .is_some_and(PolicyFault::is_active)
        {
            return Ok(crate::TrustedTimeState::IntegrityFault);
        }
        let _floor = budgets::floor_in(&private, &actual, Some(&transaction))?;
        let state = source.state();
        let incarnation = Incarnation::from_host(&actual)?;
        if state.status == Status::Unknown || state.incarnation.as_ref() != Some(&incarnation) {
            source.recheck(host)?;
            return Ok(crate::TrustedTimeState::Unknown);
        }
        // Uses actual stored Root/policy/incarnation plus a fresh native sample;
        // the copied old anchor alone cannot produce this diagnostic state.
        let _current = super::super::live_time::sample_live_time(host, &source)?;
        source.recheck(host)?;
        Ok(if state.status == Status::CleanupVerifiedZero {
            crate::TrustedTimeState::CleanupComplete
        } else {
            crate::TrustedTimeState::CleanupPending
        })
    }
    #[allow(unsafe_code)]
    pub(crate) fn time_load(
        &self,
        seed: &Seed,
        expected: &HostRegistration,
    ) -> Result<TimeSnapshot> {
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual = read_guarded_in(self, seed, &guard, &tx)?.ok_or(Error::SetupIncomplete)?;
        if actual.digest()? != expected.digest()? {
            return Err(Error::ScopeConflict);
        }
        let private = self.key(false, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        if root_history::advanced_shape_in(seed, &tx)? {
            let view = root_history::VerifiedHistory::open(seed, &actual, &guard, &tx)?;
            let snapshot = state_in_product(&private, &actual, seed, &guard, &tx, &view)?;
            view.recheck_head()?;
            Ok(snapshot)
        } else {
            state_in(&private, &actual, Some(&tx))
        }
    }
    pub(crate) fn time_policy(
        &self,
        seed: &Seed,
        expected: &TimeSnapshot,
    ) -> Result<PolicySnapshot> {
        let actual = self.read(seed)?.ok_or(Error::SetupIncomplete)?;
        if Binding::from_host(&actual) != expected.state.binding {
            return Err(Error::ScopeConflict);
        }
        let private = self.key(false, None)?.ok_or(Error::SetupIncomplete)?;
        let time = open(private.0, NAMESPACE, false, None)?.ok_or(Error::SetupIncomplete)?;
        if read(&time, "Head")? != expected.raw {
            return Err(Error::ScopeConflict);
        }
        let policy = policy_in(&time, &expected.state.binding)?;
        if read(&time, "Head")? != expected.raw {
            return Err(Error::ScopeConflict);
        }
        Ok(policy)
    }
    /// Invalidate a compact observation or persist newly observed denies.
    /// The exact authenticated product position is unchanged in this TxR.
    #[allow(unsafe_code)]
    fn time_commit_compact_unknown(
        &self,
        host: &StartedServiceContext,
        expected: &TimeSnapshot,
        next: &State,
        policy: Option<&PolicySnapshot>,
    ) -> Result<TimeSnapshot> {
        if next.status != Status::Unknown {
            return Err(Error::StateCorrupt);
        }
        let seed = &host.context.seed;
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual = read_guarded_in(self, seed, &guard, &tx)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        if next.incarnation != Some(Incarnation::from_host(&actual)?) {
            return Err(Error::ScopeConflict);
        }
        let view = root_history::VerifiedHistory::open(seed, &actual, &guard, &tx)?;
        let private = self.key(true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let current = state_in_product(&private, &actual, seed, &guard, &tx, &view)?;
        if current.raw != expected.raw
            || current.original_root != expected.original_root
            || next.policy_fault != current.state.policy_fault
        {
            return Err(Error::ScopeConflict);
        }
        let time = open(private.0, NAMESPACE, false, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        match policy {
            None if next.denied_key_ids == current.state.denied_key_ids => {}
            Some(captured) => {
                let actual_policy = policy_in(&time, &next.binding)?;
                if actual_policy.raw != captured.raw {
                    return Err(Error::ScopeConflict);
                }
                let mut known = current.state.denied_key_ids.clone();
                known.extend(actual_policy.policy.denied_key_ids.iter().cloned());
                known.sort();
                known.dedup();
                if next.denied_key_ids != known {
                    return Err(Error::StateCorrupt);
                }
            }
            _ => return Err(Error::StateCorrupt),
        }
        let raw = stage_state_in(
            &private,
            &actual,
            &current,
            next,
            seed,
            &guard,
            &tx,
            Some(&view),
        )?;
        view.recheck_head()?;
        host.authenticate_running(&actual)?;
        drop(time);
        drop(private);
        drop(view);
        commit_time_transaction(&tx)?;
        drop(tx);
        let verify = || -> Result<TimeSnapshot> {
            let private = self.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
            let time = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
            let revision = open(
                time.0,
                &format!("history\\{}", revision_name(next.revision)),
                false,
                None,
            )?
            .ok_or(Error::StateCommitUnknown)?;
            if unsafe { RegFlushKey(time.0) } != 0 || unsafe { RegFlushKey(revision.0) } != 0 {
                return Err(Error::StateCommitUnknown);
            }
            let actual = self.read(seed)?.ok_or(Error::StateCommitUnknown)?;
            host.authenticate_running(&actual)?;
            let observed = self.time_load(seed, &actual)?;
            if observed.raw != raw {
                return Err(Error::StateCommitUnknown);
            }
            Ok(observed)
        };
        verify().map_err(|_| Error::StateCommitUnknown)
    }

    /// Publish a member's own signed time at its persisted current product
    /// position, delegating nonempty Root changes to the protected V2 owner.
    #[allow(unsafe_code)]
    pub(in crate::platform::windows) fn time_commit_compact_anchor(
        &self,
        host: &StartedServiceContext,
        expected: &TimeSnapshot,
        captured: &PolicySnapshot,
        evidence: &Evidence,
        successors: &RootScratch,
        pending: Option<&crate::platform::windows::time_owner::PendingRootTime<'_, '_>>,
    ) -> Result<TimeSnapshot> {
        if successors.len() != 0 {
            return root_publication::publish(
                self,
                host,
                expected,
                captured,
                evidence,
                successors,
                pending.ok_or(Error::SourceUnavailable)?,
            );
        }
        successors.verify_all()?;
        let seed = &host.context.seed;
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual = read_guarded_in(self, seed, &guard, &tx)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let private = self.key(true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let advanced = root_history::advanced_shape_in(seed, &tx)?;
        // Normal zero-successor genesis remains on time_commit. Local-only
        // legacy rotations cannot be promoted by inventing shared witnesses.
        if !advanced {
            return Err(Error::SourceUnavailable);
        }
        let view = root_history::VerifiedHistory::open(seed, &actual, &guard, &tx)?;
        let current = state_in_product(&private, &actual, seed, &guard, &tx, &view)?;
        if current.raw != expected.raw
            || current.original_root != expected.original_root
            || current.state.incarnation != Some(Incarnation::from_host(&actual)?)
            || evidence.incarnation != Incarnation::from_host(&actual)?
        {
            return Err(Error::ScopeConflict);
        }
        let position = root_history::staged_position(&root_history::protected_head_in(seed, &tx)?)?;
        if u64::try_from(evidence.base_root_count).ok() != Some(position.root_count) {
            return Err(Error::PrerequisiteUnavailable);
        }
        let key = open(private.0, NAMESPACE, true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let caught_up = current.state.product_root.as_ref() != Some(&position);
        if !caught_up && current.state.status != Status::Unknown {
            return Err(Error::ScopeConflict);
        }
        if caught_up {
            check_catchup_in(&key, &current, Incarnation::from_host(&actual)?, &position)?;
        }
        let policy = policy_in(&key, &current.state.binding)?;
        if policy.raw != captured.raw || evidence.policy.as_bytes() != policy.raw {
            return Err(Error::ScopeConflict);
        }
        let mut denied = current.state.denied_key_ids.clone();
        denied.extend(policy.policy.denied_key_ids.iter().cloned());
        denied.sort();
        denied.dedup();
        if denied != evidence.denied_key_ids {
            return Err(Error::StateCorrupt);
        }
        let floor = current
            .state
            .floor
            .unwrap_or(0)
            .max(budgets::floor_in(&private, &actual, Some(&tx))?.unwrap_or(0));
        if evidence.floor_before != floor {
            return Err(Error::ScopeConflict);
        }
        crate::trusted_time::check_history_time_bound(view.latest_issue(), evidence.earliest)
            .map_err(|_| Error::ScopeConflict)?;
        let mut next = current
            .state
            .next_unknown(Incarnation::from_host(&actual)?, &current.raw)?;
        next.status = Status::CleanupPending;
        next.cleanup_pending = true;
        next.zero_retention = None;
        next.floor = Some(evidence.earliest);
        next.denied_key_ids = denied;
        next.evidence = Some(evidence.clone());
        if caught_up {
            next.product_root = Some(position);
        }
        let raw = if caught_up {
            current
                .state
                .transition_compact_shape(&next, &current.raw)?;
            let _ = view.authenticate(&next)?;
            let history = open(key.0, "history", true, Some(&tx))?.ok_or(Error::StateCorrupt)?;
            let revision = create(history.0, &revision_name(next.revision), &tx, false, true)?;
            let raw = write_record(&revision, &next)?;
            write(&key, "Head", &raw)?;
            if state_in_product(&private, &actual, seed, &guard, &tx, &view)?.raw != raw {
                return Err(Error::StateCorrupt);
            }
            raw
        } else {
            stage_state_in(
                &private,
                &actual,
                &current,
                &next,
                seed,
                &guard,
                &tx,
                Some(&view),
            )?
        };
        if caught_up && unsafe { RegDeleteValueW(key.0, wide("Catchup").as_ptr()) } != 0 {
            return Err(Error::StateCorrupt);
        }
        if policy_in(&key, &current.state.binding)?.raw != captured.raw
            || current
                .state
                .floor
                .unwrap_or(0)
                .max(budgets::floor_in(&private, &actual, Some(&tx))?.unwrap_or(0))
                != floor
        {
            return Err(Error::ScopeConflict);
        }
        successors.verify_all()?;
        view.recheck_head()?;
        host.authenticate_running(&actual)?;
        drop(key);
        drop(private);
        drop(view);
        commit_time_transaction(&tx)?;
        drop(tx);
        let verify = || -> Result<TimeSnapshot> {
            let private = self.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
            let time = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
            let revision = open(
                time.0,
                &format!("history\\{}", revision_name(next.revision)),
                false,
                None,
            )?
            .ok_or(Error::StateCommitUnknown)?;
            if unsafe { RegFlushKey(time.0) } != 0 || unsafe { RegFlushKey(revision.0) } != 0 {
                return Err(Error::StateCommitUnknown);
            }
            let actual = self.read(seed)?.ok_or(Error::StateCommitUnknown)?;
            host.authenticate_running(&actual)?;
            let observed = self.time_load(seed, &actual)?;
            if observed.raw != raw {
                return Err(Error::StateCommitUnknown);
            }
            Ok(observed)
        };
        verify().map_err(|_| Error::StateCommitUnknown)
    }

    /// Private fixed publisher: SCM authority, complete original custody,
    /// expected state and (for an anchor) exact captured Policy are rechecked
    /// INSIDE the same native transaction. No network work occurs under it.
    #[allow(unsafe_code)]
    pub(crate) fn time_commit(
        &self,
        host: &StartedServiceContext,
        expected: &TimeSnapshot,
        next: &State,
        policy: Option<&PolicySnapshot>,
    ) -> Result<TimeSnapshot> {
        if next.status == Status::CleanupVerifiedZero {
            return Err(Error::StateCorrupt);
        }
        if expected.state.product_root.is_some() && next.status == Status::Unknown {
            return self.time_commit_compact_unknown(host, expected, next, policy);
        }
        let seed = &host.context.seed;
        let before = self.read(seed)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&before)?;
        let _guard = BootstrapGuard::acquire(seed, false)?;
        // The product Root census reads every member's time state. Every
        // state revision must serialize with that census, including Unknown.
        let guard = super::product_catalog::ProductGuard::acquire(seed)?;
        guard.check_seed(seed)?;
        let _product_guard = guard;
        let transaction = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual = read_guarded_in(self, seed, &_product_guard, &transaction)?
            .ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        if before.digest()? != actual.digest()?
            || Binding::from_host(&actual) != expected.state.binding
            || next.incarnation != Some(Incarnation::from_host(&actual)?)
        {
            return Err(Error::ScopeConflict);
        }
        let private = self
            .key(true, Some(&transaction))?
            .ok_or(Error::SetupIncomplete)?;
        let current = state_in(&private, &actual, Some(&transaction))?;
        if current.raw != expected.raw || current.original_root != expected.original_root {
            return Err(Error::ScopeConflict);
        }
        // Root changes have one streamed V2 publisher. This legacy operation
        // may preserve its existing Roots, never create a second promotion path.
        require_product_root_ready(&current.state.roots, &next.roots)?;
        if next.status == Status::CleanupPending {
            require_product_members_at_genesis_in(seed, &actual, &transaction)?;
        }
        // Only the positively-observed native fault publisher and the fixed
        // zero-custody completion path can change incident state.
        if next.policy_fault != current.state.policy_fault {
            return Err(Error::StateCorrupt);
        }
        current
            .state
            .transition(next, &current.raw, &current.original_root)?;
        let key =
            open(private.0, NAMESPACE, true, Some(&transaction))?.ok_or(Error::SetupIncomplete)?;
        match (next.status, policy) {
            (Status::Unknown, None) => {
                if next.denied_key_ids != current.state.denied_key_ids {
                    return Err(Error::StateCorrupt);
                }
            }
            (status, Some(captured)) => {
                let actual_policy = policy_in(&key, &next.binding)?;
                if actual_policy.raw != captured.raw {
                    return Err(Error::ScopeConflict);
                }
                let mut known = current.state.denied_key_ids.clone();
                known.extend(actual_policy.policy.denied_key_ids.iter().cloned());
                known.sort();
                known.dedup();
                if next.denied_key_ids != known {
                    return Err(Error::StateCorrupt);
                }
                if status == Status::CleanupPending
                    && next
                        .evidence
                        .as_ref()
                        .ok_or(Error::StateCorrupt)?
                        .policy
                        .as_bytes()
                        != captured.raw
                {
                    return Err(Error::StateCorrupt);
                }
            }
            _ => return Err(Error::StateCorrupt),
        }
        if next.status == Status::CleanupPending {
            let actual_floor = current
                .state
                .floor
                .unwrap_or(0)
                .max(budgets::floor_in(&private, &actual, Some(&transaction))?.unwrap_or(0));
            if next
                .evidence
                .as_ref()
                .ok_or(Error::StateCorrupt)?
                .floor_before
                != actual_floor
            {
                return Err(Error::ScopeConflict);
            }
        }
        let stored = next.clone();
        let raw = json::encode(&header(&stored), false)?;
        let history =
            open(key.0, "history", true, Some(&transaction))?.ok_or(Error::StateCorrupt)?;
        let revision = create(
            history.0,
            &revision_name(stored.revision),
            &transaction,
            false,
            true,
        )?;
        if write_record(&revision, &stored)? != raw {
            return Err(Error::StateCorrupt);
        }
        write(&key, "Head", &raw)?;
        let staged = state_in(&private, &actual, Some(&transaction))?;
        if staged.raw != raw {
            return Err(Error::StateCorrupt);
        }
        drop(revision);
        drop(history);
        drop(key);
        drop(private);
        commit_time_transaction(&transaction)?;
        drop(transaction);
        let verify = || -> Result<TimeSnapshot> {
            let private = self.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
            let key = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
            let history = open(
                key.0,
                &format!("history\\{}", revision_name(next.revision)),
                false,
                None,
            )?
            .ok_or(Error::StateCommitUnknown)?;
            if unsafe { RegFlushKey(key.0) } != 0 || unsafe { RegFlushKey(history.0) } != 0 {
                return Err(Error::StateCommitUnknown);
            }
            let after = self.read(seed)?.ok_or(Error::StateCommitUnknown)?;
            host.authenticate_running(&after)?;
            let observed = state_in(&private, &after, None)?;
            if observed.raw != raw {
                return Err(Error::StateCommitUnknown);
            }
            Ok(observed)
        };
        // No later ACL/flush/readback/SCM error is a no-write error.
        verify().map_err(|_| Error::StateCommitUnknown)
    }
}

fn protected_diagnostic_error(error: Error) -> crate::TrustedTimeState {
    use crate::TrustedTimeState as State;
    match error {
        Error::Unsupported | Error::ProfileDisabled | Error::OperationUnsupported => {
            State::Unsupported
        }
        Error::SetupIncomplete | Error::InitialTrustUnavailable => State::SetupRequired,
        Error::PrerequisiteUnavailable => State::MissingPolicy,
        // Only this actual native protected-store/ACL path may confirm damage.
        Error::StateCorrupt => State::IntegrityFault,
        // Existing native security probes also use SecurityRefused when an OS
        // query fails; source refusal alone does not confirm component damage.
        Error::SecurityRefused => State::SourceUnavailable,
        // A new incarnation or legal read race is not component damage.
        Error::ServiceIdentityRefused | Error::ScopeConflict => State::Unknown,
        _ => State::SourceUnavailable,
    }
}
#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn ordinary_offline_crossboot_and_missing_policy_do_not_become_integrity_fault() {
        use crate::TrustedTimeState as State;
        assert_eq!(
            protected_diagnostic_error(Error::SourceUnavailable),
            State::SourceUnavailable
        );
        assert_eq!(
            protected_diagnostic_error(Error::Unavailable),
            State::SourceUnavailable
        );
        assert_eq!(
            protected_diagnostic_error(Error::StateCommitUnknown),
            State::SourceUnavailable
        );
        assert_eq!(
            protected_diagnostic_error(Error::ServiceIdentityRefused),
            State::Unknown
        );
        assert_eq!(
            protected_diagnostic_error(Error::ScopeConflict),
            State::Unknown
        );
        assert_eq!(
            protected_diagnostic_error(Error::PrerequisiteUnavailable),
            State::MissingPolicy
        );
        assert_eq!(
            protected_diagnostic_error(Error::SetupIncomplete),
            State::SetupRequired
        );
        assert_eq!(
            protected_diagnostic_error(Error::StateCorrupt),
            State::IntegrityFault
        );
        assert_eq!(
            protected_diagnostic_error(Error::SecurityRefused),
            State::SourceUnavailable
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[allow(unsafe_code)]
    fn canceled_time_commit_rolls_back_and_new_attempt_can_commit() {
        use std::sync::{Arc, atomic::AtomicBool};
        let path = wide(&format!(
            "Software\\PinvouTimeCommitCancelTest-{}",
            std::process::id()
        ));
        let mut raw = ptr::null_mut();
        let mut disposition = 0;
        assert_eq!(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    ptr::null(),
                    &mut raw,
                    &mut disposition,
                )
            },
            0
        );
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        struct Owned {
            key: Option<Key>,
            path: Vec<u16>,
        }
        impl Drop for Owned {
            fn drop(&mut self) {
                drop(self.key.take());
                unsafe {
                    RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr());
                }
            }
        }
        let owned = Owned {
            key: Some(Key(raw)),
            path,
        };
        let key = owned.key.as_ref().unwrap();
        let stop = Arc::new(crate::platform::windows::pipe::Event::new().unwrap());
        let scope = crate::platform::windows::time_cancel::WorkerCancelScope::enter(
            Arc::new(AtomicBool::new(false)),
            stop.clone(),
        )
        .unwrap();
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let mut item = ptr::null_mut();
        assert_eq!(
            unsafe {
                RegCreateKeyTransactedW(
                    key.0,
                    wide("pending").as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    ptr::null(),
                    &mut item,
                    &mut disposition,
                    tx.raw(),
                    ptr::null(),
                )
            },
            0
        );
        drop(Key(item));
        stop.set().unwrap();
        assert_eq!(commit_time_transaction(&tx), Err(Error::TimeCanceled));
        drop(tx);
        drop(scope);
        let mut observed = ptr::null_mut();
        assert_eq!(
            unsafe { RegOpenKeyExW(key.0, wide("pending").as_ptr(), 0, KEY_READ, &mut observed) },
            ERROR_FILE_NOT_FOUND
        );
        assert!(observed.is_null());
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let mut retry = ptr::null_mut();
        assert_eq!(
            unsafe {
                RegCreateKeyTransactedW(
                    key.0,
                    wide("retry").as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    ptr::null(),
                    &mut retry,
                    &mut disposition,
                    tx.raw(),
                    ptr::null(),
                )
            },
            0
        );
        drop(Key(retry));
        commit_time_transaction(&tx).unwrap();
        drop(tx);
        assert_eq!(
            unsafe { RegOpenKeyExW(key.0, wide("retry").as_ptr(), 0, KEY_READ, &mut observed) },
            0
        );
        drop(Key(observed));
    }
    #[test]
    fn scratch_failures_never_become_policy_corruption() {
        for error in [
            Error::StateCorrupt,
            Error::Unavailable,
            Error::SecurityRefused,
            Error::ScopeConflict,
        ] {
            assert_eq!(scratch_error(error), Error::SourceUnavailable);
        }
        for error in [
            Error::Busy,
            Error::StagingCanceled,
            Error::InspectionCanceled,
            Error::RestartCanceled,
            Error::TimeCanceled,
        ] {
            assert_eq!(scratch_error(error), error);
        }
    }
    #[test]
    fn denial_checks_read_each_prefix_object_and_detect_changed_or_missing_source() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/product-root-history.json"
        )))
        .unwrap();
        let roots = fixture["batches"][0]["successors"].as_array().unwrap();
        let first = roots[0].as_str().unwrap().as_bytes();
        let candidate = roots[1].as_str().unwrap().as_bytes();
        let digest = json::sha256(first);
        assert!(verify_scratch_digest(digest.as_bytes(), first).is_ok());
        assert_eq!(
            verify_scratch_digest(digest.as_bytes(), candidate),
            Err(Error::StateCorrupt)
        );
        assert_eq!(verify_scratch_digest(&[], first), Err(Error::StateCorrupt));
        let mut reads = 0;
        assert!(
            check_transition_denials(
                1,
                |index| {
                    reads += 1;
                    assert_eq!(index, 0);
                    Ok(first.to_vec())
                },
                candidate,
                "pinvou",
                &[]
            )
            .is_ok()
        );
        assert_eq!(reads, 1);
        let mut total_reads = 0;
        for _ in 0..3 {
            check_transition_denials(
                4,
                |_| {
                    total_reads += 1;
                    Ok(first.to_vec())
                },
                candidate,
                "pinvou",
                &[],
            )
            .unwrap();
        }
        assert_eq!(total_reads, 12);
        let signer =
            serde_json::from_slice::<serde_json::Value>(first).unwrap()["signatures"][0]["keyId"]
                .as_str()
                .unwrap()
                .to_owned();
        assert_eq!(
            check_transition_denials(1, |_| Ok(first.to_vec()), candidate, "pinvou", &[signer]),
            Err(Error::SourceUnavailable)
        );
        assert_eq!(
            check_transition_denials(1, |_| Err(Error::Unavailable), candidate, "pinvou", &[]),
            Err(Error::Unavailable)
        );
    }
    #[test]
    #[allow(unsafe_code)]
    fn scratch_transaction_allows_separate_sibling_transaction_and_rolls_back() {
        use windows_sys::Win32::Storage::FileSystem::RollbackTransaction;
        let path = wide(&format!(
            "Software\\PinvouRootScratchTest-{}",
            std::process::id()
        ));
        struct Cleanup(Vec<u16>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unsafe {
                    RegDeleteTreeW(HKEY_CURRENT_USER, self.0.as_ptr());
                }
            }
        }
        let mut root = ptr::null_mut();
        let mut disposition = 0;
        assert_eq!(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    ptr::null(),
                    &mut root,
                    &mut disposition,
                )
            },
            0
        );
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        let cleanup = Cleanup(path.clone());
        let root = Key(root);
        let scratch = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let final_tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let mut first = ptr::null_mut();
        let mut second = ptr::null_mut();
        assert_eq!(
            unsafe {
                RegCreateKeyTransactedW(
                    root.0,
                    wide("scratch").as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    ptr::null(),
                    &mut first,
                    &mut disposition,
                    scratch.raw(),
                    ptr::null(),
                )
            },
            0
        );
        let first = Key(first);
        assert_eq!(
            unsafe {
                RegSetValueExW(
                    first.0,
                    wide("Record").as_ptr(),
                    0,
                    REG_BINARY,
                    [7u8].as_ptr(),
                    1,
                )
            },
            0
        );
        let mut final_parent = ptr::null_mut();
        let parent_open = unsafe {
            RegOpenKeyTransactedW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_READ | KEY_WRITE,
                &mut final_parent,
                final_tx.raw(),
                ptr::null(),
            )
        };
        let parent_write = if parent_open == 0 {
            let key = Key(final_parent);
            unsafe {
                RegSetValueExW(
                    key.0,
                    wide("Head").as_ptr(),
                    0,
                    REG_BINARY,
                    [1u8].as_ptr(),
                    1,
                )
            }
        } else {
            parent_open
        };
        let result = unsafe {
            RegCreateKeyTransactedW(
                root.0,
                wide("published").as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                ptr::null(),
                &mut second,
                &mut disposition,
                final_tx.raw(),
                ptr::null(),
            )
        };
        let scratch_value = read(&first, "Record");
        if !second.is_null() {
            drop(Key(second));
        }
        drop(first);
        assert_ne!(unsafe { RollbackTransaction(final_tx.raw()) }, 0);
        assert_ne!(unsafe { RollbackTransaction(scratch.raw()) }, 0);
        drop(final_tx);
        drop(scratch);
        for name in ["scratch", "published"] {
            let mut observed = ptr::null_mut();
            let status =
                unsafe { RegOpenKeyExW(root.0, wide(name).as_ptr(), 0, KEY_READ, &mut observed) };
            if !observed.is_null() {
                drop(Key(observed));
            }
            assert_eq!(status, ERROR_FILE_NOT_FOUND);
        }
        let implicit = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let mut transient = ptr::null_mut();
        assert_eq!(
            unsafe {
                RegCreateKeyTransactedW(
                    root.0,
                    wide("implicit").as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    ptr::null(),
                    &mut transient,
                    &mut disposition,
                    implicit.raw(),
                    ptr::null(),
                )
            },
            0
        );
        drop(Key(transient));
        drop(implicit);
        let mut observed = ptr::null_mut();
        let implicit_status = unsafe {
            RegOpenKeyExW(
                root.0,
                wide("implicit").as_ptr(),
                0,
                KEY_READ,
                &mut observed,
            )
        };
        if !observed.is_null() {
            drop(Key(observed));
        }
        assert_eq!(implicit_status, ERROR_FILE_NOT_FOUND);
        drop(root);
        assert_eq!(
            unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) },
            0
        );
        drop(cleanup);
        assert_eq!(
            parent_write, 0,
            "final transaction must be able to update the parent"
        );
        assert_eq!(
            result, 0,
            "separate final transaction must not conflict with scratch sibling"
        );
        assert_eq!(scratch_value.unwrap(), vec![7]);
    }
    #[test]
    fn advanced_member_cannot_authorize_from_genesis_only_product_head() {
        assert!(require_genesis_roots(&[]).is_ok());
        assert_eq!(
            require_genesis_roots(&["previously accepted successor".into()]),
            Err(Error::SourceUnavailable)
        );
    }
    #[test]
    fn temporary_guard_allows_unchanged_roots_but_refuses_any_change() {
        let roots = vec!["already stored".into()];
        assert!(require_product_root_ready(&[], &[]).is_ok());
        assert!(require_product_root_ready(&roots, &roots).is_ok());
        assert_eq!(
            require_product_root_ready(&[], &roots),
            Err(Error::SourceUnavailable)
        );
        assert_eq!(
            require_product_root_ready(&roots, &[]),
            Err(Error::SourceUnavailable)
        );
    }
    #[test]
    fn metadata_damage_is_not_a_time_policy_incident() {
        assert_eq!(
            metadata_root_transition_error(Error::StateCorrupt),
            Error::RepairRequired
        );
        assert_eq!(
            metadata_root_transition_error(Error::ScopeConflict),
            Error::ScopeConflict
        );
        assert_eq!(
            metadata_root_transition_error(Error::StateCommitUnknown),
            Error::StateCommitUnknown
        );
    }
    #[test]
    #[allow(unsafe_code)]
    fn actual_initial_policy_is_written_once_and_missing_reads_never_heal() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        struct OwnedTestKey {
            key: Option<Key>,
            path: Vec<u16>,
        }
        impl Drop for OwnedTestKey {
            fn drop(&mut self) {
                drop(self.key.take());
                if !self.path.is_empty() {
                    unsafe {
                        RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr());
                    }
                }
            }
        }
        impl OwnedTestKey {
            fn finish(mut self) {
                drop(self.key.take());
                assert_eq!(
                    unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, self.path.as_ptr()) },
                    0
                );
                self.path.clear();
            }
        }
        let path = wide(&format!(
            "Software\\PinvouInitialTimePolicyTest-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut handle = ptr::null_mut();
        let mut disposition = 0;
        assert_eq!(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ | KEY_WRITE,
                    ptr::null(),
                    &mut handle,
                    &mut disposition,
                )
            },
            0
        );
        let key = Key(handle);
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        let owned = OwnedTestKey {
            key: Some(key),
            path,
        };
        let key = owned.key.as_ref().unwrap();
        let binding = Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-nsis-perMachine".into(),
            profile_kind: "production".into(),
            profile_id: "host".into(),
            genesis_seed_sha256: "a".repeat(64),
            genesis_manifest_sha256: "b".repeat(64),
            original_install_operation_id: "original".into(),
        };
        assert!(matches!(
            policy_in(key, &binding),
            Err(Error::PrerequisiteUnavailable)
        ));
        initialize_policy_in(key, &binding).unwrap();
        let first = policy_in(key, &binding).unwrap();
        assert_eq!(first.policy.max_round_trip_ms, 30_000);
        assert_eq!(first.policy.max_uncertainty_ms, 1_000);
        assert_eq!(
            initialize_policy_in(key, &binding),
            Err(Error::StateCorrupt)
        );
        assert_eq!(policy_in(key, &binding).unwrap().raw, first.raw);
        let mut other = binding.clone();
        other.original_install_operation_id = "other".into();
        assert!(matches!(policy_in(key, &other), Err(Error::StateCorrupt)));
        let mut administrative = first.policy;
        administrative.max_round_trip_ms = 15_000;
        let changed = json::encode(&administrative, false).unwrap();
        write(key, "Policy", &changed).unwrap();
        assert_eq!(
            initialize_policy_in(key, &binding),
            Err(Error::StateCorrupt)
        );
        assert_eq!(policy_in(key, &binding).unwrap().raw, changed);
        assert_eq!(
            verify_initial_policy_in(key, &binding),
            Err(Error::StateCorrupt)
        );
        assert_eq!(
            unsafe { RegDeleteValueW(key.0, wide("Policy").as_ptr()) },
            0
        );
        assert!(matches!(
            policy_in(key, &binding),
            Err(Error::PrerequisiteUnavailable)
        ));
        require_absent_value(key, "Policy").unwrap();
        owned.finish();
    }

    #[test]
    fn detached_root_descriptors_do_not_json_expand_a_maximum_metadata_original() {
        // Byte-capacity/descriptor DATA control only, not a valid Root or SCM source.
        let raw = vec![b'"'; json::RECORD_MAX];
        let blob = Blob::of(&raw);
        root_capacity(&[blob.clone()]).unwrap();
        let encoded = json::encode(&blob, false).unwrap();
        assert!(encoded.len() < 128);
        assert_eq!(blob.size, json::RECORD_MAX);
        assert_eq!(blob.sha256, json::sha256(&raw));
        assert!(root_capacity(&[blob, Blob::of(b"x")]).is_err());
        assert!(
            root_capacity(&[Blob {
                size: 0,
                sha256: "a".repeat(64)
            }])
            .is_err()
        );
    }
    #[test]
    fn private_head_is_closed_and_requires_original_evidence_identities() {
        let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../../../specs/upgrade/v1/vectors/time/anchor.json"
        )))
        .unwrap();
        let original = vectors["cases"][0]["trustedRootBytes"]
            .as_str()
            .unwrap()
            .as_bytes();
        let binding = Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-nsis-perMachine".into(),
            profile_kind: "production".into(),
            profile_id: "host".into(),
            genesis_seed_sha256: "a".repeat(64),
            genesis_manifest_sha256: "b".repeat(64),
            original_install_operation_id: "original".into(),
        };
        let state = State::genesis(binding, original).unwrap();
        let raw = json::encode(&header(&state), false).unwrap();
        let h: Header = json::decode(&raw, false).unwrap();
        assert!(h.cleanup_pending && h.floor.is_none());
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&raw)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("zeroRetention")
        );
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value["cleanupComplete"] = serde_json::Value::Bool(true);
        assert!(json::decode::<Header>(&json::encode(&value, false).unwrap(), false).is_err());
        value.as_object_mut().unwrap().remove("cleanupComplete");
        value.as_object_mut().unwrap().remove("roots");
        assert!(json::decode::<Header>(&json::encode(&value, false).unwrap(), false).is_err());
    }
}

#[cfg(test)]
mod retained_completion_census_tests {
    use super::*;
    fn fixture() -> (Binding, Vec<Vec<u8>>) {
        // Closed Header/linked-byte DATA controls only. These deliberately do
        // not construct a valid native SCM source, time result or clean permit.
        let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../../../specs/upgrade/v1/vectors/time/anchor.json"
        )))
        .unwrap();
        let root = vectors["cases"][0]["trustedRootBytes"]
            .as_str()
            .unwrap()
            .as_bytes();
        let binding = Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-nsis-perMachine".into(),
            profile_kind: "production".into(),
            profile_id: "host".into(),
            genesis_seed_sha256: "a".repeat(64),
            genesis_manifest_sha256: "b".repeat(64),
            original_install_operation_id: "original".into(),
        };
        let mut rows: Vec<Vec<u8>> = Vec::new();
        for revision in 1..=8 {
            let mut row = header(&State::genesis(binding.clone(), root).unwrap());
            row.revision = revision;
            row.previous_sha256 = rows.last().map(|raw| json::sha256(raw));
            if revision == 3 || revision == 6 {
                row.status = Status::CleanupVerifiedZero;
                row.cleanup_pending = false;
                row.zero_retention = Some(crate::retention_custody::ZeroRetentionReference {
                    completion_revision: revision,
                    completion_sha256: format!("{revision:x}").repeat(64),
                });
            } else if revision == 2 || revision == 5 || revision == 8 {
                row.status = Status::CleanupPending;
            }
            rows.push(json::encode(&row, false).unwrap());
        }
        (binding, rows)
    }
    #[test]
    fn historical_sample_recomputes_from_signed_anchor_and_rejects_changes() {
        use crate::{
            identity::{FileTime, ProcessSelector},
            monotonic::CounterObservation,
        };
        let (binding, _) = fixture();
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/product-root-history.json"
        )))
        .unwrap();
        let batch = &fixture["batches"][0];
        let original = fixture["original"].as_str().unwrap().as_bytes();
        let sent = CounterEvidence::from_data(
            CounterObservation::from_bracket(10_000_000, 9_000_000, 9_000_000, 10_000_000).unwrap(),
        );
        let received = CounterEvidence::from_data(
            CounterObservation::from_bracket(10_200_000, 9_200_000, 9_200_000, 10_200_000).unwrap(),
        );
        let incarnation = Incarnation {
            host_epoch: 1,
            instance_nonce: "c".repeat(64),
            process: ProcessSelector {
                process_id: 3,
                creation_file_time: FileTime::from_native(1, 2),
            },
        };
        let evidence = Evidence {
            incarnation: incarnation.clone(),
            request: serde_json::to_string(&batch["request"]).unwrap(),
            response: batch["response"].as_str().unwrap().into(),
            sent,
            received: received.clone(),
            policy: String::from_utf8(
                json::encode(&Policy::initial(binding.clone()).unwrap(), false).unwrap(),
            )
            .unwrap(),
            floor_before: 0,
            base_root_count: 0,
            denied_key_ids: Vec::new(),
            earliest: batch["earliest"].as_u64().unwrap(),
            latest: batch["latest"].as_u64().unwrap(),
        };
        let mut state = State::genesis(binding, original).unwrap();
        state.revision = 3;
        state.previous_sha256 = Some("a".repeat(64));
        state.incarnation = Some(incarnation.clone());
        state.status = Status::CleanupPending;
        state.floor = Some(evidence.earliest);
        state.roots = batch["successors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        state.evidence = Some(evidence);
        state.validate(original).unwrap();
        let root = state.current_root(original);
        let mut sample = HistoricalSample {
            revision: state.revision,
            head_sha256: json::sha256(&json::encode(&header(&state), false).unwrap()),
            incarnation,
            counters: received,
            earliest: state.evidence.as_ref().unwrap().earliest,
            latest: state.evidence.as_ref().unwrap().latest,
        };
        let encoded = json::encode(&sample, false).unwrap();
        let parsed = HistoricalSample::parse(&encoded).unwrap();
        assert!(verify_historical_sample(&state, root, &parsed).is_ok());
        let mut padded = encoded.clone();
        padded.push(b' ');
        assert!(HistoricalSample::parse(&padded).is_err());
        let mut extra: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        extra["unboundSource"] = true.into();
        assert!(HistoricalSample::parse(&json::encode(&extra, false).unwrap()).is_err());
        assert!(verify_historical_sample(&state, root, &sample).is_ok());
        sample.counters = CounterEvidence::from_data(
            CounterObservation::from_bracket(10_300_000, 9_300_000, 9_300_000, 10_300_000).unwrap(),
        );
        sample.earliest += 10;
        sample.latest += 10;
        assert!(verify_historical_sample(&state, root, &sample).is_ok());
        sample.counters = CounterEvidence::from_data(
            CounterObservation::from_bracket(10_100_000, 9_100_000, 9_100_000, 10_100_000).unwrap(),
        );
        assert!(verify_historical_sample(&state, root, &sample).is_err());
        sample.counters = CounterEvidence::from_data(
            CounterObservation::from_bracket(10_300_000, 9_300_000, 9_300_000, 10_300_000).unwrap(),
        );
        sample.latest += 1;
        assert!(verify_historical_sample(&state, root, &sample).is_err());
        sample.latest -= 1;
        sample.incarnation.host_epoch += 1;
        assert!(verify_historical_sample(&state, root, &sample).is_err());
        sample.incarnation.host_epoch -= 1;
        sample.head_sha256 = "f".repeat(64);
        assert!(verify_historical_sample(&state, root, &sample).is_err());
    }
    #[test]
    fn invalid_historical_time_signature_reaches_cryptographic_verification() {
        use pinvou_upgrade_codec::{Document, InputKind};
        use pinvou_upgrade_verifier::{
            SuppliedTimeObservation, TimeVerificationError, VerificationError,
            verify_time_response_source,
        };
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/product-root-history.json"
        )))
        .unwrap();
        let batch = &fixture["batches"][0];
        let request_bytes = serde_json::to_vec(&batch["request"]).unwrap();
        let request = Document::parse(&request_bytes, InputKind::Credential)
            .unwrap()
            .time_request_shape()
            .unwrap();
        let roots = batch["successors"].as_array().unwrap();
        let original = fixture["original"].as_str().unwrap().as_bytes();
        let observation = SuppliedTimeObservation {
            sent_monotonic_millis: 1000,
            received_monotonic_millis: 1020,
            max_round_trip_millis: 30_000,
            max_uncertainty_millis: 1_000,
            trusted_time_floor_millis: 0,
        };
        let verify = |response: &[u8]| {
            verify_time_response_source(
                response,
                original,
                roots.len(),
                |i| {
                    Ok(std::borrow::Cow::Borrowed(
                        roots[i].as_str().unwrap().as_bytes(),
                    ))
                },
                &request,
                observation,
                &[],
            )
        };
        let valid = batch["response"].as_str().unwrap();
        assert!(verify(valid.as_bytes()).is_ok());
        let mut invalid: serde_json::Value = serde_json::from_str(valid).unwrap();
        let sig = invalid["signatures"][0]["signature"].as_str().unwrap();
        let replacement = format!(
            "{}{}",
            if sig.starts_with('A') { 'B' } else { 'A' },
            &sig[1..]
        );
        invalid["signatures"][0]["signature"] = replacement.into();
        let bytes = json::encode(&invalid, false).unwrap();
        assert!(matches!(
            verify(&bytes),
            Err(TimeVerificationError::Verification(
                VerificationError::InvalidSignature
            ))
        ));
    }
    #[test]
    fn historical_headers_require_complete_ordered_ancestry() {
        let (binding, rows) = fixture();
        let mut chain = HistoricalHeaders::new(&binding, &rows[0], &rows[7]).unwrap();
        for raw in &rows {
            chain.observe(raw).unwrap();
        }
        chain.finish().unwrap();

        let mut missing = HistoricalHeaders::new(&binding, &rows[0], &rows[7]).unwrap();
        missing.observe(&rows[0]).unwrap();
        assert!(missing.observe(&rows[2]).is_err());
        let mut short = HistoricalHeaders::new(&binding, &rows[0], &rows[7]).unwrap();
        for raw in &rows[..7] {
            short.observe(raw).unwrap();
        }
        assert!(short.finish().is_err());
        let mut altered: Header = json::decode(&rows[2], false).unwrap();
        altered.previous_sha256 = Some("f".repeat(64));
        let mut wrong = HistoricalHeaders::new(&binding, &rows[0], &rows[7]).unwrap();
        wrong.observe(&rows[0]).unwrap();
        wrong.observe(&rows[1]).unwrap();
        assert!(
            wrong
                .observe(&json::encode(&altered, false).unwrap())
                .is_err()
        );
        let mut wrong_head: Header = json::decode(&rows[7], false).unwrap();
        wrong_head.floor = Some(1);
        let bad = json::encode(&wrong_head, false).unwrap();
        let mut mismatch = HistoricalHeaders::new(&binding, &rows[0], &bad).unwrap();
        for raw in &rows {
            mismatch.observe(raw).unwrap();
        }
        assert!(mismatch.finish().is_err());
    }
    #[test]
    fn older_completion_loss_is_detected_after_unknown_and_a_new_anchor() {
        let (binding, rows) = fixture();
        let mut census = RetainedCompletionCensus::new(&rows[7], &rows[0], &binding).unwrap();
        for (index, raw) in rows.iter().enumerate() {
            census
                .observe(&revision_name(index as u64 + 1), raw)
                .unwrap();
        }
        let all = census.finish().unwrap();
        assert_eq!(
            all.iter()
                .map(|r| r.completion_revision)
                .collect::<Vec<_>>(),
            [3, 6]
        );
        retention::exact_completion_references(&all, &all).unwrap();
        // Both references are older than current/previous. Losing revision 3
        // must fail even though revision 6 and the current anchor remain.
        assert!(retention::exact_completion_references(&all, &all[1..]).is_err());
        let mut wrong = all.clone();
        wrong[0].completion_sha256 = "f".repeat(64);
        assert!(retention::exact_completion_references(&all, &wrong).is_err());
        assert!(
            retention::exact_completion_references(&all, &[all[0].clone(), all[0].clone()])
                .is_err()
        );
        let mut hole = RetainedCompletionCensus::new(&rows[7], &rows[0], &binding).unwrap();
        hole.observe(&revision_name(1), &rows[0]).unwrap();
        assert!(hole.observe(&revision_name(3), &rows[2]).is_err());
        let mut short = RetainedCompletionCensus::new(&rows[7], &rows[0], &binding).unwrap();
        short.observe(&revision_name(1), &rows[0]).unwrap();
        assert!(short.finish().is_err());
        let mut tampered = RetainedCompletionCensus::new(&rows[7], &rows[0], &binding).unwrap();
        let mut bad: Header = json::decode(&rows[0], false).unwrap();
        bad.binding.original_install_operation_id = "another".into();
        assert!(
            tampered
                .observe(&revision_name(1), &json::encode(&bad, false).unwrap())
                .is_err()
        );
    }
    #[test]
    fn a_census_capacity_overflow_or_mismatched_head_never_becomes_an_empty_result() {
        let (binding, rows) = fixture();
        let mut huge: Header = json::decode(&rows[7], false).unwrap();
        huge.revision = u64::from(MAX_CENSUS_TIME_HEADERS) + 1;
        assert!(matches!(
            RetainedCompletionCensus::new(&json::encode(&huge, false).unwrap(), &rows[0], &binding),
            Err(Error::Unavailable)
        ));
        let mut wrong_head: Header = json::decode(&rows[7], false).unwrap();
        wrong_head.floor = Some(1);
        let mut census = RetainedCompletionCensus::new(
            &json::encode(&wrong_head, false).unwrap(),
            &rows[0],
            &binding,
        )
        .unwrap();
        for (index, raw) in rows.iter().enumerate() {
            census
                .observe(&revision_name(index as u64 + 1), raw)
                .unwrap();
        }
        assert!(census.finish().is_err());
    }
}
