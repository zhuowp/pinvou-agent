//! Atomic historical checked-observation receipts, never current eligibility.
//! Native counters describe their sampling instant, not physical COMMIT time.
use super::*;
use crate::platform::windows::installed::StartedServiceContext;
use crate::trusted_time::UtcInterval;
use pinvou_upgrade_metadata_owner::{DecisionError, DecisionInputs, decide_public_metadata_source};
use serde::{Deserialize, Serialize};
use std::cell::Cell;

mod staging;
use staging::Staged;

#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) fn component_test_staging_in(
    private: &Key,
    tx: &Handle,
    partial: bool,
) -> Result<()> {
    staging::component_test_in(private, tx, partial)
}

#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) fn component_test_no_staging(
    private: &Key,
) -> Result<()> {
    staging::component_test_no_staging(private)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    state_version: u8,
    revision: u64,
    previous_sha256: String,
    active: waterlog::publication::Position,
}

fn successor(previous: &[u8], active: waterlog::publication::Position) -> Result<Vec<u8>> {
    let revision = active
        .index
        .checked_add(1)
        .filter(|v| *v <= json::SAFE_MAX)
        .ok_or(Error::Unavailable)?;
    json::encode(
        &Record {
            state_version: 1,
            revision,
            previous_sha256: json::sha256(previous),
            active,
        },
        false,
    )
}

fn require_record(
    raw: &[u8],
    previous: &[u8],
    position: waterlog::publication::Position,
) -> Result<()> {
    let parsed: Record = json::decode(raw, false)?;
    if parsed.state_version != 1
        || json::encode(&parsed, false)? != raw
        || successor(previous, position)? != raw
    {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

/// Strict existing layout reader. Full signatures, historical time and prior
/// waters are checked separately by replay from the same native read set.
fn check_existing_in(
    private: &Key,
    seed: &Seed,
    host: &HostRegistration,
    tx: &Handle,
) -> Result<Vec<u8>> {
    if !crate::bootstrap::initialized(&host.known_owner_namespaces) {
        return Err(Error::SetupIncomplete);
    }
    let initial = genesis(
        OwnerBootstrap::new(seed, &host.installation_scope_id)?
            .metadata
            .record_bytes(),
    )?;
    check_bound_history_in(private, &initial, &Binding::from_host(host), tx)
}

/// Layout DATA for an independently authenticated native owner binding and
/// bootstrap genesis. This is shared with the catalog-member reader; signature,
/// time and water replay must still complete before using its observation.
pub(super) fn check_bound_history_in(
    private: &Key,
    initial: &[u8],
    binding: &Binding,
    tx: &Handle,
) -> Result<Vec<u8>> {
    let metadata = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    exact_names(&names(&metadata, true, 3)?, &["Genesis", "Head", "Policy"])?;
    exact_names(&names(&metadata, false, 2)?, &["history", "waterlog"])?;
    if read(&metadata, "Genesis")? != initial {
        return Err(Error::StateCorrupt);
    }
    policy::read_in(&metadata, binding)?;
    let history = open(metadata.0, "history", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let first = open(history.0, &revision_name(1), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    waterlog::exact_counts(&first, 1, 0)?;
    if read(&first, "Record")? != initial {
        return Err(Error::StateCorrupt);
    }
    let mut previous = initial.to_vec();
    let mut count = 1u64;
    waterlog::visit_structure_in(&metadata, &initial, tx, |batch| {
        count = count.checked_add(1).ok_or(Error::Unavailable)?;
        let row =
            open(history.0, &revision_name(count), false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        waterlog::exact_counts(&row, 1, 0)?;
        let raw = read(&row, "Record")?;
        require_record(&raw, &previous, batch.position(&initial)?)?;
        previous = raw;
        Ok(())
    })?;
    waterlog::exact_counts(&history, 0, count)?;
    if read(&metadata, "Head")? != previous {
        return Err(Error::StateCorrupt);
    }
    Ok(previous)
}

/// Retained prefix layout DATA only. The caller must authenticate both supplied
/// Heads and the captured policy separately; today's Policy is only checked as
/// part of today's native layout and never substitutes for a captured policy.
pub(super) fn check_bound_history_prefix_in(
    private: &Key,
    initial: &[u8],
    binding: &Binding,
    tx: &Handle,
    expected_metadata_head: &[u8],
    expected_waterlog_head: &[u8],
) -> Result<()> {
    let current_head = check_bound_history_in(private, initial, binding, tx)?;
    let metadata = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let current_policy = policy::read_in(&metadata, binding)?.1;
    let current_waterlog_head = waterlog::head_bytes_in(&metadata, initial, tx)?;
    let history = open(metadata.0, "history", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let mut previous = initial.to_vec();
    let mut revision = 1u64;
    waterlog::visit_structure_prefix_in(&metadata, initial, tx, expected_waterlog_head, |batch| {
        revision = revision.checked_add(1).ok_or(Error::Unavailable)?;
        let row = open(history.0, &revision_name(revision), false, Some(tx))?
            .ok_or(Error::StateCorrupt)?;
        waterlog::exact_counts(&row, 1, 0)?;
        let raw = read(&row, "Record")?;
        require_record(&raw, &previous, batch.position(initial)?)?;
        previous = raw;
        Ok(())
    })?;
    if previous != expected_metadata_head {
        return Err(Error::StateCorrupt);
    }
    if check_bound_history_in(private, initial, binding, tx)? != current_head
        || waterlog::head_bytes_in(&metadata, initial, tx)? != current_waterlog_head
        || policy::read_in(&metadata, binding)?.1 != current_policy
    {
        return Err(Error::ScopeConflict);
    }
    Ok(())
}

/// Historical DATA only. The host borrow prevents a receipt from being moved
/// into an unrelated service lifetime; it is not a permission capability.
pub(in crate::platform::windows) struct Receipt<'host> {
    _host: PhantomData<&'host StartedServiceContext>,
    revision: u64,
    head_sha256: String,
    sampled: UtcInterval,
}
impl Receipt<'_> {
    pub(in crate::platform::windows) fn revision(&self) -> u64 {
        self.revision
    }
    pub(in crate::platform::windows) fn head_sha256(&self) -> &str {
        &self.head_sha256
    }
    /// Recorded bounds at the actual observation, never the current time.
    pub(in crate::platform::windows) fn sampled_interval(&self) -> UtcInterval {
        self.sampled
    }
}

fn expiry(raw: &[u8]) -> Result<Option<u64>> {
    let envelope = pinvou_upgrade_codec::decode_canonical_envelope(
        raw,
        pinvou_upgrade_codec::InputKind::Metadata,
    )
    .map_err(|_| Error::StateCorrupt)?
    .check_full_schema()
    .map_err(|_| Error::StateCorrupt)?;
    let signed = envelope.envelope().signed().value();
    if signed["role"] == "package" {
        return Ok(None);
    }
    signed["expiresAt"]
        // Codec Documents normalize all protocol numbers to binary64. A
        // schema-checked integer is therefore not a serde_json N::PosInt.
        .as_f64()
        .filter(|v| v.is_finite() && v.fract() == 0.0 && *v >= 0.0 && *v <= json::SAFE_MAX as f64)
        .map(|v| Some(v as u64))
        .ok_or(Error::StateCorrupt)
}

fn require_fresh(
    initial: UtcInterval,
    final_sample: UtcInterval,
    minimum_expiry: u64,
) -> Result<()> {
    if final_sample.earliest_millis() < initial.earliest_millis()
        || final_sample.latest_millis() < initial.latest_millis()
        || final_sample.latest_millis() >= minimum_expiry
    {
        return Err(Error::SourceUnavailable);
    }
    Ok(())
}

fn supplied<T>(
    result: Result<T>,
    error: &Cell<Option<Error>>,
) -> std::result::Result<T, DecisionError> {
    result.map_err(|failure| {
        if error.get().is_none() {
            error.set(Some(failure));
        }
        DecisionError::SourceUnavailable
    })
}

impl Store {
    /// Existing-state/restart reader. Missing namespaces are never migrated
    /// or initialized here. An empty validated genesis has no observation.
    #[allow(unsafe_code, dead_code)]
    pub(in crate::platform::windows) fn metadata_receipt<'host>(
        &self,
        host: &'host StartedServiceContext,
    ) -> Result<Option<Receipt<'host>>> {
        let seed = &host.context.seed;
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let product = super::super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual =
            time::read_guarded_in(self, seed, &product, &tx)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let private = self.key(false, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let source = time::current_in(&private, seed, &actual, &product, &tx)?;
        let head = check_existing_in(&private, seed, &actual, &tx)?;
        let replay = replay::replay(&source, host)?;
        let metadata =
            open(private.0, NAMESPACE, false, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        policy::read_in(&metadata, &Binding::from_host(&actual))?
            .0
            .require_retains(replay.required_role_denials())?;
        let mut observation = None;
        source.visit_metadata_time(host, |batch| {
            observation = Some((batch.index() + 1, batch.interval()));
            Ok(())
        })?;
        replay.recheck(host)?;
        if check_existing_in(&private, seed, &actual, &tx)? != head {
            return Err(Error::ScopeConflict);
        }
        Ok(observation.map(|(revision, sampled)| Receipt {
            _host: PhantomData,
            revision,
            head_sha256: json::sha256(&head),
            sampled,
        }))
    }

    /// Publish a complete public graph as historical checked DATA. Input
    /// members are one-based; readers MUST enforce RECORD_MAX before allocating
    /// their return vector. This boundary also rejects oversized returned data.
    /// No supplied Root, time, policy, sample or prior record is accepted.
    /// CleanupPending is preserved: passive storage grants no upgrade action.
    #[allow(unsafe_code, dead_code)]
    pub(in crate::platform::windows) fn publish_metadata<'host>(
        &self,
        host: &'host StartedServiceContext,
        timestamp: &[u8],
        snapshot: &[u8],
        member_count: u32,
        read_member: impl FnMut(u32) -> Result<Vec<u8>>,
    ) -> Result<Receipt<'host>> {
        let seed = &host.context.seed;
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let product = super::super::product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual =
            time::read_guarded_in(self, seed, &product, &tx)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&actual)?;
        let expected_host = actual.digest()?;
        let private = self.key(true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let source = time::current_in(&private, seed, &actual, &product, &tx)?;
        let old_head = check_existing_in(&private, seed, &actual, &tx)?;
        let prefix = replay::replay(&source, host)?;
        prefix.require_source(&source)?;
        let metadata =
            open(private.0, NAMESPACE, true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
        let (roles, role_raw) = policy::read_in(&metadata, &Binding::from_host(&actual))?;
        roles.require_retains(prefix.required_role_denials())?;
        let initial = time::HistoricalSample::capture(host, &source)?;
        let stage = Staged::create_in(
            &private,
            &tx,
            timestamp,
            snapshot,
            member_count,
            read_member,
        )?;
        let selected_root = replay_index::root(source.current_root())?;
        let context = replay_index::document(&json::encode(
            &serde_json::json!({"product":actual.product,"component":actual.component}),
            false,
        )?)?;
        let bounds = initial.bounds();
        let earliest = replay_index::document(bounds.earliest_millis().to_string().as_bytes())?
            .protocol_time_shape()
            .map_err(|_| Error::StateCorrupt)?;
        let latest = replay_index::document(bounds.latest_millis().to_string().as_bytes())?
            .protocol_time_shape()
            .map_err(|_| Error::StateCorrupt)?;
        let timestamp = stage.timestamp()?;
        let snapshot = stage.snapshot()?;
        let role_denied = roles.by_role();
        let error = Cell::new(None);
        let decision = decide_public_metadata_source(
            &timestamp,
            &snapshot,
            member_count as usize,
            |i| {
                supplied(
                    stage.member(
                        u32::try_from(i)
                            .map_err(|_| DecisionError::SourceUnavailable)?
                            .checked_add(1)
                            .ok_or(DecisionError::SourceUnavailable)?,
                    ),
                    &error,
                )
            },
            DecisionInputs {
                root: &selected_root,
                context: &context,
                earliest: &earliest,
                latest: &latest,
                denied: &source.state().denied_key_ids,
                denied_by_role: &role_denied,
            },
            |context| supplied(prefix.prior(host, context), &error),
        );
        if let Some(error) = error.get() {
            return Err(error);
        }
        let _decision = decision.map_err(|_| Error::StateCorrupt)?;
        // The full journal is the water authority; replay reconstructs all
        // proposed waters from these exact originals, never a second ledger.
        let mut minimum_expiry = expiry(source.current_root())?.ok_or(Error::StateCorrupt)?;
        for raw in [&timestamp, &snapshot] {
            minimum_expiry = minimum_expiry.min(expiry(raw)?.ok_or(Error::StateCorrupt)?);
        }
        for i in 1..=member_count {
            if let Some(end) = expiry(&stage.member(i)?)? {
                minimum_expiry = minimum_expiry.min(end);
            }
        }
        stage.recheck()?;
        prefix.recheck(host)?;
        if check_existing_in(&private, seed, &actual, &tx)? != old_head
            || policy::read_in(&metadata, &Binding::from_host(&actual))?.1 != role_raw
        {
            return Err(Error::ScopeConflict);
        }
        source.recheck(host)?;
        // No further external callbacks or prior queries after this point.
        let initial_genesis = genesis(
            OwnerBootstrap::new(seed, &actual.installation_scope_id)?
                .metadata
                .record_bytes(),
        )?;
        let pending = waterlog::publication::copy_in(
            &metadata,
            &initial_genesis,
            &tx,
            &timestamp,
            &snapshot,
            member_count,
            |i| stage.member(i),
        )?;
        pending.recheck_originals()?;
        stage.remove(&private, &tx)?;
        if policy::read_in(&metadata, &Binding::from_host(&actual))?.1 != role_raw {
            return Err(Error::ScopeConflict);
        }
        source.recheck(host)?;
        let final_sample = initial.refresh(host)?;
        require_fresh(initial.bounds(), final_sample.bounds(), minimum_expiry)?;
        budgets::retain_samples_floor_in(
            &private,
            &actual,
            &tx,
            &source,
            initial.live_for(&source)?,
            Some(final_sample.live_for(&source)?),
        )?;
        let position = pending.finish(
            &private,
            host,
            &source,
            &final_sample,
            &source.policy().raw,
            &role_raw,
        )?;
        let revision = position.index + 1;
        let head = successor(&old_head, position)?;
        let history = open(metadata.0, "history", true, Some(&tx))?.ok_or(Error::StateCorrupt)?;
        let row = create(history.0, &revision_name(revision), &tx, false, true)?;
        write(&row, "Record", &head)?;
        write(&metadata, "Head", &head)?;
        // All original/prefix verification precedes the final observation.
        // Only fixed local finalization follows it; full committed traversal
        // is done after COMMIT without claiming those old bounds are current.
        if read(&metadata, "Head")? != head || read(&row, "Record")? != head {
            return Err(Error::ScopeConflict);
        }
        source.recheck(host)?;
        let budget_key =
            open(private.0, budgets::NAMESPACE, false, Some(&tx))?.ok_or(Error::StateCorrupt)?;
        let budget_head = read(&budget_key, "Head")?;
        let sampled = final_sample.bounds();
        drop(final_sample);
        drop(initial);
        drop(prefix);
        drop(source);
        drop(row);
        drop(history);
        drop(metadata);
        drop(budget_key);
        drop(private);
        crate::platform::windows::time_cancel::check()?;
        if unsafe { CommitTransaction(tx.raw()) } == 0 {
            return Err(Error::StateCommitUnknown);
        }
        drop(tx);
        // Every failure after native COMMIT is ambiguous. Guards remain held
        // until exact committed readback and complete historical replay finish.
        self.readback_metadata(host, &product, &expected_host, &head, &budget_head)
            .map_err(|_| Error::StateCommitUnknown)?;
        Ok(Receipt {
            _host: PhantomData,
            revision,
            head_sha256: json::sha256(&head),
            sampled,
        })
    }

    #[allow(unsafe_code)]
    fn readback_metadata(
        &self,
        host: &StartedServiceContext,
        product: &super::super::product_catalog::ProductGuard,
        expected_host: &str,
        head: &[u8],
        budget_head: &[u8],
    ) -> Result<()> {
        let seed = &host.context.seed;
        let private = self.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
        let metadata = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
        let history = open(metadata.0, "history", false, None)?.ok_or(Error::StateCommitUnknown)?;
        let journal =
            open(metadata.0, "waterlog", false, None)?.ok_or(Error::StateCommitUnknown)?;
        let entries = open(journal.0, "entries", false, None)?.ok_or(Error::StateCommitUnknown)?;
        let budget =
            open(private.0, budgets::NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
        for key in [&private, &metadata, &history, &journal, &entries, &budget] {
            if unsafe { RegFlushKey(key.0) } != 0 {
                return Err(Error::StateCommitUnknown);
            }
        }
        if read(&metadata, "Head")? != head || read(&budget, "Head")? != budget_head {
            return Err(Error::StateCommitUnknown);
        }
        // Open a fresh native read transaction only after COMMIT and flush.
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let actual =
            time::read_guarded_in(self, seed, product, &tx)?.ok_or(Error::StateCommitUnknown)?;
        host.authenticate_running(&actual)?;
        if actual.digest()? != expected_host {
            return Err(Error::StateCommitUnknown);
        }
        let current = self
            .key(false, Some(&tx))?
            .ok_or(Error::StateCommitUnknown)?;
        let source = time::current_in(&current, seed, &actual, product, &tx)?;
        if check_existing_in(&current, seed, &actual, &tx)? != head {
            return Err(Error::StateCommitUnknown);
        }
        let replay = replay::replay(&source, host)?;
        let metadata =
            open(current.0, NAMESPACE, false, Some(&tx))?.ok_or(Error::StateCommitUnknown)?;
        policy::read_in(&metadata, &Binding::from_host(&actual))?
            .0
            .require_retains(replay.required_role_denials())?;
        replay.recheck(host)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_reads_codec_binary64_from_actual_signed_roots() {
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/product-root-history.json"
        )))
        .unwrap();
        let mut roots = vec![fixture["original"].as_str().unwrap()];
        for batch in fixture["batches"].as_array().unwrap() {
            roots.extend(
                batch["successors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|raw| raw.as_str().unwrap()),
            );
        }
        for raw in roots {
            let wire: serde_json::Value = serde_json::from_str(raw).unwrap();
            let expected = wire["signed"]["expiresAt"].as_u64().unwrap();
            assert_eq!(expiry(raw.as_bytes()), Ok(Some(expected)));
        }
    }

    fn interval(earliest: u64, latest: u64) -> UtcInterval {
        let zero = crate::monotonic::CounterObservation::from_bracket(0, 0, 0, 0).unwrap();
        crate::trusted_time::advance_interval(earliest, latest, zero, zero).unwrap()
    }
    #[test]
    fn final_observation_covers_verification_latency_and_strict_expiry() {
        let initial = interval(10, 20);
        assert_eq!(require_fresh(initial, interval(25, 29), 30), Ok(()));
        assert_eq!(
            require_fresh(initial, interval(25, 30), 30),
            Err(Error::SourceUnavailable)
        );
        assert_eq!(
            require_fresh(initial, interval(31, 32), 30),
            Err(Error::SourceUnavailable)
        );
        assert_eq!(
            require_fresh(initial, interval(9, 25), 30),
            Err(Error::SourceUnavailable)
        );
        assert_eq!(
            require_fresh(initial, interval(10, 19), 30),
            Err(Error::SourceUnavailable)
        );
        assert_eq!(require_fresh(initial, initial, 21), Ok(()));
    }
    fn position() -> waterlog::publication::Position {
        waterlog::publication::Position {
            index: 1,
            record_sha256: "a".repeat(64),
            timestamp_sha256: "b".repeat(64),
            snapshot_sha256: "c".repeat(64),
            member_count: 2,
            member_chain_sha256: "d".repeat(64),
            head_sha256: "e".repeat(64),
        }
    }
    #[test]
    fn successor_binds_exact_prefix_active_graph_and_journal() {
        let raw = successor(b"genesis", position()).unwrap();
        require_record(&raw, b"genesis", position()).unwrap();
        assert!(require_record(&raw, b"other", position()).is_err());
        let mut changed = position();
        changed.snapshot_sha256 = "f".repeat(64);
        assert!(require_record(&raw, b"genesis", changed).is_err());
        let mut changed = position();
        changed.head_sha256 = "f".repeat(64);
        assert!(require_record(&raw, b"genesis", changed).is_err());
        let mut changed = position();
        changed.index = json::SAFE_MAX;
        assert!(successor(b"genesis", changed).is_err());
    }
    #[test]
    fn source_errors_cannot_become_absent_priors() {
        let error = Cell::new(None);
        assert!(supplied::<Option<()>>(Err(Error::Unavailable), &error).is_err());
        assert_eq!(error.get(), Some(Error::Unavailable));
        assert!(supplied::<Option<()>>(Ok(None), &error).unwrap().is_none());
        assert_eq!(error.get(), Some(Error::Unavailable));
    }
}
