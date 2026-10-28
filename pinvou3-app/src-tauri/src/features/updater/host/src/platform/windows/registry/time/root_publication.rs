//! Fixed service-owned V2 Root publication. No caller callbacks, DTO clock or
//! alternate transaction/commit capability escape this operation.
use super::*;
use crate::platform::windows::time_owner::PendingRootTime;

/// Only this publisher constructs the bounded registration view, after complete
/// replay in its held product guard and transaction. Detached registration DATA
/// cannot request a native sample through this capability.
pub(in crate::platform::windows) struct RootPublicationClock<'tx> {
    private: &'tx Key,
    row: Key,
    seed: &'tx Seed,
    guard: &'tx super::super::product_catalog::ProductGuard,
    _transaction: &'tx Handle,
    host: &'tx HostRegistration,
    raw: Vec<u8>,
}

impl<'tx> RootPublicationClock<'tx> {
    fn new(
        private: &'tx Key,
        seed: &'tx Seed,
        guard: &'tx super::super::product_catalog::ProductGuard,
        tx: &'tx Handle,
        host: &'tx HostRegistration,
    ) -> Result<Self> {
        guard.check_seed(seed)?;
        let raw = read(private, "Head")?;
        if raw != json::encode(host, false)? {
            return Err(Error::ScopeConflict);
        }
        let row = open(
            private.0,
            &format!("history\\{}", revision_name(host.revision)),
            false,
            Some(tx),
        )?
        .ok_or(Error::StateCorrupt)?;
        if read(&row, "Record")? != raw {
            return Err(Error::ScopeConflict);
        }
        Ok(Self {
            private,
            row,
            seed,
            guard,
            _transaction: tx,
            host,
            raw,
        })
    }

    /// Bounded native registration pins and actual SCM authentication only.
    /// No Store::read, Root traversal, graph callback or new transaction occurs.
    pub(in crate::platform::windows) fn registration(
        &self,
        service: &StartedServiceContext,
    ) -> Result<&HostRegistration> {
        self.guard.check_seed(self.seed)?;
        inspect_registry(self.private.0, true)?;
        inspect_registry(self.row.0, true)?;
        if read(self.private, "Head")? != self.raw || read(&self.row, "Record")? != self.raw {
            return Err(Error::ScopeConflict);
        }
        service.authenticate_running(self.host)?;
        Ok(self.host)
    }
}

#[allow(unsafe_code)]
pub(super) fn publish(
    store: &Store,
    host: &StartedServiceContext,
    expected: &TimeSnapshot,
    captured: &PolicySnapshot,
    evidence: &Evidence,
    successors: &RootScratch,
    pending: &PendingRootTime<'_, '_>,
) -> Result<TimeSnapshot> {
    if successors.len() == 0 {
        return Err(Error::ScopeConflict);
    }
    super::super::super::time_cancel::check()?;
    let seed = &host.context.seed;
    let _bootstrap = BootstrapGuard::acquire(seed, false)?;
    let guard = super::super::product_catalog::ProductGuard::acquire(seed)?;
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })?;
    let actual = read_guarded_in(store, seed, &guard, &tx)?.ok_or(Error::SetupIncomplete)?;
    host.authenticate_running(&actual)?;
    let private = store.key(true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
    let advanced = root_history::advanced_shape_in(seed, &tx)?;
    let view = if advanced {
        Some(
            root_history::VerifiedHistory::open(seed, &actual, &guard, &tx)
                .map_err(metadata_root_transition_error)?,
        )
    } else {
        None
    };
    let current = match &view {
        Some(view) => state_in_product(&private, &actual, seed, &guard, &tx, view)?,
        None => state_in(&private, &actual, Some(&tx))?,
    };
    let incarnation = Incarnation::from_host(&actual)?;
    if current.raw != expected.raw
        || current.original_root != expected.original_root
        || current.state.incarnation.as_ref() != Some(&incarnation)
        || evidence.incarnation != incarnation
    {
        return Err(Error::ScopeConflict);
    }
    if !advanced && !current.state.roots.is_empty() {
        // Older per-profile Roots provide no complete shared historical V2
        // member witnesses. Preserve them; never manufacture an empty set.
        return Err(Error::SourceUnavailable);
    }
    let position = if advanced {
        Some(root_history::staged_position(
            &root_history::protected_head_in(seed, &tx)?,
        )?)
    } else {
        None
    };
    let base_count = position.as_ref().map_or(0, |position| position.root_count);
    if u64::try_from(evidence.base_root_count).ok() != Some(base_count) {
        return Err(Error::PrerequisiteUnavailable);
    }
    let caught_up = position
        .as_ref()
        .is_some_and(|position| current.state.product_root.as_ref() != Some(position));
    if !caught_up && current.state.status != Status::Unknown {
        return Err(Error::ScopeConflict);
    }
    let time = open(private.0, NAMESPACE, true, Some(&tx))?.ok_or(Error::SetupIncomplete)?;
    if caught_up {
        check_catchup_in(
            &time,
            &current,
            incarnation.clone(),
            position.as_ref().ok_or(Error::StateCorrupt)?,
        )?;
    }
    let policy = policy_in(&time, &current.state.binding)?;
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
    if let Some(view) = &view {
        crate::trusted_time::check_history_time_bound(view.latest_issue(), evidence.earliest)?;
    }
    let base_root = view
        .as_ref()
        .map_or(current.original_root.as_slice(), |view| view.current_root());
    pending.require_context(
        host,
        evidence,
        successors,
        base_root,
        usize::try_from(base_count).map_err(|_| Error::Unavailable)?,
    )?;
    let stage = root_history::StagedV2Batch::prepare(
        seed,
        &actual,
        &guard,
        &tx,
        view.as_ref(),
        evidence,
        successors,
    )
    .map_err(metadata_root_transition_error)?;
    if stage.base_root() != base_root || stage.base_count() != base_count {
        return Err(Error::ScopeConflict);
    }
    let head = stage.head().to_vec();
    let final_root = stage.final_root()?;
    drop(view);
    stage
        .publish_into_product()
        .map_err(metadata_root_transition_error)?;

    // The issuer's pre-state is in the fixed V2 snapshot. Only now bind its
    // successor to the newly computed product Head, avoiding a hash cycle.
    let mut next = current.state.next_unknown(incarnation, &current.raw)?;
    next.status = Status::CleanupPending;
    next.cleanup_pending = true;
    next.zero_retention = None;
    next.floor = Some(evidence.earliest);
    next.denied_key_ids = denied;
    next.evidence = Some(evidence.clone());
    next.product_root = Some(root_history::staged_position(&head)?);
    current
        .state
        .transition_compact_shape(&next, &current.raw)?;
    let history = open(time.0, "history", true, Some(&tx))?.ok_or(Error::StateCorrupt)?;
    let row = create(history.0, &revision_name(next.revision), &tx, false, true)?;
    let raw = write_record(&row, &next)?;
    write(&time, "Head", &raw)?;
    if caught_up && unsafe { RegDeleteValueW(time.0, wide("Catchup").as_ptr()) } != 0 {
        return Err(Error::StateCorrupt);
    }
    stage
        .discard_staging()
        .map_err(metadata_root_transition_error)?;
    let fresh = root_history::VerifiedHistory::open(seed, &actual, &guard, &tx)
        .map_err(metadata_root_transition_error)?;
    if state_in_product(&private, &actual, seed, &guard, &tx, &fresh)?.raw != raw {
        return Err(Error::StateCorrupt);
    }
    fresh
        .prefix()?
        .verify_all_metadata()
        .map_err(metadata_root_transition_error)?;
    root_read_set::census(seed, &actual, &guard, &tx, true)
        .map_err(metadata_root_transition_error)?;
    if policy_in(&time, &current.state.binding)?.raw != captured.raw
        || budgets::floor_in(&private, &actual, Some(&tx))?
            .unwrap_or(0)
            .max(current.state.floor.unwrap_or(0))
            != floor
    {
        return Err(Error::ScopeConflict);
    }
    let retained_floor = budgets::PendingRootFloor::prepare(&private, &actual, &tx)?;
    let clock = RootPublicationClock::new(&private, seed, &guard, &tx, &actual)?;
    host.authenticate_running(&actual)?;
    super::super::super::time_cancel::check()?;
    // No source callbacks or full graph traversal follow this native sample.
    let late = pending.sample_late(host, &clock, &final_root, &head)?;
    let floor_position = retained_floor.retain(host, pending, &late, &head)?;
    host.authenticate_running(&actual)?;
    super::super::super::time_cancel::check()?;
    drop(row);
    drop(history);
    drop(time);
    drop(clock);
    drop(private);
    drop(fresh);
    commit_time_transaction(&tx)?;
    drop(tx);

    let verify = || -> Result<TimeSnapshot> {
        root_history::flush_persisted(seed)?;
        let private = store.key(false, None)?.ok_or(Error::StateCommitUnknown)?;
        let time = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
        let row = open(
            time.0,
            &format!("history\\{}", revision_name(next.revision)),
            false,
            None,
        )?
        .ok_or(Error::StateCommitUnknown)?;
        if unsafe { RegFlushKey(row.0) } != 0 || unsafe { RegFlushKey(time.0) } != 0 {
            return Err(Error::StateCommitUnknown);
        }
        let actual_after = store.read(seed)?.ok_or(Error::StateCommitUnknown)?;
        host.authenticate_running(&actual_after)?;
        floor_position.flush_and_recheck(&private, &actual_after)?;
        let read_set = root_read_set::RootReadSet::new_persisted(host)?;
        read_set.committed_member(&head, &final_root, &raw)
    };
    verify().map_err(|_| Error::StateCommitUnknown)
}
