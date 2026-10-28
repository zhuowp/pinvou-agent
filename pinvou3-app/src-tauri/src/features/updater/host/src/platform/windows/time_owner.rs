//! Actual SCM-bound time acquisition. This batch commits evidence and a cleanup
//! barrier only; it never advertises a durable Known clock or recovery permission.
mod pending_root;
use super::{
    installed::StartedServiceContext,
    original_root::ProtectedOriginalRoot,
    registry::{
        BootstrapGuard, Store,
        product_catalog::ProductGuard,
        time::{PolicySnapshot, RootScratch, TimeSnapshot},
    },
    time_transport::TimeTransport,
};
use crate::{
    error::{Error, Result},
    json,
    trusted_time::{CounterEvidence, Evidence, Incarnation, Status, root_version},
};
pub(super) use pending_root::{LateRootAcceptance, PendingRootTime};
use pinvou_upgrade_codec::{Document, InputKind};
use pinvou_upgrade_control_http::RootGetResult;
use pinvou_upgrade_verifier::{
    SuppliedTimeObservation, TimeVerificationError, verify_time_response_source,
    verify_time_root_successor,
};

pub(super) struct TimeOwner {
    snapshot: TimeSnapshot,
    original: ProtectedOriginalRoot,
    incarnation: Incarnation,
    commit_uncertain: bool,
}
impl TimeOwner {
    /// Recovery, never initialization. A scope predating this owner remains
    /// SetupIncomplete. Even genuine new genesis proves no empty obligations.
    pub(super) fn open(host: &StartedServiceContext) -> Result<Self> {
        let original = host.original_root_source()?;
        let own = &host.context;
        let store = Store::new(&own.seed);
        let before = store.read(&own.seed)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&before)?;
        let mut snapshot = store.time_load(&own.seed, &before)?;
        if snapshot.original_root.as_slice() != original.root_bytes(host)? {
            return Err(Error::StateCorrupt);
        }
        let incarnation = Incarnation::from_host(&before)?;
        if snapshot.state.product_root.is_none()
            && snapshot.state.roots.is_empty()
            && snapshot.state.floor.is_none()
            && snapshot.state.evidence.is_none()
            && let Some(caught_up) = store.time_catchup_new(host, &snapshot)?
        {
            snapshot = caught_up;
        }
        if snapshot.state.incarnation.as_ref() != Some(&incarnation) {
            // Invalidate continuity durably BEFORE any network/policy work.
            // Original floor, Root lineage, evidence and barrier all survive.
            let unknown = snapshot
                .state
                .next_unknown(incarnation.clone(), &snapshot.raw)?;
            snapshot = store.time_commit(host, &snapshot, &unknown, None)?;
        }
        let after = store.read(&own.seed)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&after)?;
        if Incarnation::from_host(&after)? != incarnation {
            return Err(Error::ServiceIdentityRefused);
        }
        Ok(Self {
            snapshot,
            original,
            incarnation,
            commit_uncertain: false,
        })
    }
    /// One explicitly controlled attempt. The startup worker calls this once
    /// then waits for stop; there is no hidden reconnect timer or expiry policy.
    /// Cancellation/errors leave Unknown/barrier, never an inferred cleanup.
    pub(super) async fn refresh(
        &mut self,
        host: &StartedServiceContext,
        transport: &TimeTransport,
    ) -> Result<()> {
        let result = self.acquire(host, transport).await;
        if let Err(Error::StateCorrupt) = &result {
            // This covers the whole attempt, including final policy recapture
            // after HTTP and cleanup rechecks. Generic corruption alone is not
            // evidence: the fixed native publisher must still reobserve actual
            // invalid Policy bytes and the unchanged intact original snapshot.
            self.commit_uncertain = true;
            Store::new(&host.context.seed).latch_time_policy_fault(host, &self.snapshot)?;
        }
        result
    }
    async fn acquire(
        &mut self,
        host: &StartedServiceContext,
        transport: &TimeTransport,
    ) -> Result<()> {
        if self.commit_uncertain {
            return Err(Error::StateCommitUnknown);
        }
        self.original.recheck(host)?;
        let seed = &host.context.seed;
        let store = Store::new(seed);
        let current = store.read(seed)?.ok_or(Error::SetupIncomplete)?;
        host.authenticate_running(&current)?;
        if Incarnation::from_host(&current)? != self.incarnation {
            return Err(Error::ServiceIdentityRefused);
        }
        let actual = store.time_load(seed, &current)?;
        if actual.raw != self.snapshot.raw || actual.original_root != self.snapshot.original_root {
            return Err(Error::ScopeConflict);
        }
        // A lagging compact member first persists a product-position cursor
        // without changing its signed evidence or cleanup state. Its stale
        // time cannot be consumed at the newer product Root.
        self.commit_uncertain = true;
        let caught_up = store.time_catchup_existing(host, &self.snapshot)?;
        self.commit_uncertain = false;
        if self.snapshot.state.status != Status::Unknown && !caught_up {
            let next = self
                .snapshot
                .state
                .next_unknown(self.incarnation.clone(), &self.snapshot.raw)?;
            self.commit_uncertain = true;
            self.snapshot = store.time_commit(host, &self.snapshot, &next, None)?;
            self.commit_uncertain = false;
        }
        // The prior observation is either durably invalidated or cannot be
        // consumed because it is behind the authenticated product Root.
        let mut anchor = store.time_acquisition_preflight(host, &self.snapshot, None)?;
        // Policy missing is a safe fixed error, not a default profile. Capture
        // bytes are finally re-read by time_commit in its actual native TX.
        let policy = store.time_policy(seed, &self.snapshot)?;
        let mut denied = self.snapshot.state.denied_key_ids.clone();
        denied.extend(policy.policy.denied_key_ids.iter().cloned());
        denied.sort();
        denied.dedup();
        if denied.len() > 4096 {
            return Err(Error::Unavailable);
        }
        if denied != self.snapshot.state.denied_key_ids {
            // Persist newly observed protected deny BEFORE any network await.
            // A later policy edit cannot erase this accumulated high-water.
            let mut unknown = self
                .snapshot
                .state
                .next_unknown(self.incarnation.clone(), &self.snapshot.raw)?;
            unknown.denied_key_ids = denied.clone();
            self.commit_uncertain = true;
            self.snapshot = store.time_commit(host, &self.snapshot, &unknown, Some(&policy))?;
            self.commit_uncertain = false;
            // The updated state has a new digest; refresh any catch-up cursor
            // and reacquire the product anchor before starting network work.
            if caught_up || self.snapshot.state.product_root.is_some() {
                self.commit_uncertain = true;
                let _ = store.time_catchup_existing(host, &self.snapshot)?;
                self.commit_uncertain = false;
            }
            anchor = store.time_acquisition_preflight(host, &self.snapshot, None)?;
        }
        let trusted_root = anchor.root;
        let floor = self
            .snapshot
            .state
            .floor
            .unwrap_or(0)
            .max(store.budget_time_floor(seed, &current)?.unwrap_or(0));
        let base_root_count = anchor.root_count;
        let history_latest_issue = anchor.latest_issue;
        // Keep the network attempt relative to the authenticated product anchor.
        // The member's retained lineage is used only when publishing the legacy
        // state; it must not independently choose the request's trust anchor.
        let mut successors = store.time_root_scratch(host, &self.snapshot)?;
        loop {
            successors.verify_all()?;
            let selected_owned = if successors.len() == 0 {
                None
            } else {
                Some(successors.read(successors.len() - 1)?)
            };
            let selected = selected_owned.as_deref().unwrap_or(trusted_root.as_slice());
            let version = root_version(selected, &self.snapshot.state.binding.product)?;
            let nonce = transport.fresh_nonce()?;
            let request = json::encode(
                &serde_json::json!({"protocolVersion":1,
                "product":self.snapshot.state.binding.product,"component":self.snapshot.state.binding.component,
                "requestNonce":nonce,"root":{"version":version,"sha256":json::sha256(selected)}}),
                false,
            )?;
            let request_shape = Document::parse(&request, InputKind::Credential)
                .map_err(|_| Error::StateCorrupt)?
                .time_request_shape()
                .map_err(|_| Error::StateCorrupt)?;
            let sent = host.sample_monotonic()?;
            let response = transport.post_time(&request).await;
            if let Ok(response) = response {
                let received = host.sample_monotonic()?;
                received.elapsed_since(&sent)?;
                let observation = SuppliedTimeObservation {
                    sent_monotonic_millis: sent.counters().suspend_inclusive().floor_millis()?,
                    received_monotonic_millis: received
                        .counters()
                        .suspend_inclusive()
                        .ceil_millis()?,
                    max_round_trip_millis: policy.policy.max_round_trip_ms,
                    max_uncertainty_millis: policy.policy.max_uncertainty_ms,
                    trusted_time_floor_millis: floor,
                };
                let mut source_error = None;
                let verified = verify_time_response_source(
                    &response,
                    &trusted_root,
                    successors.len(),
                    |index| read_time_source(|| successors.read(index), &mut source_error),
                    &request_shape,
                    observation,
                    &denied,
                );
                if let Some(error) = source_error {
                    return Err(error);
                }
                if verified.as_ref().is_ok_and(|time| {
                    crate::trusted_time::check_history_time_bound(
                        history_latest_issue,
                        time.earliest_millis(),
                    )
                    .is_ok()
                }) {
                    // Include the first actual signature verification in the
                    // receive/verification bracket, retaining original send.
                    let verified_at = host.sample_monotonic()?;
                    verified_at.elapsed_since(&sent)?;
                    let mut source_error = None;
                    let checked = verify_time_response_source(
                        &response,
                        &trusted_root,
                        successors.len(),
                        |index| read_time_source(|| successors.read(index), &mut source_error),
                        &request_shape,
                        SuppliedTimeObservation {
                            received_monotonic_millis: verified_at
                                .counters()
                                .suspend_inclusive()
                                .ceil_millis()?,
                            ..observation
                        },
                        &denied,
                    );
                    if let Some(error) = source_error {
                        return Err(error);
                    }
                    let checked = checked.map_err(|_| Error::SourceUnavailable)?;
                    crate::trusted_time::check_history_time_bound(
                        history_latest_issue,
                        checked.earliest_millis(),
                    )
                    .map_err(|_| Error::SourceUnavailable)?;
                    let evidence = Evidence {
                        request: String::from_utf8(request).map_err(|_| Error::StateCorrupt)?,
                        response: String::from_utf8(response)
                            .map_err(|_| Error::SourceUnavailable)?,
                        sent: CounterEvidence::from_data(sent.counters()),
                        received: CounterEvidence::from_data(verified_at.counters()),
                        incarnation: self.incarnation.clone(),
                        policy: String::from_utf8(policy.raw.clone())
                            .map_err(|_| Error::StateCorrupt)?,
                        floor_before: floor,
                        base_root_count,
                        denied_key_ids: denied.clone(),
                        earliest: checked.earliest_millis(),
                        latest: checked.latest_millis(),
                    };
                    let pending = PendingRootTime::new(
                        host,
                        &successors,
                        sent,
                        verified_at,
                        evidence,
                        &trusted_root,
                        &checked,
                    )?;
                    return self.publish(host, &store, policy, &successors, denied, pending);
                }
            }
            // A missing successor is only a failed acquisition attempt, never
            // proof that selected is latest or sufficient to advance the floor.
            let next_version = version
                .checked_add(1)
                .filter(|n| *n <= json::SAFE_MAX)
                .ok_or(Error::Unavailable)?;
            match transport
                .get_root(&self.snapshot.state.binding.product, next_version)
                .await?
            {
                RootGetResult::Missing => return Err(Error::SourceUnavailable),
                RootGetResult::Found(root) => {
                    if root.version() != next_version
                        || root.product() != self.snapshot.state.binding.product
                    {
                        return Err(Error::SourceUnavailable);
                    }
                    // Authenticate both Root thresholds before this object can
                    // become the anchor of another network time request.
                    verify_time_root_successor(
                        selected,
                        root.bytes(),
                        &self.snapshot.state.binding.product,
                        &denied,
                    )
                    .map_err(|_| Error::SourceUnavailable)?;
                    let transition = store.time_acquisition_preflight(
                        host,
                        &self.snapshot,
                        Some((&successors, root.bytes())),
                    )?;
                    if transition.root != trusted_root
                        || transition.root_count != base_root_count
                        || transition.latest_issue != history_latest_issue
                    {
                        return Err(Error::ScopeConflict);
                    }
                    successors.push(root.bytes())?;
                }
            }
        }
    }
    fn publish(
        &mut self,
        host: &StartedServiceContext,
        store: &Store,
        policy: PolicySnapshot,
        successors: &RootScratch,
        denied: Vec<String>,
        pending: PendingRootTime<'_, '_>,
    ) -> Result<()> {
        self.original.recheck(host)?;
        // Keep both same-thread recursive mutexes through both native commits
        // and the final authenticated readback. No network operation occurs
        // here. Inner publishers acquire/release their own recursive levels.
        let seed = &host.context.seed;
        let _profile_guard = BootstrapGuard::acquire(seed, false)?;
        let _product_guard = ProductGuard::acquire(seed)?;
        let mut next = self
            .snapshot
            .state
            .next_unknown(self.incarnation.clone(), &self.snapshot.raw)?;
        next.status = Status::CleanupPending;
        next.cleanup_pending = true;
        next.zero_retention = None;
        next.floor = Some(pending.evidence().earliest);
        next.denied_key_ids = denied;
        next.evidence = Some(pending.evidence().clone());
        // Refuse every further refresh after an ambiguous/erroring publisher.
        // Reopening authenticates actual committed state; it never resets it.
        self.commit_uncertain = true;
        self.snapshot = if self.snapshot.state.product_root.is_some()
            || next
                .evidence
                .as_ref()
                .is_some_and(|e| e.base_root_count > 0)
            || successors.len() != 0
        {
            store.time_commit_compact_anchor(
                host,
                &self.snapshot,
                &policy,
                next.evidence.as_ref().ok_or(Error::StateCorrupt)?,
                successors,
                Some(&pending),
            )?
        } else {
            next.validate(&self.snapshot.original_root)?;
            store.time_commit(host, &self.snapshot, &next, Some(&policy))?
        };
        self.commit_uncertain = false;
        // The fixed cleanup-only native operation may finish a genuine fresh
        // zero-obligation census. Legacy/nonzero custody cannot be guessed empty.
        self.commit_uncertain = true;
        store.complete_zero_retention(host)?;
        let actual = store
            .read(seed)
            .map_err(|_| Error::StateCommitUnknown)?
            .ok_or(Error::StateCommitUnknown)?;
        host.authenticate_running(&actual)
            .map_err(|_| Error::StateCommitUnknown)?;
        self.snapshot = store
            .time_load(seed, &actual)
            .map_err(|_| Error::StateCommitUnknown)?;
        self.commit_uncertain = false;
        // No Known clock, preparation, installation or execution permit is returned. The evidence's
        // interval is historical at its recorded counter, not commit-time UTC.
        // Any later consumer still needs a new native counter/readset check;
        // this zero-custody completion is neither a retained UTC ticket nor a
        // real T28/T32/T36 producer, nonzero cleanup or execution permission.
        Ok(())
    }
}
fn read_time_source(
    read: impl FnOnce() -> Result<Vec<u8>>,
    source_error: &mut Option<Error>,
) -> std::result::Result<std::borrow::Cow<'static, [u8]>, TimeVerificationError> {
    read().map(std::borrow::Cow::Owned).map_err(|error| {
        *source_error = Some(error);
        TimeVerificationError::InvalidObservation
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_verification_reads_preserve_source_failure_for_owner() {
        for error in [
            Error::SourceUnavailable,
            Error::Busy,
            Error::StagingCanceled,
            Error::TimeCanceled,
        ] {
            for _phase in 0..2 {
                let mut observed = None;
                assert!(read_time_source(|| Err(error), &mut observed).is_err());
                assert_eq!(observed, Some(error));
            }
        }
    }
    #[test]
    fn successor_preflight_checks_real_dual_thresholds_and_denials() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/product-root-history.json"
        )))
        .unwrap();
        let original = fixture["original"].as_str().unwrap().as_bytes();
        let successor = fixture["batches"][0]["successors"][0].as_str().unwrap();
        assert!(verify_time_root_successor(original, successor.as_bytes(), "pinvou", &[]).is_ok());
        let mut damaged: serde_json::Value = serde_json::from_str(successor).unwrap();
        let signature = damaged["signatures"][0]["signature"]
            .as_str()
            .unwrap()
            .to_owned();
        let first = if signature.starts_with('A') { 'B' } else { 'A' };
        damaged["signatures"][0]["signature"] = format!("{}{}", first, &signature[1..]).into();
        let damaged = json::encode(&damaged, false).unwrap();
        assert!(verify_time_root_successor(original, &damaged, "pinvou", &[]).is_err());
        let denied = serde_json::from_str::<serde_json::Value>(successor).unwrap()["signatures"][0]
            ["keyId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            verify_time_root_successor(original, successor.as_bytes(), "pinvou", &[denied])
                .is_err()
        );
    }
    #[test]
    #[allow(unsafe_code)]
    fn native_mutex_recursion_keeps_other_threads_excluded_until_final_release() {
        use std::ptr;
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        use windows_sys::Win32::System::Threading::{
            CreateMutexExW, MUTEX_MODIFY_STATE, ReleaseMutex, WaitForSingleObject,
        };
        struct TestMutex(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for TestMutex {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let mutex = TestMutex(unsafe {
            CreateMutexExW(
                ptr::null(),
                ptr::null(),
                0,
                MUTEX_MODIFY_STATE | SYNCHRONIZE,
            )
        });
        assert!(!mutex.0.is_null());
        assert_eq!(unsafe { WaitForSingleObject(mutex.0, 0) }, WAIT_OBJECT_0);
        assert_eq!(unsafe { WaitForSingleObject(mutex.0, 0) }, WAIT_OBJECT_0);
        let observe = || {
            let raw = mutex.0 as usize;
            std::thread::spawn(move || {
                let handle = raw as windows_sys::Win32::Foundation::HANDLE;
                let result = unsafe { WaitForSingleObject(handle, 0) };
                if result == WAIT_OBJECT_0 {
                    assert_ne!(unsafe { ReleaseMutex(handle) }, 0);
                }
                result
            })
            .join()
            .unwrap()
        };
        assert_eq!(observe(), WAIT_TIMEOUT);
        assert_ne!(unsafe { ReleaseMutex(mutex.0) }, 0);
        assert_eq!(observe(), WAIT_TIMEOUT);
        assert_ne!(unsafe { ReleaseMutex(mutex.0) }, 0);
        assert_eq!(observe(), WAIT_OBJECT_0);
    }
}
