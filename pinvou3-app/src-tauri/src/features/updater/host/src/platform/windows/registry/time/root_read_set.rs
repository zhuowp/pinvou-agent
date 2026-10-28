//! Private, read-only product Root input census. This grants no Root authority.
//! A future publisher must own this entire operation, including the final recheck
//! and commit; it must not expose this transaction or accept arbitrary callbacks.
use super::*;
use sha2::{Digest, Sha256};

fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

pub(super) fn bind_product_head(hash: &mut Sha256, head: &[u8]) {
    frame(hash, head);
}

pub(super) fn require_unchanged(expected: &[u8; 32], observed: &[u8; 32]) -> Result<()> {
    if expected != observed {
        return Err(Error::ScopeConflict);
    }
    Ok(())
}

// This is only a read-set fingerprint. None of these bytes or catalog callbacks
// grants authority; replay and full state validation must succeed separately.
fn provisional_member_fingerprint(
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    frame(&mut hash, b"pinvou.product-root.provisional-members.v1");
    let mut count = 0u64;
    super::super::product_catalog::visit_history_directory_in(
        seed,
        host,
        guard,
        tx,
        &mut |event: &crate::product_catalog::Event, member: &HostRegistration| {
            let path = format!(
                "Software\\Pinvou\\{}\\{}\\private",
                seed.updater_leaf(),
                event.profile_id
            );
            let private =
                open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
            let time =
                open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
            frame(&mut hash, &json::encode(event, false)?);
            frame(&mut hash, &json::encode(member, false)?);
            frame(&mut hash, &read(&private, METADATA_BOOTSTRAP_ROOT)?);
            frame(&mut hash, &read(&time, "Head")?);
            frame(&mut hash, &read(&time, "Policy")?);
            count = count.checked_add(1).ok_or(Error::Unavailable)?;
            Ok(())
        },
    )?;
    hash.update(count.to_be_bytes());
    Ok(hash.finalize().into())
}

pub(super) fn census(
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
    persisted_history: bool,
) -> Result<[u8; 32]> {
    let store = Store::new(seed);
    let actual = if persisted_history {
        store.read_for_root_history_in(seed, guard, tx)?
    } else {
        store.read_in(seed, Some(tx))?
    }
    .ok_or(Error::SetupIncomplete)?;
    if actual.digest()? != host.digest()? {
        return Err(Error::ScopeConflict);
    }
    let catalog_leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let catalog = open(
        HKEY_LOCAL_MACHINE,
        &format!("Software\\Pinvou\\{catalog_leaf}"),
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
    let mut hash = Sha256::new();
    frame(&mut hash, b"pinvou.product-root.read-set.v1");
    frame(&mut hash, &read(&product, "Head")?);
    frame(&mut hash, &read(&product, "Root")?);
    let mut count = 0u64;
    // The first pass has no authority. Authenticate the historical chain
    // before consuming member state, then require the same protected inputs.
    let provisional = if persisted_history {
        let before = provisional_member_fingerprint(seed, &actual, guard, tx)?;
        let root_state =
            open(product.0, "root-state-v1", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let root_head = read(&root_state, "Head")?;
        let verified = super::root_history::VerifiedHistory::open(seed, &actual, guard, tx)?;
        if read(&root_state, "Head")? != root_head
            || provisional_member_fingerprint(seed, &actual, guard, tx)? != before
        {
            return Err(Error::ScopeConflict);
        }
        // The authenticated canonical head includes the final batch position,
        // Root count and digest. Its exact bytes bind the read-set fingerprint.
        bind_product_head(&mut hash, &root_head);
        Some((before, root_head, verified))
    } else {
        None
    };
    let mut visit_member = |event: &crate::product_catalog::Event, member: &HostRegistration| {
        let path = format!(
            "Software\\Pinvou\\{}\\{}\\private",
            seed.updater_leaf(),
            event.profile_id
        );
        let private =
            open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let snapshot = if persisted_history {
            let (_, _, verified) = provisional.as_ref().ok_or(Error::StateCorrupt)?;
            state_in_product(&private, member, seed, guard, tx, verified)?
        } else {
            state_in(&private, member, Some(tx))?
        };
        if snapshot
            .state
            .policy_fault
            .as_ref()
            .is_some_and(PolicyFault::is_active)
        {
            return Err(Error::PrerequisiteUnavailable);
        }
        let key = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
        let policy = policy_in(&key, &snapshot.state.binding)?;
        frame(&mut hash, &json::encode(event, false)?);
        frame(&mut hash, &json::encode(member, false)?);
        frame(&mut hash, &snapshot.raw);
        frame(&mut hash, &snapshot.original_root);
        frame(&mut hash, &policy.raw);
        count = count.checked_add(1).ok_or(Error::Unavailable)?;
        Ok(())
    };
    if persisted_history {
        super::super::product_catalog::visit_history_directory_in(
            seed,
            &actual,
            guard,
            tx,
            &mut visit_member,
        )?;
        let (expected_members, expected_root_head, _) = provisional.ok_or(Error::StateCorrupt)?;
        let root_state =
            open(product.0, "root-state-v1", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        if read(&root_state, "Head")? != expected_root_head
            || provisional_member_fingerprint(seed, &actual, guard, tx)? != expected_members
        {
            return Err(Error::ScopeConflict);
        }
    } else {
        super::super::product_catalog::visit_members_in(seed, &actual, tx, &mut visit_member)?;
    }
    hash.update(count.to_be_bytes());
    Ok(hash.finalize().into())
}

/// Owns the guards and transaction; no transaction or callback escapes.
/// `state_in` validates the current time state and its predecessor, not the
/// complete lifetime history. Root history needs independent replay.
pub(in crate::platform::windows::registry) struct RootReadSet<'a> {
    seed: &'a Seed,
    host: HostRegistration,
    service: Option<&'a StartedServiceContext>,
    persisted_history: bool,
    // Fields drop in declaration order: end the transaction before either lock.
    tx: Handle,
    guard: super::super::product_catalog::ProductGuard,
    _bootstrap: BootstrapGuard,
    fingerprint: [u8; 32],
}
impl<'a> RootReadSet<'a> {
    #[allow(unsafe_code)]
    pub(in crate::platform::windows::registry) fn new(
        seed: &'a Seed,
        host: &'a HostRegistration,
    ) -> Result<Self> {
        let bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::super::product_catalog::ProductGuard::acquire(seed)?;
        guard.check_seed(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let fingerprint = census(seed, host, &guard, &tx, false)?;
        Ok(Self {
            seed,
            host: host.clone(),
            service: None,
            persisted_history: false,
            _bootstrap: bootstrap,
            guard,
            tx,
            fingerprint,
        })
    }

    /// Acquire an authenticated view of an already persisted product history.
    /// No time or upgrade authority is granted; no commit capability escapes.
    #[allow(unsafe_code)]
    pub(in crate::platform::windows::registry) fn new_persisted(
        service: &'a StartedServiceContext,
    ) -> Result<Self> {
        let seed = &service.context.seed;
        let bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = super::super::product_catalog::ProductGuard::acquire(seed)?;
        guard.check_seed(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let host = Store::new(seed)
            .read_for_root_history_in(seed, &guard, &tx)?
            .ok_or(Error::SetupIncomplete)?;
        service.authenticate_running(&host)?;
        let fingerprint = census(seed, &host, &guard, &tx, true)?;
        service.authenticate_running(&host)?;
        Ok(Self {
            seed,
            host,
            service: Some(service),
            persisted_history: true,
            _bootstrap: bootstrap,
            guard,
            tx,
            fingerprint,
        })
    }
    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        self.guard.check_seed(self.seed)?;
        if let Some(service) = self.service {
            service.authenticate_running(&self.host)?;
        }
        let observed = census(
            self.seed,
            &self.host,
            &self.guard,
            &self.tx,
            self.persisted_history,
        )?;
        require_unchanged(&self.fingerprint, &observed)?;
        if let Some(service) = self.service {
            service.authenticate_running(&self.host)?;
        }
        Ok(())
    }
    /// Read the current product Root from the protected history rather than a
    /// member's cumulative vector. The guard and transaction remain held;
    /// this data alone is not a live time or installation capability.
    pub(in crate::platform::windows::registry) fn replayed_product_root(&self) -> Result<Vec<u8>> {
        if !self.persisted_history {
            return Err(Error::PrerequisiteUnavailable);
        }
        self.recheck()?;
        let root = super::root_history::replay_persisted_in(self.seed, &self.guard, &self.tx)?;
        self.recheck()?;
        Ok(root)
    }
    /// Recheck the exact committed product head and the member revision inside
    /// the same protected replay view. No caller-supplied record grants trust.
    pub(super) fn committed_member(
        &self,
        expected_head: &[u8],
        expected_root: &[u8],
        expected_member: &[u8],
    ) -> Result<TimeSnapshot> {
        if !self.persisted_history {
            return Err(Error::PrerequisiteUnavailable);
        }
        self.recheck()?;
        if super::root_history::protected_head_in(self.seed, &self.tx)? != expected_head
            || self.replayed_product_root()? != expected_root
        {
            return Err(Error::ScopeConflict);
        }
        let private = Store::new(self.seed)
            .key(false, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        let verified = super::root_history::VerifiedHistory::open(
            self.seed,
            &self.host,
            &self.guard,
            &self.tx,
        )?;
        verified.prefix()?.verify_all_metadata()?;
        let snapshot = state_in_product(
            &private,
            &self.host,
            self.seed,
            &self.guard,
            &self.tx,
            &verified,
        )?;
        if snapshot.raw != expected_member {
            return Err(Error::ScopeConflict);
        }
        let evidence = snapshot
            .state
            .evidence
            .as_ref()
            .ok_or(Error::StateCorrupt)?;
        let (_, verified_root, _) = super::root_history::replay_persisted_with_position_in(
            self.seed,
            &self.guard,
            &self.tx,
            Some((
                &json::sha256(expected_head),
                &snapshot.state.binding,
                Some(evidence),
            )),
        )?;
        let verified_root = verified_root.ok_or(Error::StateCorrupt)?;
        if verified_root.root() != expected_root {
            return Err(Error::StateCorrupt);
        }
        if snapshot.state.product_root.is_some() {
            verified_root.authenticate_compact(&snapshot.state)?;
        }
        self.recheck()?;
        Ok(snapshot)
    }
    /// This consumes and always drops the uncommitted transaction. It is an
    /// internal verification probe, never a publication or Root authority.
    #[allow(dead_code)]
    pub(in crate::platform::windows::registry) fn probe_first_root_batch(self) -> Result<()> {
        self.recheck()?;
        super::root_history::probe_first_in(self.seed, &self.host, &self.guard, &self.tx)?;
        self.recheck()
    }
    /// Create only the test-owned scratch container; this does not create a
    /// candidate Root or claim that replay succeeded.
    #[cfg(feature = "metadata-component-tests")]
    pub(in crate::platform::windows::registry) fn stage_container_for_test(&self) -> Result<()> {
        let private = Store::new(self.seed)
            .key(true, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        create(
            private.0,
            "root-history-candidate-v2",
            &self.tx,
            false,
            true,
        )?;
        Ok(())
    }
    #[cfg(feature = "metadata-component-tests")]
    pub(in crate::platform::windows::registry) fn damage_original_root_for_test(
        &self,
    ) -> Result<()> {
        let private = Store::new(self.seed)
            .key(true, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        write(&private, METADATA_BOOTSTRAP_ROOT, b"damaged")
    }
    #[cfg(feature = "metadata-component-tests")]
    #[allow(unsafe_code)]
    pub(in crate::platform::windows::registry) fn delete_policy_for_test(&self) -> Result<()> {
        let private = Store::new(self.seed)
            .key(true, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        let key =
            open(private.0, NAMESPACE, true, Some(&self.tx))?.ok_or(Error::SetupIncomplete)?;
        if unsafe { RegDeleteValueW(key.0, wide("Policy").as_ptr()) } != 0 {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    #[cfg(feature = "metadata-component-tests")]
    pub(in crate::platform::windows::registry) fn add_root_extra_for_test(&self) -> Result<()> {
        let leaf = if self.seed.profile_kind == "production" {
            "UpgradeProductCatalogV1"
        } else {
            "UpgradeProductCatalogLabV1"
        };
        let path = format!(
            "Software\\Pinvou\\{leaf}\\products\\{}\\root-state-v1",
            json::sha256(self.seed.product.as_bytes())
        );
        let root =
            open(HKEY_LOCAL_MACHINE, &path, true, Some(&self.tx))?.ok_or(Error::StateCorrupt)?;
        write(&root, "Unexpected", b"x")
    }
    #[cfg(feature = "metadata-component-tests")]
    pub(in crate::platform::windows::registry) fn damage_time_head_for_test(&self) -> Result<()> {
        let private = Store::new(self.seed)
            .key(true, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        let key =
            open(private.0, NAMESPACE, true, Some(&self.tx))?.ok_or(Error::SetupIncomplete)?;
        write(&key, "Head", b"damaged")
    }
    #[cfg(feature = "metadata-component-tests")]
    pub(in crate::platform::windows::registry) fn damage_policy_for_test(&self) -> Result<()> {
        let private = Store::new(self.seed)
            .key(true, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        let key =
            open(private.0, NAMESPACE, true, Some(&self.tx))?.ok_or(Error::SetupIncomplete)?;
        write(&key, "Policy", b"{}")
    }
    #[cfg(feature = "metadata-component-tests")]
    pub(in crate::platform::windows::registry) fn change_valid_policy_for_test(
        &self,
    ) -> Result<()> {
        let private = Store::new(self.seed)
            .key(true, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        let state = state_in(&private, &self.host, Some(&self.tx))?;
        let key =
            open(private.0, NAMESPACE, true, Some(&self.tx))?.ok_or(Error::SetupIncomplete)?;
        let mut policy = policy_in(&key, &state.state.binding)?.policy;
        policy.max_round_trip_ms = policy
            .max_round_trip_ms
            .checked_add(1)
            .ok_or(Error::Unavailable)?;
        write(&key, "Policy", &json::encode(&policy, false)?)?;
        policy_in(&key, &state.state.binding)?;
        Ok(())
    }
    #[cfg(feature = "metadata-component-tests")]
    #[allow(unsafe_code)]
    pub(in crate::platform::windows::registry) fn empty_policy_for_test(&self) -> Result<()> {
        let private = Store::new(self.seed)
            .key(true, Some(&self.tx))?
            .ok_or(Error::SetupIncomplete)?;
        let key =
            open(private.0, NAMESPACE, true, Some(&self.tx))?.ok_or(Error::SetupIncomplete)?;
        if unsafe {
            RegSetValueExW(
                key.0,
                wide("Policy").as_ptr(),
                0,
                REG_BINARY,
                ptr::null(),
                0,
            )
        } != 0
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
