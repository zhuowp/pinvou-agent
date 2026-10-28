//! Same-TxR V2 staging outside the accepted product subtree. This owner never
//! commits, samples a clock or constructs service authority. Any error requires
//! abandoning the caller's transaction, including partial copy/delete errors.
use super::super::super::metadata::member_source;
use super::super::super::product_catalog::{ProductGuard, exact};
use super::*;
use std::cell::Cell;
#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) mod component_fixture;

const STAGING: &str = "root-publication-staging-v2";

pub(in crate::platform::windows::registry) struct StagedV2Batch<'tx> {
    seed: &'tx Seed,
    host: HostRegistration,
    guard: &'tx ProductGuard,
    tx: &'tx Handle,
    successors: &'tx RootScratch,
    private: Key,
    stage: Key,
    base_head: Vec<u8>,
    base_root: Vec<u8>,
    base_count: u64,
    advanced: bool,
    head: Vec<u8>,
    roots_chain: (u64, String),
    time_fingerprint: [u8; 32],
    metadata_fingerprint: [u8; 32],
    stage_fingerprint: [u8; 32],
    published: Cell<bool>,
}

impl<'tx> StagedV2Batch<'tx> {
    /// Native copy/delete primitives only; this does not mint a staged batch,
    /// Root proof, service or publication capability from fixture bytes.
    #[cfg(feature = "metadata-component-tests")]
    pub(in crate::platform::windows::registry) fn component_test_tree_in(
        parent: &Key,
        tx: &Handle,
    ) -> Result<()> {
        let root = create(parent.0, "root-publication-tree-probe", tx, false, true)?;
        let source = create(root.0, "source", tx, false, true)?;
        write(&source, "Head", b"unchanged")?;
        let nested = create(source.0, "nested", tx, false, true)?;
        write(&nested, "Original", b"original")?;
        let frozen = tree_hash(&source, tx)?;
        let target = create(root.0, "target", tx, false, true)?;
        copy_tree(&source, &target, tx, 0)?;
        if tree_hash(&target, tx)? != frozen {
            return Err(Error::StateCorrupt);
        }
        write(&nested, "Original", b"changed")?;
        if tree_hash(&source, tx)? == frozen {
            return Err(Error::StateCorrupt);
        }
        write(&nested, "Original", b"original")?;
        if tree_hash(&source, tx)? != frozen {
            return Err(Error::StateCorrupt);
        }
        drop(target);
        drop(nested);
        drop(source);
        drop(root);
        delete_tree(parent, "root-publication-tree-probe", tx, 0)?;
        if open(parent.0, "root-publication-tree-probe", false, Some(tx))?.is_some() {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
    pub(in crate::platform::windows::registry) fn prepare(
        seed: &'tx Seed,
        host: &HostRegistration,
        guard: &'tx ProductGuard,
        tx: &'tx Handle,
        view: Option<&VerifiedHistory<'tx>>,
        evidence: &Evidence,
        successors: &'tx RootScratch,
    ) -> Result<Self> {
        guard.check_seed(seed)?;
        if successors.len() == 0 {
            return Err(Error::StateCorrupt);
        }
        successors.verify_all()?;
        let advanced = advanced_shape_in(seed, tx)?;
        if advanced != view.is_some() {
            return Err(Error::ScopeConflict);
        }
        let product = product(seed, tx, false)?;
        let root_state =
            open(product.0, "root-state-v1", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let base_head = read(&root_state, "Head")?;
        let base_count = if advanced {
            counter(&BatchHead::parse(&base_head)?.root_count)?
        } else {
            0
        };
        let base_root = if let Some(view) = view {
            view.check_context(seed, guard, tx)?;
            view.recheck_head()?;
            view.prefix()?.verify_all_metadata()?;
            crate::trusted_time::check_history_time_bound(view.latest_issue(), evidence.earliest)
                .map_err(|_| Error::ScopeConflict)?;
            view.current_root().to_vec()
        } else {
            super::super::require_product_members_at_genesis_in(seed, host, tx)?;
            let private = Store::new(seed)
                .key(false, Some(tx))?
                .ok_or(Error::SetupIncomplete)?;
            let actual = state_in(&private, host, Some(tx))?;
            // No protected V2 witness exists for local-only legacy rotations.
            if !actual.state.roots.is_empty() {
                return Err(Error::SourceUnavailable);
            }
            let original = read(&product, "Root")?;
            if actual.original_root != original {
                return Err(Error::StateCorrupt);
            }
            original
        };
        if u64::try_from(evidence.base_root_count).ok() != Some(base_count) {
            return Err(Error::ScopeConflict);
        }
        let prefix = view.map(VerifiedHistory::prefix).transpose()?;
        let before_time = super::super::root_read_set::census(seed, host, guard, tx, advanced)?;
        let before_metadata =
            member_source::fingerprint_members(seed, host, guard, tx, prefix.as_ref())?;
        let mut local = evidence.clone();
        local.base_root_count = 0;
        let checked = local.verify_source_checked(
            &Binding::from_host(host),
            &base_root,
            successors.len(),
            |i| Ok(std::borrow::Cow::Owned(successors.read(i)?)),
        )?;
        let roots_chain = fingerprint_root_source(successors.len(), &mut |i| successors.read(i))?;

        // Check each independently bounded global list against the response and
        // every successor. The replay cursor does not claim metadata completeness.
        let mut replay = ProductRootReplay::new(
            &seed.product,
            std::str::from_utf8(&base_root).map_err(|_| Error::StateCorrupt)?,
        )?;
        replay.advance(
            &ProductRootBatch {
                binding: Binding::from_host(host),
                evidence: local,
                successor_count: successors.len(),
            },
            |i| successors.read(i),
            |visit| {
                member_source::visit_metadata_members(
                    seed,
                    host,
                    guard,
                    tx,
                    prefix.as_ref(),
                    |member| {
                        // Refuse a known incompatible active set before any
                        // staging key is created; capture repeats this check.
                        member.assert_active_binding(&checked)?;
                        visit(&member.member().current_state().denied_key_ids)?;
                        let policy = Policy::parse(
                            member.member().current_policy_raw(),
                            member.member().binding(),
                        )?;
                        visit(&policy.denied_key_ids)
                    },
                )
            },
        )?;
        let private = Store::new(seed)
            .key(true, Some(tx))?
            .ok_or(Error::SetupIncomplete)?;
        if open(private.0, STAGING, false, Some(tx))?.is_some() {
            return Err(Error::ScopeConflict);
        }
        let stage = create(private.0, STAGING, tx, false, true)?;
        let members = create(stage.0, "members", tx, false, true)?;
        let catalog_raw = read(&product, "Head")?;
        let catalog = crate::product_catalog::ProductEvent::parse(&catalog_raw)?;
        let mut chain = ObjectChain::new(MEMBER_DOMAIN);
        let mut issuer = false;
        member_source::visit_metadata_members(seed, host, guard, tx, prefix.as_ref(), |member| {
            member.assert_active_binding(&checked)?;
            let event = member.member().event();
            if event.profile_id == seed.profile_id {
                if issuer {
                    return Err(Error::StateCorrupt);
                }
                issuer = true;
            }
            let number = chain.count.checked_add(1).ok_or(Error::Unavailable)?;
            let raw = super::super::root_snapshot::capture_metadata_in(
                &members,
                &revision_name(number),
                seed,
                event,
                member.member().host(),
                guard,
                tx,
                view,
                member,
            )?;
            chain.push(&raw)
        })?;
        let (member_count, member_chain) = chain.finish();
        if !issuer || member_count != catalog.revision || read(&product, "Head")? != catalog_raw {
            return Err(Error::ScopeConflict);
        }
        let roots = create(stage.0, "roots", tx, false, true)?;
        let mut copied = ObjectChain::new(ROOT_DOMAIN);
        let mut final_hash = None;
        for index in 0..successors.len() {
            super::super::super::super::time_cancel::check()?;
            let raw = successors.read(index)?;
            copied.push(&raw)?;
            final_hash = Some(json::sha256(&raw));
            write_root_in(&roots, index as u64 + 1, tx, &raw)?;
        }
        if copied.finish() != roots_chain {
            return Err(Error::ScopeConflict);
        }
        let evidence_raw = write_evidence_in(
            &stage,
            tx,
            &ProductRootBatch {
                binding: Binding::from_host(host),
                evidence: evidence.clone(),
                successor_count: successors.len(),
            },
        )?;
        let old = if advanced {
            Some(BatchHead::parse(&base_head)?)
        } else {
            None
        };
        let next_batch = match &old {
            Some(head) => counter(&head.batch)?,
            None => 0,
        }
        .checked_add(1)
        .ok_or(Error::Unavailable)?;
        let head = BatchHead {
            version: 1,
            batch: next_batch.to_string(),
            previous_sha256: json::sha256(&base_head),
            catalog_revision: catalog.revision.to_string(),
            catalog_head_sha256: json::sha256(&catalog_raw),
            root_count: base_count
                .checked_add(roots_chain.0)
                .ok_or(Error::Unavailable)?
                .to_string(),
            successor_count: roots_chain.0.to_string(),
            root_sha256: final_hash.ok_or(Error::StateCorrupt)?,
            roots_chain_sha256: roots_chain.1.clone(),
            member_count: member_count.to_string(),
            members_chain_sha256: member_chain,
            evidence_sha256: json::sha256(&evidence_raw),
        };
        head.follows(&base_head, old.as_ref())?;
        let head = json::encode(&head, false)?;
        write(&stage, "Record", &head)?;
        let mut result = Self {
            seed,
            host: host.clone(),
            guard,
            tx,
            successors,
            private,
            stage,
            base_head,
            base_root,
            base_count,
            advanced,
            head,
            roots_chain,
            time_fingerprint: before_time,
            metadata_fingerprint: before_metadata,
            stage_fingerprint: [0; 32],
            published: Cell::new(false),
        };
        result.verify_stage()?;
        result.stage_fingerprint = tree_hash(&result.stage, tx)?;
        result.recheck_sources()?;
        Ok(result)
    }
    pub(in crate::platform::windows::registry) fn head(&self) -> &[u8] {
        &self.head
    }
    pub(in crate::platform::windows::registry) fn base_head(&self) -> &[u8] {
        &self.base_head
    }
    pub(in crate::platform::windows::registry) fn base_root(&self) -> &[u8] {
        &self.base_root
    }
    pub(in crate::platform::windows::registry) fn base_count(&self) -> u64 {
        self.base_count
    }
    pub(in crate::platform::windows::registry) fn final_root(&self) -> Result<Vec<u8>> {
        self.verify_stage()?;
        let roots =
            open(self.stage.0, "roots", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        read_root_in(&roots, self.roots_chain.0, self.tx)
    }
    pub(in crate::platform::windows::registry) fn recheck_sources(&self) -> Result<()> {
        if self.published.get() {
            return Err(Error::ScopeConflict);
        }
        self.successors.verify_all()?;
        if fingerprint_root_source(self.successors.len(), &mut |i| self.successors.read(i))?
            != self.roots_chain
        {
            return Err(Error::ScopeConflict);
        }
        if protected_head_in(self.seed, self.tx)? != self.base_head {
            return Err(Error::ScopeConflict);
        }
        let view = if self.advanced {
            Some(VerifiedHistory::open(
                self.seed, &self.host, self.guard, self.tx,
            )?)
        } else {
            None
        };
        let prefix = view.as_ref().map(VerifiedHistory::prefix).transpose()?;
        if let Some(prefix) = &prefix {
            prefix.verify_all_metadata()?;
        }
        let time = super::super::root_read_set::census(
            self.seed,
            &self.host,
            self.guard,
            self.tx,
            self.advanced,
        )?;
        let metadata = member_source::fingerprint_members(
            self.seed,
            &self.host,
            self.guard,
            self.tx,
            prefix.as_ref(),
        )?;
        if time != self.time_fingerprint || metadata != self.metadata_fingerprint {
            return Err(Error::ScopeConflict);
        }
        self.verify_stage()?;
        if tree_hash(&self.stage, self.tx)? != self.stage_fingerprint {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
    fn verify_stage(&self) -> Result<()> {
        exact(&self.stage, true, &["Record"])?;
        exact(&self.stage, false, &["members", "roots", "evidence"])?;
        if read(&self.stage, "Record")? != self.head {
            return Err(Error::ScopeConflict);
        }
        let head = BatchHead::parse(&self.head)?;
        read_evidence_in(&self.stage, self.tx, &head.evidence_sha256)?;
        let roots =
            open(self.stage.0, "roots", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        exact_root_shards(&roots, self.roots_chain.0, self.tx)?;
        let mut chain = ObjectChain::new(ROOT_DOMAIN);
        for i in 1..=self.roots_chain.0 {
            chain.push(&read_root_in(&roots, i, self.tx)?)?;
        }
        if chain.finish() != self.roots_chain {
            return Err(Error::ScopeConflict);
        }
        let members =
            open(self.stage.0, "members", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let count = counter(&head.member_count)?;
        exact(&members, true, &[])?;
        exact_numbered(&members, count)?;
        let mut chain = ObjectChain::new(MEMBER_DOMAIN);
        for i in 1..=count {
            let key = open(members.0, &revision_name(i), false, Some(self.tx))?
                .ok_or(Error::StateCorrupt)?;
            let raw = read(&key, "Record")?;
            super::super::root_snapshot::read_captured_in(&key, self.tx, &raw)?;
            chain.push(&raw)?;
        }
        if chain.finish() != (count, head.members_chain_sha256) {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
    pub(in crate::platform::windows::registry) fn publish_into_product(&self) -> Result<()> {
        self.recheck_sources()?;
        let product = product(self.seed, self.tx, true)?;
        let root =
            open(product.0, "root-state-v1", true, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let history = if self.advanced {
            open(root.0, "history-v2", true, Some(self.tx))?.ok_or(Error::StateCorrupt)?
        } else {
            create(root.0, "history-v2", self.tx, false, true)?
        };
        let batches = if self.advanced {
            open(history.0, "batches", true, Some(self.tx))?.ok_or(Error::StateCorrupt)?
        } else {
            create(history.0, "batches", self.tx, false, true)?
        };
        let number = counter(&BatchHead::parse(&self.head)?.batch)?;
        let target = create(batches.0, &revision_name(number), self.tx, false, true)?;
        copy_tree(&self.stage, &target, self.tx, 0)?;
        if tree_hash(&target, self.tx)? != self.stage_fingerprint {
            return Err(Error::ScopeConflict);
        }
        super::super::super::super::time_cancel::check()?;
        write(&history, "Head", &self.head)?;
        write(&root, "Head", &self.head)?;
        self.published.set(true);
        Ok(())
    }
    pub(in crate::platform::windows::registry) fn discard_staging(self) -> Result<()> {
        self.verify_stage()?;
        if tree_hash(&self.stage, self.tx)? != self.stage_fingerprint {
            return Err(Error::ScopeConflict);
        }
        // Close the owned stage handle before native deletion. The consumer
        // retains intended Head/Root DATA separately for finalization/readback.
        drop(self.stage);
        delete_tree(&self.private, STAGING, self.tx, 0)?;
        if open(self.private.0, STAGING, false, Some(self.tx))?.is_some() {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
}

fn product(seed: &Seed, tx: &Handle, writable: bool) -> Result<Key> {
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    open(
        HKEY_LOCAL_MACHINE,
        &format!(
            "Software\\Pinvou\\{leaf}\\products\\{}",
            json::sha256(seed.product.as_bytes())
        ),
        writable,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)
}

fn tree_hash(key: &Key, tx: &Handle) -> Result<[u8; 32]> {
    fn visit(key: &Key, tx: &Handle, depth: usize, hash: &mut Sha256) -> Result<()> {
        if depth > 8 {
            return Err(Error::StateCorrupt);
        }
        super::super::super::super::time_cancel::check()?;
        hash.update(b"key");
        super::super::super::product_catalog::visit(key, true, |name| {
            let raw = read(key, name)?;
            for raw in [name.as_bytes(), &raw] {
                hash.update((raw.len() as u64).to_be_bytes());
                hash.update(raw);
            }
            Ok(())
        })?;
        hash.update(b"children");
        super::super::super::product_catalog::visit(key, false, |name| {
            hash.update((name.len() as u64).to_be_bytes());
            hash.update(name.as_bytes());
            let child = open(key.0, name, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
            visit(&child, tx, depth + 1, hash)
        })?;
        hash.update(b"end");
        Ok(())
    }
    let mut hash = Sha256::new();
    visit(key, tx, 0, &mut hash)?;
    Ok(hash.finalize().into())
}
fn copy_tree(source: &Key, target: &Key, tx: &Handle, depth: usize) -> Result<()> {
    if depth > 8 {
        return Err(Error::StateCorrupt);
    }
    super::super::super::super::time_cancel::check()?;
    super::super::super::product_catalog::visit(source, true, |name| {
        write(target, name, &read(source, name)?)
    })?;
    super::super::super::product_catalog::visit(source, false, |name| {
        let from = open(source.0, name, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let to = create(target.0, name, tx, false, true)?;
        copy_tree(&from, &to, tx, depth + 1)
    })
}
#[allow(unsafe_code)]
fn delete_tree(parent: &Key, name: &str, tx: &Handle, depth: usize) -> Result<()> {
    if depth > 8 {
        return Err(Error::StateCorrupt);
    }
    super::super::super::super::time_cancel::check()?;
    let key = open(parent.0, name, true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    // Delete index zero each time; names shift after every native deletion.
    while let Some(child) = first_name(&key, false)? {
        delete_tree(&key, &child, tx, depth + 1)?;
    }
    while let Some(value) = first_name(&key, true)? {
        if unsafe { RegDeleteValueW(key.0, wide(&value).as_ptr()) } != 0 {
            return Err(Error::Unavailable);
        }
    }
    drop(key);
    if unsafe {
        windows_sys::Win32::System::Registry::RegDeleteKeyTransactedW(
            parent.0,
            wide(name).as_ptr(),
            KEY_WOW64_64KEY,
            0,
            tx.raw(),
            ptr::null(),
        )
    } != 0
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn first_name(key: &Key, values: bool) -> Result<Option<String>> {
    super::super::super::super::time_cancel::check()?;
    let mut name = [0u16; 129];
    let mut length = name.len() as u32;
    let status = if values {
        unsafe {
            windows_sys::Win32::System::Registry::RegEnumValueW(
                key.0,
                0,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
    } else {
        unsafe {
            windows_sys::Win32::System::Registry::RegEnumKeyExW(
                key.0,
                0,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
    };
    if status == windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS {
        return Ok(None);
    }
    if status != 0 || length == 0 || length as usize >= name.len() {
        return Err(Error::Unavailable);
    }
    Ok(Some(
        String::from_utf16(&name[..length as usize]).map_err(|_| Error::StateCorrupt)?,
    ))
}
