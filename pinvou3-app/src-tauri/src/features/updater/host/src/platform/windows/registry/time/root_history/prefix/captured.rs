//! Captured-member provenance from the actual, completed Root/time lineage.
//! This capability authenticates snapshot bytes, never their metadata history,
//! current time, or a product Root publication. No DTO/key-based minting exists.
use super::super::super::root_snapshot::CapturedData;
use super::*;

pub(in crate::platform::windows::registry) struct CapturedRootMember<'source, 'tx> {
    source: &'source RootSignaturePrefix<'tx>,
    batch: u64,
    index: u64,
    record: Vec<u8>,
    data: CapturedData,
}

impl RootSignaturePrefix<'_> {
    fn batch_key(&self, number: u64) -> Result<Key> {
        if number == 0 || number > self.batch {
            return Err(Error::StateCorrupt);
        }
        let product = product_in(self.seed, self.tx)?;
        let root =
            open(product.0, "root-state-v1", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let history =
            open(root.0, "history-v2", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let batches =
            open(history.0, "batches", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        open(batches.0, &revision_name(number), false, Some(self.tx))?.ok_or(Error::StateCorrupt)
    }

    /// Visit V2 witnesses from the exact authenticated native batch. V1 is
    /// retained as Root/time lineage DATA and cannot become an empty metadata
    /// assertion. Results are provisional until the complete visit succeeds.
    pub(in crate::platform::windows::registry) fn visit_batch_members(
        &self,
        number: u64,
        mut visitor: impl FnMut(&CapturedRootMember<'_, '_>) -> Result<()>,
    ) -> Result<()> {
        self.recheck()?;
        let batch = self.batch_key(number)?;
        let raw = read(&batch, "Record")?;
        let head = BatchHead::parse(&raw)?;
        if counter(&head.batch)? != number {
            return Err(Error::StateCorrupt);
        }
        let count = counter(&head.member_count)?;
        let members = open(batch.0, "members", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        exact_numbered(&members, count)?;
        let mut chain = ObjectChain::new(MEMBER_DOMAIN);
        for index in 1..=count {
            super::super::super::super::super::time_cancel::check()?;
            let key = open(members.0, &revision_name(index), false, Some(self.tx))?
                .ok_or(Error::StateCorrupt)?;
            let record = read(&key, "Record")?;
            chain.push(&record)?;
            let data =
                super::super::super::root_snapshot::read_captured_in(&key, self.tx, &record)?;
            if data.event().product != self.seed.product
                || data.event().kind != self.seed.profile_kind
            {
                return Err(Error::StateCorrupt);
            }
            let captured = CapturedRootMember {
                source: self,
                batch: number,
                index,
                record,
                data,
            };
            captured.recheck()?;
            visitor(&captured)?;
            captured.recheck()?;
        }
        if chain.finish() != (count, head.members_chain_sha256) || read(&batch, "Record")? != raw {
            return Err(Error::ScopeConflict);
        }
        exact_numbered(&members, count)?;
        self.recheck()
    }

    /// Historical active-set verification for one exact native batch. The
    /// prefix grants only Root/time lineage provenance; this separately checks
    /// all V2 member metadata prefixes and their final-Root compatibility.
    /// Success does not publish a Root or grant current metadata-use rights.
    pub(in crate::platform::windows::registry) fn verify_batch_metadata(
        &self,
        number: u64,
    ) -> Result<()> {
        self.recheck()?;
        let batch = self.batch_key(number)?;
        let head = BatchHead::parse(&read(&batch, "Record")?)?;
        let mut evidence = read_evidence_in(&batch, self.tx, &head.evidence_sha256)?;
        let predecessor = self.before_batch(number)?;
        let original = if number == 1 {
            self.original.clone()
        } else {
            let prior = self.batch_key(number - 1)?;
            let prior_head = BatchHead::parse(&read(&prior, "Record")?)?;
            let roots = open(prior.0, "roots", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
            read_root_in(&roots, counter(&prior_head.successor_count)?, self.tx)?
        };
        let expected_base =
            usize::try_from(predecessor.root_count).map_err(|_| Error::Unavailable)?;
        if evidence.evidence.base_root_count != expected_base
            || u64::try_from(evidence.successor_count).ok() != Some(counter(&head.successor_count)?)
        {
            return Err(Error::StateCorrupt);
        }
        evidence.evidence.base_root_count = 0;
        let roots = open(batch.0, "roots", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let checked = evidence.evidence.verify_source_checked(
            &evidence.binding,
            &original,
            evidence.successor_count,
            |index| {
                Ok(std::borrow::Cow::Owned(read_root_in(
                    &roots,
                    index as u64 + 1,
                    self.tx,
                )?))
            },
        )?;
        if checked.root_sha256() != head.root_sha256 {
            return Err(Error::StateCorrupt);
        }
        crate::platform::windows::registry::metadata::captured_source::visit_batch_metadata(
            self,
            number,
            |view| view.assert_active_binding(&checked),
        )?;
        self.recheck()
    }

    pub(in crate::platform::windows::registry) fn verify_all_metadata(&self) -> Result<()> {
        self.recheck()?;
        for number in 1..=self.batch {
            self.verify_batch_metadata(number)?;
        }
        self.recheck()
    }
}

impl<'source, 'tx> CapturedRootMember<'source, 'tx> {
    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        self.source.recheck()?;
        let batch = self.source.batch_key(self.batch)?;
        let members =
            open(batch.0, "members", false, Some(self.source.tx))?.ok_or(Error::StateCorrupt)?;
        let member = open(
            members.0,
            &revision_name(self.index),
            false,
            Some(self.source.tx),
        )?
        .ok_or(Error::StateCorrupt)?;
        if read(&member, "Record")? != self.record {
            return Err(Error::ScopeConflict);
        }
        self.source.recheck()
    }

    /// The ceiling is derived by the source owner, never chosen by a DTO.
    pub(in crate::platform::windows::registry) fn predecessor(
        &self,
    ) -> Result<RootSignaturePrefix<'tx>> {
        self.recheck()?;
        self.source.before_batch(self.batch)
    }
    pub(in crate::platform::windows::registry) fn transaction(&self) -> &'tx Handle {
        self.source.tx
    }
    pub(in crate::platform::windows::registry) fn seed(&self) -> &'tx Seed {
        self.source.seed
    }
    pub(in crate::platform::windows::registry) fn check_context(
        &self,
        seed: &Seed,
        guard: &ProductGuard,
        tx: &Handle,
    ) -> Result<()> {
        self.source.check_context(seed, guard, tx)?;
        self.recheck()
    }
    pub(in crate::platform::windows::registry) fn data(&self) -> &CapturedData {
        &self.data
    }
    pub(in crate::platform::windows::registry) fn source_fingerprint(&self) -> Result<[u8; 32]> {
        self.recheck()?;
        let mut hash = Sha256::new();
        hash.update(b"pinvou.root.captured-member-source.v2");
        hash.update(self.source.source_fingerprint);
        hash.update(self.batch.to_be_bytes());
        hash.update(self.index.to_be_bytes());
        frame(&mut hash, &self.record);
        Ok(hash.finalize().into())
    }
    pub(in crate::platform::windows::registry) fn retained_store(&self) -> Store {
        Store {
            path: format!(
                "Software\\Pinvou\\{}\\{}",
                self.source.seed.updater_leaf(),
                self.data.event().profile_id
            ),
        }
    }

    /// Locate today's registration only to authenticate the retained native
    /// profile path. Its epoch/state never replaces the captured observation.
    pub(in crate::platform::windows::registry) fn current_registration(
        &self,
    ) -> Result<HostRegistration> {
        self.recheck()?;
        let requester = Store::new(self.source.seed)
            .read_for_root_history_in(self.source.seed, self.source.guard, self.source.tx)?
            .ok_or(Error::SetupIncomplete)?;
        let mut found = None;
        super::super::super::super::product_catalog::visit_history_directory_in(
            self.source.seed,
            &requester,
            self.source.guard,
            self.source.tx,
            |event, host| {
                if event.profile_id != self.data.event().profile_id {
                    return Ok(());
                }
                if found.is_some()
                    || json::encode(event, false)? != json::encode(self.data.event(), false)?
                {
                    return Err(Error::StateCorrupt);
                }
                found = Some(host.clone());
                Ok(())
            },
        )?;
        self.recheck()?;
        found.ok_or(Error::StateCorrupt)
    }
}

/// Real native provenance path with public signed Root/time fixture DATA. No
/// running service or live sample is constructed, and the caller never commits.
/// This exercises exact empty V2 metadata, not a nonempty publisher pipeline.
#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) fn component_test_captured_prefix(
    private: &Key,
    seed: &Seed,
    host: &HostRegistration,
    guard: &ProductGuard,
    tx: &Handle,
    batch: &ProductRootBatch,
    mut root: impl FnMut(usize) -> Result<Vec<u8>>,
) -> Result<()> {
    use crate::platform::windows::registry::metadata;
    let current = state_in(private, host, Some(tx))?;
    if current.state.revision != 1 || current.state.evidence.is_some() {
        return Err(Error::StateCorrupt);
    }
    let next = current
        .state
        .next_unknown(batch.evidence.incarnation.clone(), &current.raw)?;
    current
        .state
        .transition(&next, &current.raw, &current.original_root)?;
    let time = open(private.0, NAMESPACE, true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let history = open(time.0, "history", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let row = create(history.0, &revision_name(next.revision), tx, false, true)?;
    let state_raw = write_record(&row, &next)?;
    write(&time, "Head", &state_raw)?;
    let staging = create(private.0, "captured-prefix-test", tx, false, true)?;
    let mut staged = None;
    metadata::member_source::visit_metadata_members(seed, host, guard, tx, None, |view| {
        if staged.is_some() {
            return Err(Error::StateCorrupt);
        }
        staged = Some(super::super::super::root_snapshot::capture_metadata_in(
            &staging,
            "member",
            seed,
            view.member().event(),
            host,
            guard,
            tx,
            None,
            view,
        )?);
        Ok(())
    })?;
    let staged_raw = staged.ok_or(Error::StateCorrupt)?;
    let staged_member = open(staging.0, "member", false, Some(tx))?.ok_or(Error::StateCorrupt)?;

    // First use the unchanged Root/time staging owner and genuine signed
    // evidence. Before minting any prefix, attach the prepared V2 descriptor
    // and recompute the local member-chain/Heads in this discarded test TxR.
    stage_first_stream_in(
        seed,
        host,
        guard,
        tx,
        &batch.evidence,
        batch.successor_count,
        &mut root,
    )?;
    let product = product_in(seed, tx)?;
    let root_state =
        open(product.0, "root-state-v1", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let root_history =
        open(root_state.0, "history-v2", true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let batches = open(root_history.0, "batches", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let batch_key =
        open(batches.0, &revision_name(1), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let members = open(batch_key.0, "members", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    exact_numbered(&members, 1)?;
    let member = open(members.0, &revision_name(1), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    for name in ["Enrollment", "Host", "Original", "Policy"] {
        if read(&member, name)? != read(&staged_member, name)? {
            return Err(Error::StateCorrupt);
        }
    }
    let captured_state = open(member.0, "state", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let staged_state =
        open(staged_member.0, "state", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    if read(&captured_state, "Record")? != read(&staged_state, "Record")? {
        return Err(Error::StateCorrupt);
    }
    for name in [
        "Bootstrap",
        "MetadataGenesis",
        "MetadataHead",
        "WaterlogHead",
        "RolePolicy",
    ] {
        write(&member, name, &read(&staged_member, name)?)?;
    }
    write(&member, "Record", &staged_raw)?;
    let mut head = BatchHead::parse(&read(&batch_key, "Record")?)?;
    let mut chain = ObjectChain::new(MEMBER_DOMAIN);
    chain.push(&staged_raw)?;
    let (count, digest) = chain.finish();
    if count != 1 {
        return Err(Error::StateCorrupt);
    }
    head.members_chain_sha256 = digest;
    let head_raw = json::encode(&head, false)?;
    write(&batch_key, "Record", &head_raw)?;
    write(&root_history, "Head", &head_raw)?;
    write(&root_state, "Head", &head_raw)?;
    let verified = VerifiedHistory::open(seed, host, guard, tx)?;
    let prefix = verified.prefix()?;
    let mut seen = 0;
    prefix.visit_batch_members(1, |cap| {
        seen += 1;
        let view = metadata::captured_source::CapturedMetadataView::from_root_member(cap)?;
        if view.batches() != 0 {
            return Err(Error::StateCorrupt);
        }
        let mut originals = 0;
        view.visit_active(|_, _| {
            originals += 1;
            Ok(())
        })?;
        if originals != 0 {
            return Err(Error::StateCorrupt);
        }
        let saved = read(&member, "MetadataHead")?;
        write(&member, "MetadataHead", b"modified-snapshot")?;
        if cap.recheck().is_ok() || view.recheck().is_ok() {
            return Err(Error::StateCorrupt);
        }
        write(&member, "MetadataHead", &saved)?;
        view.recheck()
    })?;
    if seen != 1 {
        return Err(Error::StateCorrupt);
    }
    let mut complete = 0;
    metadata::captured_source::visit_batch_metadata(&prefix, 1, |view| {
        complete += 1;
        if view.batches() != 0 {
            return Err(Error::StateCorrupt);
        }
        view.visit_active(|_, _| Err(Error::StateCorrupt))
    })?;
    if complete != 1 {
        return Err(Error::StateCorrupt);
    }
    prefix.verify_batch_metadata(1)?;
    prefix.verify_all_metadata()?;
    Ok(())
}
