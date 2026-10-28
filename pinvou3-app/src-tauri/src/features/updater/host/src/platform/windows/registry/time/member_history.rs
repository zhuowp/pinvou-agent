//! Read-only CURRENT catalog member time history. Historical observations are
//! DATA; this module cannot sample counters, construct a running service, write
//! time, or authorize metadata/Root publication. Captured historical member
//! snapshots require a separate provenance factory and are not accepted here.
use super::*;
use crate::product_catalog::Event;
use pinvou_upgrade_metadata_owner::{BootstrapAnchor, BootstrapBinding};
use root_history::RootSignaturePrefix;

type ProductGuard = super::super::product_catalog::ProductGuard;

/// Private shared native replay input. Both the real live-service wrapper and
/// the protected catalog-member factory use this same historical verifier.
pub(super) struct HistoricalSource<'a> {
    pub(super) private: &'a Key,
    pub(super) transaction: &'a Handle,
    pub(super) binding: &'a Binding,
    pub(super) original: &'a [u8],
    pub(super) head: &'a [u8],
}
pub(super) struct HistoricalReplay {
    pub(super) current: State,
    pub(super) selected: Option<(State, Vec<u8>)>,
}

/// Replay every retained row to the exact pinned Head. Selecting a historical
/// observation requires its recorded live-anchor invariants; merely validating
/// a chain ending in Unknown does not require evidence on that current row.
pub(super) fn replay_historical_source(
    source: HistoricalSource<'_>,
    target: Option<(u64, &str)>,
    mut resolve_compact: impl FnMut(&State) -> Result<Vec<u8>>,
) -> Result<HistoricalReplay> {
    let key = open(source.private.0, NAMESPACE, false, Some(source.transaction))?
        .ok_or(Error::StateCorrupt)?;
    if read(&key, "Head")? != source.head {
        return Err(Error::ScopeConflict);
    }
    let genesis = read(&key, "Genesis")?;
    let expected = State::genesis(source.binding.clone(), source.original)?;
    if genesis != json::encode(&header(&expected), false)? {
        return Err(Error::StateCorrupt);
    }
    let mut chain = HistoricalHeaders::new(source.binding, &genesis, source.head)?;
    if let Some((revision, hash)) = target {
        if revision == 0 || revision > chain.head_revision || !json::digest(hash) {
            return Err(Error::StateCorrupt);
        }
    }
    let history =
        open(key.0, "history", false, Some(source.transaction))?.ok_or(Error::StateCorrupt)?;
    exact_history_count(&history, chain.head_revision)?;
    let mut previous: Option<(State, Vec<u8>)> = None;
    let mut selected = None;
    for index in 1..=chain.head_revision {
        super::super::super::time_cancel::check()?;
        let row = open(
            history.0,
            &revision_name(index),
            false,
            Some(source.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let raw = read(&row, "Record")?;
        chain.observe(&raw)?;
        let state = read_record_shape(&row, &raw)?;
        let root = if state.product_root.is_some() {
            resolve_compact(&state)?
        } else {
            state.validate(source.original)?;
            state.current_root(source.original).to_vec()
        };
        if let Some((prior, prior_raw)) = &previous {
            if state.product_root.is_some() {
                prior.transition_compact_shape(&state, prior_raw)?;
            } else {
                if prior.product_root.is_some() {
                    return Err(Error::StateCorrupt);
                }
                prior.transition(&state, prior_raw, source.original)?;
            }
        }
        if let Some(observation) = select_observation(&state, &raw, root, target)? {
            selected = Some(observation);
        }
        previous = Some((state, raw));
    }
    chain.finish()?;
    if read(&key, "Head")? != source.head {
        return Err(Error::ScopeConflict);
    }
    if target.is_some() && selected.is_none() {
        return Err(Error::StateCorrupt);
    }
    Ok(HistoricalReplay {
        current: previous.ok_or(Error::StateCorrupt)?.0,
        selected,
    })
}

fn select_observation(
    state: &State,
    raw: &[u8],
    root: Vec<u8>,
    target: Option<(u64, &str)>,
) -> Result<Option<(State, Vec<u8>)>> {
    let Some((revision, expected_hash)) = target else {
        return Ok(None);
    };
    if state.revision != revision {
        return Ok(None);
    }
    if json::sha256(raw) != expected_hash {
        return Err(Error::StateCorrupt);
    }
    let evidence = state.evidence.as_ref().ok_or(Error::SourceUnavailable)?;
    let incarnation = state.incarnation.as_ref().ok_or(Error::StateCorrupt)?;
    state.anchor_for_live(evidence.policy.as_bytes(), incarnation)?;
    Ok(Some((state.clone(), root)))
}

pub(in crate::platform::windows::registry) struct MemberTimeHistory<'prefix, 'tx> {
    seed: &'tx Seed,
    guard: &'tx ProductGuard,
    transaction: &'tx Handle,
    prefix: Option<&'prefix RootSignaturePrefix<'tx>>,
    requester: HostRegistration,
    event: Event,
    host: HostRegistration,
    host_raw: Vec<u8>,
    bootstrap_raw: Vec<u8>,
    original: Vec<u8>,
    private: Key,
    head: Vec<u8>,
    state: State,
    policy: PolicySnapshot,
}

/// Callback sources are provisional until the complete directory visit and
/// final rechecks succeed. No DTO-based or historical-snapshot constructor is
/// exposed. The caller owns the actual product guard/TxR for this entire call.
pub(in crate::platform::windows::registry) fn visit_member_histories<'prefix, 'tx>(
    seed: &'tx Seed,
    requester: &HostRegistration,
    guard: &'tx ProductGuard,
    transaction: &'tx Handle,
    prefix: Option<&'prefix RootSignaturePrefix<'tx>>,
    mut visitor: impl FnMut(&MemberTimeHistory<'prefix, 'tx>) -> Result<()>,
) -> Result<()> {
    guard.check_seed(seed)?;
    require_product_source(seed, requester, guard, transaction, prefix)?;
    let before = census_members(seed, requester, guard, transaction, prefix, |_| Ok(()))?;
    let visited = census_members(seed, requester, guard, transaction, prefix, &mut visitor)?;
    let after = census_members(seed, requester, guard, transaction, prefix, |_| Ok(()))?;
    super::root_read_set::require_unchanged(&before, &visited)?;
    super::root_read_set::require_unchanged(&before, &after)?;
    require_product_source(seed, requester, guard, transaction, prefix)
}

fn census_members<'prefix, 'tx>(
    seed: &'tx Seed,
    requester: &HostRegistration,
    guard: &'tx ProductGuard,
    transaction: &'tx Handle,
    prefix: Option<&'prefix RootSignaturePrefix<'tx>>,
    mut visitor: impl FnMut(&MemberTimeHistory<'prefix, 'tx>) -> Result<()>,
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"pinvou.product-member.current-time-census.v1");
    let mut count = 0u64;
    super::super::product_catalog::visit_history_directory_in(
        seed,
        requester,
        guard,
        transaction,
        |event, host| {
            let member = MemberTimeHistory::from_catalog(
                seed,
                requester,
                guard,
                transaction,
                prefix,
                event,
                host,
            )?;
            hash.update(member.pins_fingerprint()?);
            count = count.checked_add(1).ok_or(Error::Unavailable)?;
            visitor(&member)?;
            member.recheck()
        },
    )?;
    hash.update(count.to_be_bytes());
    Ok(hash.finalize().into())
}

fn require_product_source(
    seed: &Seed,
    requester: &HostRegistration,
    guard: &ProductGuard,
    tx: &Handle,
    prefix: Option<&RootSignaturePrefix<'_>>,
) -> Result<()> {
    match prefix {
        Some(prefix) => {
            prefix.check_context(seed, guard, tx)?;
            prefix.recheck()
        }
        None => {
            if root_history::advanced_shape_in(seed, tx)? {
                return Err(Error::StateCorrupt);
            }
            // advanced_shape_in only chooses a path; this authenticates the
            // complete original product genesis rather than trusting equality.
            super::super::product_catalog::visit_members_in(seed, requester, tx, |_, _| Ok(()))
        }
    }
}

impl<'prefix, 'tx> MemberTimeHistory<'prefix, 'tx> {
    fn pins_fingerprint(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"pinvou.product-member.current-time-pins.v1");
        let event = json::encode(&self.event, false)?;
        for raw in [
            &event,
            &self.host_raw,
            &self.bootstrap_raw,
            &self.original,
            &self.head,
            &self.policy.raw,
        ] {
            hash.update((raw.len() as u64).to_be_bytes());
            hash.update(raw);
        }
        Ok(hash.finalize().into())
    }

    /// Read-set identity only, usable after the factory's complete traversal.
    pub(in crate::platform::windows::registry) fn source_fingerprint(&self) -> Result<[u8; 32]> {
        self.recheck()?;
        self.pins_fingerprint()
    }
    fn from_catalog(
        seed: &'tx Seed,
        requester: &HostRegistration,
        guard: &'tx ProductGuard,
        transaction: &'tx Handle,
        prefix: Option<&'prefix RootSignaturePrefix<'tx>>,
        event: &Event,
        host: &HostRegistration,
    ) -> Result<Self> {
        if !crate::bootstrap::initialized(&host.known_owner_namespaces) {
            return Err(Error::SetupIncomplete);
        }
        let store = Store {
            path: format!(
                "Software\\Pinvou\\{}\\{}",
                seed.updater_leaf(),
                event.profile_id
            ),
        };
        let private = store
            .key(false, Some(transaction))?
            .ok_or(Error::StateCorrupt)?;
        let host_raw = json::encode(host, false)?;
        if read(&private, "Head")? != host_raw {
            return Err(Error::ScopeConflict);
        }
        let original = read(&private, METADATA_BOOTSTRAP_ROOT)?;
        let bootstrap_raw = read(&private, METADATA_BOOTSTRAP)?;
        let binding = BootstrapBinding::new(
            &event.scope,
            &event.product,
            &event.component,
            &event.target_key,
            &event.kind,
            &event.profile_id,
            &event.seed_sha256,
        )
        .map_err(|_| Error::StateCorrupt)?;
        BootstrapAnchor::new(
            &binding,
            &original,
            event.original_root_size,
            &event.original_root_sha256,
        )
        .and_then(|anchor| anchor.check_existing(&bootstrap_raw, &original))
        .map_err(|_| Error::StateCorrupt)?;
        let time =
            open(private.0, NAMESPACE, false, Some(transaction))?.ok_or(Error::SetupIncomplete)?;
        let head = read(&time, "Head")?;
        let actual_binding = Binding::from_host(host);
        let policy = policy_in(&time, &actual_binding)?;
        let replay = replay_historical_source(
            HistoricalSource {
                private: &private,
                transaction,
                binding: &actual_binding,
                original: &original,
                head: &head,
            },
            None,
            |state| {
                let resolved = prefix
                    .ok_or(Error::StateCorrupt)?
                    .resolve_member_state(state)?;
                Ok(resolved.root().to_vec())
            },
        )?;
        let member = Self {
            seed,
            guard,
            transaction,
            prefix,
            requester: requester.clone(),
            event: event.clone(),
            host: host.clone(),
            host_raw,
            bootstrap_raw,
            original,
            private,
            head,
            state: replay.current,
            policy,
        };
        member.recheck()?;
        Ok(member)
    }

    pub(in crate::platform::windows::registry) fn binding(&self) -> &Binding {
        &self.state.binding
    }
    pub(in crate::platform::windows::registry) fn event(&self) -> &Event {
        &self.event
    }
    pub(in crate::platform::windows::registry) fn host(&self) -> &HostRegistration {
        &self.host
    }
    pub(in crate::platform::windows::registry) fn private(&self) -> &Key {
        &self.private
    }
    pub(in crate::platform::windows::registry) fn transaction(&self) -> &Handle {
        self.transaction
    }
    pub(in crate::platform::windows::registry) fn original_root(&self) -> &[u8] {
        &self.original
    }
    pub(in crate::platform::windows::registry) fn current_state(&self) -> &State {
        &self.state
    }
    pub(in crate::platform::windows::registry) fn current_policy_raw(&self) -> &[u8] {
        &self.policy.raw
    }
    pub(in crate::platform::windows::registry) fn source_scope_store(&self) -> Store {
        Store {
            path: format!(
                "Software\\Pinvou\\{}\\{}",
                self.seed.updater_leaf(),
                self.event.profile_id
            ),
        }
    }

    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        require_product_source(
            self.seed,
            &self.requester,
            self.guard,
            self.transaction,
            self.prefix,
        )?;
        self.recheck_pins()?;
        self.replay(None)?;
        self.recheck_pins()?;
        require_product_source(
            self.seed,
            &self.requester,
            self.guard,
            self.transaction,
            self.prefix,
        )
    }

    fn recheck_pins(&self) -> Result<()> {
        let private = self
            .source_scope_store()
            .key(false, Some(self.transaction))?
            .ok_or(Error::StateCorrupt)?;
        if read(&private, "Head")? != self.host_raw
            || read(&private, METADATA_BOOTSTRAP)? != self.bootstrap_raw
            || read(&private, METADATA_BOOTSTRAP_ROOT)? != self.original
        {
            return Err(Error::ScopeConflict);
        }
        let time = open(private.0, NAMESPACE, false, Some(self.transaction))?
            .ok_or(Error::StateCorrupt)?;
        if read(&time, "Head")? != self.head
            || policy_in(&time, self.binding())?.raw != self.policy.raw
        {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }

    fn replay(&self, target: Option<(u64, &str)>) -> Result<HistoricalReplay> {
        replay_historical_source(
            HistoricalSource {
                private: &self.private,
                transaction: self.transaction,
                binding: self.binding(),
                original: &self.original,
                head: &self.head,
            },
            target,
            |state| {
                let resolved = self
                    .prefix
                    .ok_or(Error::StateCorrupt)?
                    .resolve_member_state(state)?;
                Ok(resolved.root().to_vec())
            },
        )
    }

    /// The metadata owner MUST obtain these bytes from its authenticated actual
    /// same-TxR waterlog batch. This verifies historical DATA, not sample custody
    /// or a current clock. No supplied sample can grant live time authority.
    pub(in crate::platform::windows::registry) fn historical_observation(
        &self,
        sample_raw: &[u8],
    ) -> Result<MemberHistoricalObservation<'_, 'prefix, 'tx>> {
        self.recheck()?;
        let sample = HistoricalSample::parse(sample_raw)?;
        let (state, root) = self
            .replay(Some((sample.revision(), sample.head_sha256())))?
            .selected
            .ok_or(Error::StateCorrupt)?;
        let interval = verify_historical_sample(&state, &root, &sample)?;
        self.recheck()?;
        Ok(MemberHistoricalObservation {
            source: self,
            sample,
            state,
            root,
            interval,
        })
    }
}

pub(in crate::platform::windows::registry) struct MemberHistoricalObservation<'member, 'prefix, 'tx>
{
    source: &'member MemberTimeHistory<'prefix, 'tx>,
    sample: HistoricalSample,
    state: State,
    root: Vec<u8>,
    interval: crate::trusted_time::UtcInterval,
}
impl MemberHistoricalObservation<'_, '_, '_> {
    pub(in crate::platform::windows::registry) fn state(&self) -> &State {
        &self.state
    }
    pub(in crate::platform::windows::registry) fn root(&self) -> &[u8] {
        &self.root
    }
    pub(in crate::platform::windows::registry) fn interval(
        &self,
    ) -> crate::trusted_time::UtcInterval {
        self.interval
    }
    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        self.source.recheck()?;
        let (state, root) = self
            .source
            .replay(Some((self.sample.revision(), self.sample.head_sha256())))?
            .selected
            .ok_or(Error::StateCorrupt)?;
        if json::encode(&header(&state), false)? != json::encode(&header(&self.state), false)?
            || state.roots != self.state.roots
            || state.evidence != self.state.evidence
            || root != self.root
            || verify_historical_sample(&state, &root, &self.sample)? != self.interval
        {
            return Err(Error::ScopeConflict);
        }
        self.source.recheck()
    }
}

#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_test_current(
    seed: &Seed,
    requester: &HostRegistration,
    guard: &ProductGuard,
    tx: &Handle,
) -> Result<()> {
    let mut found = false;
    visit_member_histories(seed, requester, guard, tx, None, |member| {
        if member.event().profile_id != seed.profile_id {
            return Ok(());
        }
        found = true;
        member.recheck()?;
        if member.state.evidence.is_none() {
            assert!(matches!(
                member.replay(Some((member.state.revision, &json::sha256(&member.head)))),
                Err(Error::SourceUnavailable)
            ));
        }
        let private = member
            .source_scope_store()
            .key(true, Some(tx))?
            .ok_or(Error::StateCorrupt)?;
        let time = open(private.0, NAMESPACE, true, Some(tx))?.ok_or(Error::StateCorrupt)?;
        for (key, name) in [
            (&private, "Head"),
            (&private, METADATA_BOOTSTRAP),
            (&private, METADATA_BOOTSTRAP_ROOT),
            (&time, "Head"),
            (&time, "Policy"),
        ] {
            let saved = read(key, name)?;
            write(key, name, b"changed")?;
            assert!(member.recheck().is_err());
            write(key, name, &saved)?;
            member.recheck()?;
        }
        let history = open(time.0, "history", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let first =
            open(history.0, &revision_name(1), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let saved = read(&first, "Record")?;
        write(&first, "Record", b"changed-old-row-with-same-head")?;
        assert!(member.recheck().is_err());
        write(&first, "Record", &saved)?;
        member.recheck()
    })?;
    if !found {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_genesis_is_valid_history_but_not_a_historical_observation() {
        let root = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/metadata-component-fixture/root.json"
        ));
        let binding = Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-nsis-perMachine".into(),
            profile_kind: "lab".into(),
            profile_id: "member-test".into(),
            genesis_seed_sha256: "1".repeat(64),
            genesis_manifest_sha256: "2".repeat(64),
            original_install_operation_id: "operation".into(),
        };
        let state = State::genesis(binding, root).unwrap();
        state.validate(root).unwrap();
        let raw = json::encode(&header(&state), false).unwrap();
        assert!(
            select_observation(&state, &raw, root.to_vec(), None)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            select_observation(&state, &raw, root.to_vec(), Some((1, &json::sha256(&raw)))),
            Err(Error::SourceUnavailable)
        ));
        assert!(matches!(
            select_observation(&state, &raw, root.to_vec(), Some((1, &"f".repeat(64)))),
            Err(Error::StateCorrupt)
        ));
    }
}
