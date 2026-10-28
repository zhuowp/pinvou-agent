//! Captured native member prefixes. Only a Root-owned capture capability can
//! select the ceiling. No running service or current clock is constructed.
use super::super::metadata::member_source::CapturedMetadataPins;
use super::member_history::{HistoricalReplay, HistoricalSource, replay_historical_prefix_source};
use super::root_history::{CapturedRootMember, RootSignaturePrefix};
use super::*;
use sha2::{Digest, Sha256};

pub(in crate::platform::windows::registry) struct CapturedMemberTimeHistory<'cap, 'source, 'tx> {
    cap: &'cap CapturedRootMember<'source, 'tx>,
    predecessor: RootSignaturePrefix<'tx>,
    private: Key,
    host_head: Vec<u8>,
    time_head: Vec<u8>,
    time_genesis: Vec<u8>,
    policy: Vec<u8>,
    ceiling: Vec<u8>,
}

impl<'cap, 'source, 'tx> CapturedMemberTimeHistory<'cap, 'source, 'tx> {
    pub(in crate::platform::windows::registry) fn from_root_member(
        cap: &'cap CapturedRootMember<'source, 'tx>,
    ) -> Result<Self> {
        cap.recheck()?;
        let current = cap.current_registration()?;
        if Binding::from_host(&current) != cap.data().state().binding
            || current.initial_root_reference != cap.data().host().initial_root_reference
        {
            return Err(Error::StateCorrupt);
        }
        let tx = cap.transaction();
        let private = cap
            .retained_store()
            .key(false, Some(tx))?
            .ok_or(Error::StateCorrupt)?;
        let time = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        let source = Self {
            cap,
            predecessor: cap.predecessor()?,
            host_head: json::encode(&current, false)?,
            time_head: read(&time, "Head")?,
            time_genesis: read(&time, "Genesis")?,
            policy: read(&time, "Policy")?,
            ceiling: json::encode(&header(cap.data().state()), false)?,
            private,
        };
        source.recheck()?;
        Ok(source)
    }
    pub(in crate::platform::windows::registry) fn binding(&self) -> &Binding {
        &self.state().binding
    }
    pub(in crate::platform::windows::registry) fn private(&self) -> &Key {
        &self.private
    }
    pub(in crate::platform::windows::registry) fn transaction(&self) -> &'tx Handle {
        self.cap.transaction()
    }
    pub(in crate::platform::windows::registry) fn original_root(&self) -> &[u8] {
        self.cap.data().original()
    }
    pub(in crate::platform::windows::registry) fn state(&self) -> &State {
        self.cap.data().state()
    }
    pub(in crate::platform::windows::registry) fn global_policy_raw(&self) -> &[u8] {
        self.cap.data().global_policy_raw()
    }
    pub(in crate::platform::windows::registry) fn metadata_pins(&self) -> &CapturedMetadataPins {
        self.cap.data().metadata()
    }
    pub(in crate::platform::windows::registry) fn source_scope_store(&self) -> Store {
        self.cap.retained_store()
    }

    pub(in crate::platform::windows::registry) fn source_fingerprint(&self) -> Result<[u8; 32]> {
        self.recheck()?;
        let mut hash = Sha256::new();
        hash.update(b"pinvou.member.captured-time-source.v2");
        hash.update(self.cap.source_fingerprint()?);
        for raw in [
            &self.host_head,
            &self.time_head,
            &self.time_genesis,
            &self.policy,
            &self.ceiling,
        ] {
            hash.update((raw.len() as u64).to_be_bytes());
            hash.update(raw);
        }
        Ok(hash.finalize().into())
    }

    fn pins(&self) -> Result<()> {
        let private = self
            .source_scope_store()
            .key(false, Some(self.transaction()))?
            .ok_or(Error::StateCorrupt)?;
        let time = open(private.0, NAMESPACE, false, Some(self.transaction()))?
            .ok_or(Error::StateCorrupt)?;
        if read(&private, "Head")? != self.host_head
            || read(&private, METADATA_BOOTSTRAP)? != self.metadata_pins().bootstrap
            || read(&private, METADATA_BOOTSTRAP_ROOT)? != self.original_root()
            || read(&time, "Head")? != self.time_head
            || read(&time, "Genesis")? != self.time_genesis
            || read(&time, "Policy")? != self.policy
        {
            return Err(Error::ScopeConflict);
        }
        // Today's policy is a source pin only, never the captured admission
        // policy. Its valid binding cannot replace historical deny knowledge.
        Policy::parse(&self.policy, self.binding())?;
        Ok(())
    }

    fn host_history(&self) -> Result<()> {
        let captured = self.cap.data().host();
        let current: HostRegistration = json::decode(&self.host_head, false)?;
        if captured.revision == 0 || captured.revision > current.revision {
            return Err(Error::StateCorrupt);
        }
        let history = open(self.private.0, "history", false, Some(self.transaction()))?
            .ok_or(Error::StateCorrupt)?;
        exact_history_count(&history, current.revision)?;
        let mut previous = None;
        let mut last = Vec::new();
        let expected_capture = json::encode(captured, false)?;
        for revision in 1..=current.revision {
            super::super::super::time_cancel::check()?;
            let row = open(
                history.0,
                &revision_name(revision),
                false,
                Some(self.transaction()),
            )?
            .ok_or(Error::StateCorrupt)?;
            super::super::product_catalog::exact(&row, true, &["Record"])?;
            super::super::product_catalog::exact(&row, false, &[])?;
            let raw = read(&row, "Record")?;
            let value: HostRegistration = json::decode(&raw, false)?;
            if json::encode(&value, false)? != raw
                || value.revision != revision
                || value.previous_record_sha256 != previous
                || Binding::from_host(&value) != *self.binding()
                || value.initial_root_reference != captured.initial_root_reference
                || value.host_state_version != captured.host_state_version
                || (revision == captured.revision && raw != expected_capture)
            {
                return Err(Error::StateCorrupt);
            }
            previous = Some(json::sha256(&raw));
            last = raw;
        }
        if last != self.host_head {
            return Err(Error::ScopeConflict);
        }
        exact_history_count(&history, current.revision)
    }

    fn replay(&self, target: Option<(u64, &str)>) -> Result<HistoricalReplay> {
        replay_historical_prefix_source(
            HistoricalSource {
                private: &self.private,
                transaction: self.transaction(),
                binding: self.binding(),
                original: self.original_root(),
                head: &self.ceiling,
            },
            &self.time_head,
            target,
            |state| {
                Ok(self
                    .predecessor
                    .resolve_member_state(state)?
                    .root()
                    .to_vec())
            },
        )
    }

    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        self.cap.recheck()?;
        if json::encode(&self.cap.current_registration()?, false)? != self.host_head {
            return Err(Error::ScopeConflict);
        }
        self.pins()?;
        self.host_history()?;
        let observed = self.replay(None)?.current;
        if json::encode(&header(&observed), false)? != self.ceiling
            || observed.roots != self.state().roots
            || observed.evidence != self.state().evidence
        {
            return Err(Error::ScopeConflict);
        }
        self.host_history()?;
        self.pins()?;
        self.predecessor.recheck()?;
        self.cap.recheck()
    }

    /// The metadata owner supplies only its actual bound journal Sample. Raw
    /// samples select historical DATA and cannot grant clock or source custody.
    pub(in crate::platform::windows::registry) fn historical_observation(
        &self,
        raw: &[u8],
    ) -> Result<CapturedHistoricalObservation<'_, 'cap, 'source, 'tx>> {
        self.recheck()?;
        let sample = HistoricalSample::parse(raw)?;
        let (state, root) = self
            .replay(Some((sample.revision(), sample.head_sha256())))?
            .selected
            .ok_or(Error::StateCorrupt)?;
        let interval = verify_historical_sample(&state, &root, &sample)?;
        self.recheck()?;
        Ok(CapturedHistoricalObservation {
            source: self,
            sample,
            state,
            root,
            interval,
        })
    }
}

pub(in crate::platform::windows::registry) struct CapturedHistoricalObservation<
    'read,
    'cap,
    'source,
    'tx,
> {
    source: &'read CapturedMemberTimeHistory<'cap, 'source, 'tx>,
    sample: HistoricalSample,
    state: State,
    root: Vec<u8>,
    interval: crate::trusted_time::UtcInterval,
}
impl CapturedHistoricalObservation<'_, '_, '_, '_> {
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
