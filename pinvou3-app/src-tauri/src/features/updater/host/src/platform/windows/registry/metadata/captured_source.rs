//! Historical metadata prefix DATA from an authenticated captured Root member.
//! Current native heads are only read-set pins. Captured policies and time
//! ceilings come exclusively from the Root-owned member capability.
use super::member_source::{active_context, reject_current_denials};
use super::time_history::HistoryPosition;
use super::*;
use crate::platform::windows::registry::time::{
    captured_history::CapturedMemberTimeHistory,
    root_history::{CapturedRootMember, RootSignaturePrefix},
};
use pinvou_upgrade_codec::Document;
use pinvou_upgrade_verifier::{ActiveMetadataInput, SignatureCheckedTimeResponse};
use sha2::{Digest, Sha256};

/// Complete captured batch DATA. Root snapshot stability does not pin the
/// profiles holding retained journal originals; revalidate every such source
/// before, during and after callbacks, including earlier members.
pub(in crate::platform::windows::registry) fn visit_batch_metadata(
    prefix: &RootSignaturePrefix<'_>,
    batch: u64,
    mut visitor: impl FnMut(&CapturedMetadataView<'_, '_, '_>) -> Result<()>,
) -> Result<()> {
    let before = census(prefix, batch, |_| Ok(()))?;
    let visited = census(prefix, batch, &mut visitor)?;
    let after = census(prefix, batch, |_| Ok(()))?;
    if before != visited || before != after {
        return Err(Error::ScopeConflict);
    }
    prefix.recheck()
}

fn census(
    prefix: &RootSignaturePrefix<'_>,
    batch: u64,
    mut visitor: impl FnMut(&CapturedMetadataView<'_, '_, '_>) -> Result<()>,
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"pinvou.root-batch.captured-metadata-census.v2");
    hash.update(batch.to_be_bytes());
    let mut count = 0u64;
    prefix.visit_batch_members(batch, |cap| {
        let view = CapturedMetadataView::from_root_member(cap)?;
        hash.update(view.fingerprint()?);
        count = count.checked_add(1).ok_or(Error::Unavailable)?;
        visitor(&view)?;
        view.recheck()
    })?;
    hash.update(count.to_be_bytes());
    Ok(hash.finalize().into())
}

pub(in crate::platform::windows::registry) struct CapturedMetadataView<'cap, 'source, 'tx> {
    source: CapturedMemberTimeHistory<'cap, 'source, 'tx>,
    actual_head: Vec<u8>,
    actual_roles: Vec<u8>,
    position: HistoryPosition,
    batches: u64,
}

impl<'cap, 'source, 'tx> CapturedMetadataView<'cap, 'source, 'tx> {
    /// Only the native Root owner can mint the input capability. Supplied
    /// snapshot DTOs, keys and an arbitrary "expected" Head cannot enter here.
    pub(in crate::platform::windows::registry) fn from_root_member(
        cap: &'cap CapturedRootMember<'source, 'tx>,
    ) -> Result<Self> {
        let source = CapturedMemberTimeHistory::from_root_member(cap)?;
        source.recheck()?;
        check_layout(&source)?;
        let (actual_head, actual_roles) = current_pins(&source)?;
        let roles = policy::Policy::parse(&source.metadata_pins().role_policy, source.binding())?;
        let context = replay_index::document(&json::encode(
            &serde_json::json!({"product":source.binding().product,
                "component":source.binding().component}),
            false,
        )?)?;
        let mut accumulator = replay::Accumulator::new(&source.source_scope_store())?;
        let position =
            time_history::visit_captured_in(&source, |batch| accumulator.observe(batch, &context))?;
        roles.require_retains(accumulator.required_role_denials())?;
        let batches = accumulator.batches();
        drop(accumulator);
        let view = Self {
            source,
            actual_head,
            actual_roles,
            position,
            batches,
        };
        view.recheck()?;
        Ok(view)
    }

    pub(in crate::platform::windows::registry) fn batches(&self) -> u64 {
        self.batches
    }

    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        self.source.recheck()?;
        check_layout(&self.source)?;
        self.check_pins()?;
        let mut batches = 0u64;
        let position = time_history::visit_captured_in(&self.source, |batch| {
            if batch.index() != batches.checked_add(1).ok_or(Error::Unavailable)? {
                return Err(Error::StateCorrupt);
            }
            batches = batch.index();
            Ok(())
        })?;
        if position != self.position || batches != self.batches {
            return Err(Error::ScopeConflict);
        }
        self.check_pins()?;
        self.source.recheck()
    }

    fn check_pins(&self) -> Result<()> {
        let (head, roles) = current_pins(&self.source)?;
        if head != self.actual_head || roles != self.actual_roles {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }

    fn fingerprint(&self) -> Result<[u8; 32]> {
        self.recheck()?;
        let mut hash = Sha256::new();
        hash.update(b"pinvou.member.captured-metadata-pins.v2");
        hash.update(self.source.source_fingerprint()?);
        for raw in [
            &self.actual_head[..],
            &self.actual_roles,
            self.position.head_bytes(),
        ] {
            hash.update((raw.len() as u64).to_be_bytes());
            hash.update(raw);
        }
        hash.update(self.batches.to_be_bytes());
        Ok(hash.finalize().into())
    }

    /// Stream only the latest graph accepted AT THE CAPTURED CEILING. Its
    /// exact original contexts were authenticated by complete historical graph
    /// replay; deriving them here does not grant a self-asserted scope trust.
    /// No body freshness, current policy or current permission is inferred.
    pub(in crate::platform::windows::registry) fn visit_active(
        &self,
        mut visitor: impl FnMut(&[u8], &Document) -> Result<()>,
    ) -> Result<()> {
        self.recheck()?;
        let global = crate::trusted_time::Policy::parse(
            self.source.global_policy_raw(),
            self.source.binding(),
        )?;
        let roles = policy::Policy::parse(
            &self.source.metadata_pins().role_policy,
            self.source.binding(),
        )?
        .by_role();
        let mut found = false;
        let position = time_history::visit_captured_in(&self.source, |batch| {
            if batch.index() != self.batches {
                return Ok(());
            }
            if found {
                return Err(Error::StateCorrupt);
            }
            found = true;
            let mut original = |raw: Vec<u8>| -> Result<()> {
                let (checked, expected) = active_context(
                    &raw,
                    &self.source.binding().product,
                    &self.source.binding().component,
                )?;
                reject_current_denials(
                    &checked,
                    &self.source.state().denied_key_ids,
                    &global.denied_key_ids,
                    &roles,
                )?;
                visitor(&raw, &expected)
            };
            original(batch.timestamp()?)?;
            original(batch.snapshot()?)?;
            for index in 1..=batch.count() {
                original(batch.member(index)?)?;
            }
            Ok(())
        })?;
        if position != self.position || found != (self.batches != 0) {
            return Err(Error::ScopeConflict);
        }
        self.recheck()
    }

    /// Compatibility with a supplied verified final Root only. The publishing
    /// owner still owns its exact batch binding, full census and atomic commit.
    pub(in crate::platform::windows::registry) fn assert_active_binding(
        &self,
        checked: &SignatureCheckedTimeResponse,
    ) -> Result<()> {
        self.visit_active(|raw, expected| {
            checked
                .assert_active_binding(&ActiveMetadataInput::new(raw, expected))
                .map_err(|_| Error::SourceUnavailable)
        })
    }
}

fn check_layout(source: &CapturedMemberTimeHistory<'_, '_, '_>) -> Result<()> {
    let pins = source.metadata_pins();
    publication::check_bound_history_prefix_in(
        source.private(),
        &pins.genesis,
        source.binding(),
        source.transaction(),
        &pins.head,
        &pins.waterlog_head,
    )
}

fn current_pins(source: &CapturedMemberTimeHistory<'_, '_, '_>) -> Result<(Vec<u8>, Vec<u8>)> {
    let metadata = open(
        source.private().0,
        NAMESPACE,
        false,
        Some(source.transaction()),
    )?
    .ok_or(Error::StateCorrupt)?;
    // These current values only detect source changes. Captured denial policy
    // above is immutable snapshot DATA and is never replaced by these bytes.
    Ok((
        read(&metadata, "Head")?,
        policy::read_in(&metadata, source.binding())?.1,
    ))
}
