//! Historical time verification over the actual same-transaction waterlog.
//! Complete metadata signatures, watermark replay and publication are separate.
use super::waterlog::StructuralBatch;
use super::*;
use crate::platform::windows::{
    installed::StartedServiceContext,
    registry::time::{HistoricalSample, LiveTimeReadSet},
};
use crate::trusted_time::UtcInterval;
use std::collections::BTreeMap;

/// Native history position DATA. Equality is meaningful only together with a
/// successful complete traversal of the same source, never as a hash-only grant.
#[derive(PartialEq, Eq)]
pub(in crate::platform::windows::registry) struct HistoryPosition {
    head: Vec<u8>,
}
impl HistoryPosition {
    pub(super) fn head_bytes(&self) -> &[u8] {
        &self.head
    }
}

/// A provisional batch with authenticated historical time, not a metadata
/// acceptance result. The native row borrows the held TxR; the owned bounded
/// observation remains DATA and is rechecked by its source-specific visitor.
#[allow(dead_code)]
pub(in crate::platform::windows::registry) struct TimeCheckedBatch<'batch, 'tx> {
    batch: &'batch StructuralBatch<'tx>,
    state: crate::trusted_time::State,
    root: Vec<u8>,
    interval: UtcInterval,
    role_denied: BTreeMap<String, Vec<String>>,
}

#[allow(dead_code)]
impl TimeCheckedBatch<'_, '_> {
    pub(in crate::platform::windows::registry) fn index(&self) -> u64 {
        self.batch.index()
    }
    pub(in crate::platform::windows::registry) fn count(&self) -> u32 {
        self.batch.count()
    }
    pub(in crate::platform::windows::registry) fn interval(&self) -> UtcInterval {
        self.interval
    }
    pub(in crate::platform::windows::registry) fn root(&self) -> &[u8] {
        &self.root
    }
    pub(in crate::platform::windows::registry) fn global_denied(&self) -> &[String] {
        &self.state.denied_key_ids
    }
    pub(in crate::platform::windows::registry) fn role_denied(
        &self,
    ) -> &BTreeMap<String, Vec<String>> {
        &self.role_denied
    }
    pub(in crate::platform::windows::registry) fn timestamp(&self) -> Result<Vec<u8>> {
        self.batch.timestamp()
    }
    pub(in crate::platform::windows::registry) fn snapshot(&self) -> Result<Vec<u8>> {
        self.batch.snapshot()
    }
    pub(in crate::platform::windows::registry) fn member(&self, index: u32) -> Result<Vec<u8>> {
        self.batch.member(index)
    }
}

fn checked_observation<'batch, 'tx>(
    batch: &'batch StructuralBatch<'tx>,
    state: &crate::trusted_time::State,
    root: &[u8],
    interval: UtcInterval,
) -> Result<TimeCheckedBatch<'batch, 'tx>> {
    let policy = batch.global_policy()?;
    require_observation_policy(state, &policy)?;
    let roles = super::policy::Policy::parse(&batch.role_policy()?, &state.binding)?;
    Ok(TimeCheckedBatch {
        batch,
        state: state.clone(),
        root: root.to_vec(),
        interval,
        role_denied: roles.by_role(),
    })
}

fn with_live_batch(
    batch: &StructuralBatch<'_>,
    source: &LiveTimeReadSet<'_>,
    host: &StartedServiceContext,
    visit: impl FnOnce(&TimeCheckedBatch<'_, '_>) -> Result<()>,
) -> Result<()> {
    // Only the actual pinned native batch supplies the serialized sample.
    let sample = HistoricalSample::parse(&batch.sample()?)?;
    let anchor = source.historical_anchor(host, sample.revision(), sample.head_sha256())?;
    let interval = anchor.verify_sample(host, &sample)?;
    let checked = checked_observation(batch, anchor.state(), anchor.root(), interval)?;
    visit(&checked)?;
    // A visitor can own writable handles. Reauthenticate its historical source.
    anchor.recheck(host)
}

fn require_observation_policy(state: &crate::trusted_time::State, raw: &[u8]) -> Result<()> {
    let evidence = state.evidence.as_ref().ok_or(Error::SourceUnavailable)?;
    require_policy_bytes(&state.binding, evidence.policy.as_bytes(), raw)
}

fn require_policy_bytes(binding: &Binding, expected: &[u8], raw: &[u8]) -> Result<()> {
    if raw != expected {
        return Err(Error::StateCorrupt);
    }
    crate::trusted_time::Policy::parse(raw, binding)?;
    Ok(())
}

pub(in crate::platform::windows::registry) fn visit_in(
    private: &Key,
    tx: &Handle,
    source: &LiveTimeReadSet<'_>,
    host: &StartedServiceContext,
    mut visit: impl FnMut(&TimeCheckedBatch<'_, '_>) -> Result<()>,
) -> Result<HistoryPosition> {
    source.require_metadata_transaction(private, tx)?;
    source.recheck(host)?;
    let initial = genesis(
        OwnerBootstrap::new(&host.context.seed, &host.startup.installation_scope_id)?
            .metadata
            .record_bytes(),
    )?;
    let metadata = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    let head = waterlog::head_bytes_in(&metadata, &initial, tx)?;
    waterlog::visit_structure_in(&metadata, &initial, tx, |batch| {
        with_live_batch(batch, source, host, &mut visit)
    })?;
    // A later visitor may modify the time history used by an earlier batch.
    // The structural pass rechecks waterlog bytes; this second pass separately
    // reauthenticates every consumed historical time source without callbacks.
    waterlog::visit_structure_in(&metadata, &initial, tx, |batch| {
        with_live_batch(batch, source, host, |_| Ok(()))
    })?;
    if waterlog::head_bytes_in(&metadata, &initial, tx)? != head {
        return Err(Error::ScopeConflict);
    }
    source.recheck(host)?;
    Ok(HistoryPosition { head })
}

fn with_member_batch(
    batch: &StructuralBatch<'_>,
    member: &super::super::time::member_history::MemberTimeHistory<'_, '_>,
    visit: impl FnOnce(&TimeCheckedBatch<'_, '_>) -> Result<()>,
) -> Result<()> {
    // The actual bound native batch is the only sample source here.
    let observation = member.historical_observation(&batch.sample()?)?;
    let checked = checked_observation(
        batch,
        observation.state(),
        observation.root(),
        observation.interval(),
    )?;
    visit(&checked)?;
    observation.recheck()
}

/// Historical member DATA only; no running-service context is constructed.
/// Both complete traversals use the member's actual private key and held TxR.
pub(super) fn visit_member_in(
    member: &super::super::time::member_history::MemberTimeHistory<'_, '_>,
    initial: &[u8],
    mut visit: impl FnMut(&TimeCheckedBatch<'_, '_>) -> Result<()>,
) -> Result<HistoryPosition> {
    member.recheck()?;
    let tx = member.transaction();
    let metadata =
        open(member.private().0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    if read(&metadata, "Genesis")? != initial {
        return Err(Error::StateCorrupt);
    }
    let metadata_head = read(&metadata, "Head")?;
    let head = waterlog::head_bytes_in(&metadata, initial, tx)?;
    waterlog::visit_structure_in(&metadata, initial, tx, |batch| {
        with_member_batch(batch, member, &mut visit)
    })?;
    waterlog::visit_structure_in(&metadata, initial, tx, |batch| {
        with_member_batch(batch, member, |_| Ok(()))
    })?;
    if waterlog::head_bytes_in(&metadata, initial, tx)? != head
        || read(&metadata, "Head")? != metadata_head
        || read(&metadata, "Genesis")? != initial
    {
        return Err(Error::ScopeConflict);
    }
    member.recheck()?;
    Ok(HistoryPosition { head })
}

/// Samples come from the actual retained native prefix authenticated by the
/// enclosing Root-member witness. Later native batches are not historical time
/// authority for this ceiling; the structural worker separately pins them.
pub(super) fn visit_captured_in(
    source: &super::super::time::captured_history::CapturedMemberTimeHistory<'_, '_, '_>,
    mut visit: impl FnMut(&TimeCheckedBatch<'_, '_>) -> Result<()>,
) -> Result<HistoryPosition> {
    source.recheck()?;
    let pins = source.metadata_pins();
    let tx = source.transaction();
    let metadata =
        open(source.private().0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    if read(&metadata, "Genesis")? != pins.genesis {
        return Err(Error::StateCorrupt);
    }
    let current_head = read(&metadata, "Head")?;
    let mut with_batch = |batch: &StructuralBatch<'_>, callbacks: bool| -> Result<()> {
        let observation = source.historical_observation(&batch.sample()?)?;
        let checked = checked_observation(
            batch,
            observation.state(),
            observation.root(),
            observation.interval(),
        )?;
        if callbacks {
            visit(&checked)?;
        }
        observation.recheck()
    };
    waterlog::visit_structure_prefix_in(
        &metadata,
        &pins.genesis,
        tx,
        &pins.waterlog_head,
        |batch| with_batch(batch, true),
    )?;
    waterlog::visit_structure_prefix_in(
        &metadata,
        &pins.genesis,
        tx,
        &pins.waterlog_head,
        |batch| with_batch(batch, false),
    )?;
    if read(&metadata, "Genesis")? != pins.genesis || read(&metadata, "Head")? != current_head {
        return Err(Error::ScopeConflict);
    }
    source.recheck()?;
    Ok(HistoryPosition {
        head: pins.waterlog_head.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_global_policy_must_match_the_signed_observations_admission_policy() {
        // Absence never becomes an empty policy or proof of a valid sample.
        let binding = crate::trusted_time::Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-exe-perMachine".into(),
            profile_kind: "production".into(),
            profile_id: "profile".into(),
            genesis_seed_sha256: "1".repeat(64),
            genesis_manifest_sha256: "2".repeat(64),
            original_install_operation_id: "operation".into(),
        };
        let mut policy = crate::trusted_time::Policy::initial(binding.clone()).unwrap();
        let original = json::encode(&policy, false).unwrap();
        assert_eq!(require_policy_bytes(&binding, &original, &original), Ok(()));
        policy.denied_key_ids.push("a".repeat(64));
        let changed = json::encode(&policy, false).unwrap();
        // Two separately valid policies must not be interchangeable for the
        // historical observation under which the original was accepted.
        crate::trusted_time::Policy::parse(&changed, &binding).unwrap();
        assert_eq!(
            require_policy_bytes(&binding, &original, &changed),
            Err(Error::StateCorrupt)
        );
        let mut other = binding;
        other.profile_id = "other-profile".into();
        assert_eq!(
            require_policy_bytes(&other, &original, &original),
            Err(Error::StateCorrupt)
        );
        assert_eq!(
            require_policy_bytes(&other, b"{}", b"{}"),
            Err(Error::StateCorrupt)
        );
    }
}
