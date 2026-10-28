//! Per-member Root replay inputs, copied from protected member history in TxR.
//! A snapshot alone conveys no authority: its record digest must be bound to
//! a complete, protected product history and replayed by its transaction owner.
#![allow(dead_code)]

use super::super::product_catalog::exact;
use super::*;
use crate::product_catalog::Event;

#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) static FAIL_AFTER_ENROLLMENT:
    std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u8,
    enrollment: Blob,
    host: Blob,
    original: Blob,
    state: Blob,
    policy: Blob,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    catchup: Option<Blob>,
}

/// Both independently validated lists must be visited for this member. Keeping
/// them separate avoids inventing a combined limit on two valid policies.
pub(in crate::platform::windows::registry) struct MemberDenials {
    state: Vec<String>,
    policy: Vec<String>,
    policy_raw: Vec<u8>,
}
impl MemberDenials {
    pub(super) fn matches_policy(&self, evidence: &Evidence) -> bool {
        self.policy_raw == evidence.policy.as_bytes()
    }
    pub(in crate::platform::windows::registry) fn visit(
        &self,
        visitor: &mut dyn FnMut(&[String]) -> Result<()>,
    ) -> Result<()> {
        visitor(&self.state)?;
        visitor(&self.policy)
    }
}

/// Capture only the actual member selected by the authenticated catalog visit.
/// All keys are created in the caller's transaction and must be discarded on
/// any failure. This function never commits and does not authorize promotion.
pub(in crate::platform::windows::registry) fn capture_in(
    parent: &Key,
    name: &str,
    seed: &Seed,
    event: &Event,
    host: &HostRegistration,
    tx: &Handle,
) -> Result<Vec<u8>> {
    capture_state_in(parent, name, seed, event, host, tx, None)
}

/// Capture an already authenticated product member from the same guarded
/// product-history transaction. No caller-provided state is accepted.
pub(super) fn capture_history_in(
    parent: &Key,
    name: &str,
    seed: &Seed,
    event: &Event,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
    verified: &super::root_history::VerifiedHistory<'_>,
) -> Result<Vec<u8>> {
    capture_state_in(parent, name, seed, event, host, tx, Some((guard, verified)))
}

/// Validate the issuer's proposed transition in the publishing transaction,
/// then capture its protected pre-state. This avoids including the resulting
/// product Head in the bytes from which that same Head is computed.
pub(super) fn capture_issuer_in(
    parent: &Key,
    name: &str,
    seed: &Seed,
    event: &Event,
    host: &HostRegistration,
    tx: &Handle,
    proposed: &State,
) -> Result<Vec<u8>> {
    if event.profile_id != seed.profile_id {
        return Err(Error::ScopeConflict);
    }
    let path = format!(
        "Software\\Pinvou\\{}\\{}\\private",
        seed.updater_leaf(),
        event.profile_id
    );
    let private = open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let current = state_in(&private, host, Some(tx))?;
    current
        .state
        .transition(proposed, &current.raw, &current.original_root)?;
    // Bind the pre-state. Including the proposed state would make its own
    // product Head reference part of the digest that defines that Head.
    capture_state_in(parent, name, seed, event, host, tx, None)
}

fn capture_state_in(
    parent: &Key,
    name: &str,
    seed: &Seed,
    event: &Event,
    host: &HostRegistration,
    tx: &Handle,
    history: Option<(
        &super::super::product_catalog::ProductGuard,
        &super::root_history::VerifiedHistory<'_>,
    )>,
) -> Result<Vec<u8>> {
    let path = format!(
        "Software\\Pinvou\\{}\\{}\\private",
        seed.updater_leaf(),
        event.profile_id
    );
    let private = open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let snapshot = if let Some((guard, verified)) = history {
        state_in_product(&private, host, seed, guard, tx, verified)?
    } else {
        state_in(&private, host, Some(tx))?
    };
    let state = &snapshot.state;
    if state
        .policy_fault
        .as_ref()
        .is_some_and(PolicyFault::is_active)
    {
        return Err(Error::PrerequisiteUnavailable);
    }
    let time = open(private.0, NAMESPACE, false, Some(tx))?.ok_or(Error::SetupIncomplete)?;
    let policy = policy_in(&time, &state.binding)?;
    let enrollment = json::encode(event, false)?;
    let host_raw = json::encode(host, false)?;
    let state_raw = json::encode(&header(state), false)?;
    let catchup = if history.is_some() && event.profile_id == seed.profile_id {
        let position = super::root_history::staged_position(
            &super::root_history::protected_head_in(seed, tx)?,
        )?;
        if state.product_root.as_ref() != Some(&position) {
            let incarnation = Incarnation::from_host(host)?;
            check_catchup_in(&time, &snapshot, incarnation, &position)?;
            Some(read(&time, "Catchup")?)
        } else {
            None
        }
    } else {
        None
    };
    let record = Record {
        version: 1,
        enrollment: Blob::of(&enrollment),
        host: Blob::of(&host_raw),
        original: Blob::of(&snapshot.original_root),
        state: Blob::of(&state_raw),
        policy: Blob::of(&policy.raw),
        catchup: catchup.as_ref().map(|raw| Blob::of(raw)),
    };
    let raw = json::encode(&record, false)?;
    let key = create(parent.0, name, tx, false, true)?;
    let state_key = create(key.0, "state", tx, false, true)?;
    if write_record(&state_key, state)? != state_raw {
        return Err(Error::StateCorrupt);
    }
    write(&key, "Enrollment", &enrollment)?;
    #[cfg(feature = "metadata-component-tests")]
    if FAIL_AFTER_ENROLLMENT.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(Error::Unavailable);
    }
    write(&key, "Host", &host_raw)?;
    write(&key, "Original", &snapshot.original_root)?;
    write(&key, "Policy", &policy.raw)?;
    if let Some(catchup) = catchup {
        write(&key, "Catchup", &catchup)?;
    }
    write(&key, "Record", &raw)?;
    read_shape_in(&key, tx, &raw)?.replay_input()?;
    Ok(raw)
}

/// Decode a snapshot after its exact record has been authenticated by the
/// product history owner. This is data for replay, not a current policy grant.
pub(in crate::platform::windows::registry) fn read_in(
    key: &Key,
    tx: &Handle,
    expected: &[u8],
) -> Result<MemberDenials> {
    Ok(read_verified_in(key, tx, expected)?.0)
}

/// Return the authenticated state as well as both independent deny lists.
/// The product history owner must authenticate the enclosing record digest.
pub(super) fn read_verified_in(
    key: &Key,
    tx: &Handle,
    expected: &[u8],
) -> Result<(MemberDenials, State)> {
    read_shape_in(key, tx, expected)?.verify_legacy()
}

// Structural decoding is not authority. Only the history owner may interpret
// these bytes after binding the record to its authenticated batch position.
pub(super) struct UnverifiedMember {
    denials: MemberDenials,
    state: State,
    original: Vec<u8>,
    catchup: Option<CatchupRecord>,
}
impl UnverifiedMember {
    pub(super) fn catchup(&self) -> Option<&CatchupRecord> {
        self.catchup.as_ref()
    }
    /// Intermediate replay input only. Compact evidence must still be checked
    /// against an ancestor after the whole protected history is replayed.
    pub(super) fn replay_input(self) -> Result<(MemberDenials, State)> {
        if self.state.product_root.is_some() {
            self.state.validate_compact_shape()?;
            Ok((self.denials, self.state))
        } else {
            self.verify_legacy()
        }
    }
    pub(super) fn verify_legacy(self) -> Result<(MemberDenials, State)> {
        self.state.validate(&self.original)?;
        Ok((self.denials, self.state))
    }
}

pub(super) fn read_shape_in(key: &Key, tx: &Handle, expected: &[u8]) -> Result<UnverifiedMember> {
    exact(key, false, &["state"])?;
    let raw = read(key, "Record")?;
    if raw != expected {
        return Err(Error::StateCorrupt);
    }
    let record: Record = json::decode(&raw, false)?;
    if record.version != 1 || json::encode(&record, false)? != raw {
        return Err(Error::StateCorrupt);
    }
    let mut values = vec!["Enrollment", "Host", "Original", "Policy", "Record"];
    if record.catchup.is_some() {
        values.push("Catchup");
    }
    exact(key, true, &values)?;
    let catchup = record
        .catchup
        .as_ref()
        .map(|blob| {
            let raw = blob.read(key, "Catchup", json::RECORD_MAX)?;
            let value: CatchupRecord = json::decode(&raw, false)?;
            if json::encode(&value, false)? != raw {
                return Err(Error::StateCorrupt);
            }
            Ok(value)
        })
        .transpose()?;
    let enrollment_raw = record
        .enrollment
        .read(key, "Enrollment", json::RECORD_MAX)?;
    let event = Event::parse(&enrollment_raw)?;
    let host_raw = record.host.read(key, "Host", json::RECORD_MAX)?;
    let host: HostRegistration = json::decode(&host_raw, false)?;
    if json::encode(&host, false)? != host_raw
        || host.profile_kind != event.kind
        || host.profile_id != event.profile_id
        || host.product != event.product
        || host.component != event.component
        || host.target_key != event.target_key
        || host.installation_scope_id != event.scope
        || host.genesis_seed_sha256 != event.seed_sha256
        || host.initial_root_reference.sha256 != event.original_root_sha256
        || host.initial_root_reference.size != event.original_root_size
    {
        return Err(Error::StateCorrupt);
    }
    let original = record.original.read(key, "Original", json::RECORD_MAX)?;
    if original.len() as u64 != event.original_root_size
        || json::sha256(&original) != event.original_root_sha256
    {
        return Err(Error::StateCorrupt);
    }
    let state_key = open(key.0, "state", false, Some(tx))?.ok_or(Error::StateCorrupt)?;
    exact(&state_key, false, &[])?;
    let state_raw = record.state.read(&state_key, "Record", json::RECORD_MAX)?;
    let state_header: Header = json::decode(&state_raw, false)?;
    root_capacity(&state_header.roots)?;
    let mut values = vec!["Record".to_string()];
    values.extend((0..state_header.roots.len()).map(|i| format!("Root-{i}")));
    if state_header.evidence.is_some() {
        values.extend(["Request", "Response", "PolicyEvidence"].map(str::to_string));
    }
    let names: Vec<&str> = values.iter().map(String::as_str).collect();
    exact(&state_key, true, &names)?;
    let state = read_record_shape(&state_key, &state_raw)?;
    if state.binding != Binding::from_host(&host)
        || state
            .policy_fault
            .as_ref()
            .is_some_and(PolicyFault::is_active)
    {
        return Err(Error::StateCorrupt);
    }
    let policy_raw = record.policy.read(key, "Policy", json::RECORD_MAX)?;
    let policy = Policy::parse(&policy_raw, &state.binding)?;
    let denials = MemberDenials {
        state: state.denied_key_ids.clone(),
        policy: policy.denied_key_ids,
        policy_raw,
    };
    Ok(UnverifiedMember {
        denials,
        state,
        original,
        catchup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_visits_each_independent_list_without_a_union_limit() {
        let denials = MemberDenials {
            state: (0..4096).map(|i| format!("{i:064x}")).collect(),
            policy: (4096..8192).map(|i| format!("{i:064x}")).collect(),
            policy_raw: Vec::new(),
        };
        let mut observed = Vec::new();
        denials
            .visit(&mut |ids| {
                observed.push(ids.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(observed, vec![denials.state, denials.policy]);
        assert_eq!(observed.iter().map(Vec::len).sum::<usize>(), 8192);
    }

    #[test]
    fn visitor_failure_stops_and_propagates_at_each_list() {
        let denials = MemberDenials {
            state: vec!["state".into()],
            policy: vec!["policy".into()],
            policy_raw: Vec::new(),
        };
        let mut calls = 0;
        let result = denials.visit(&mut |_| {
            calls += 1;
            Err(Error::Unavailable)
        });
        assert_eq!(result, Err(Error::Unavailable));
        assert_eq!(calls, 1);
        calls = 0;
        let result = denials.visit(&mut |_| {
            calls += 1;
            if calls == 2 {
                Err(Error::ScopeConflict)
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(Error::ScopeConflict));
        assert_eq!(calls, 2);
    }
}
