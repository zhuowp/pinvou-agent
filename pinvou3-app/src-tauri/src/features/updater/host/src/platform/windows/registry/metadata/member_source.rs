//! Complete read-only CURRENT catalog member metadata observations. This is
//! historical DATA, never online freshness, live time, or Root publication.
//! All visitor results are provisional until the complete product census ends.
use super::super::time::{
    member_history::{MemberTimeHistory, visit_member_histories},
    root_history::RootSignaturePrefix,
};
use super::time_history::HistoryPosition;
use super::*;
use pinvou_upgrade_codec::{Document, InputKind, SchemaCheckedEnvelope, decode_canonical_envelope};
use pinvou_upgrade_metadata_owner::{BootstrapAnchor, BootstrapBinding};
use pinvou_upgrade_verifier::{ActiveMetadataInput, SignatureCheckedTimeResponse};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type ProductGuard = super::super::product_catalog::ProductGuard;

/// Complete validated current source fingerprint DATA, with no caller callback.
pub(in crate::platform::windows::registry) fn fingerprint_members<'prefix, 'tx>(
    seed: &'tx Seed,
    requester: &HostRegistration,
    guard: &'tx ProductGuard,
    tx: &'tx Handle,
    prefix: Option<&'prefix RootSignaturePrefix<'tx>>,
) -> Result<[u8; 32]> {
    census(seed, requester, guard, tx, prefix, |_| Ok(()))
}

/// Private construction binds this view to an actual catalog member source.
/// The index used for complete water replay is ephemeral and is not retained.
pub(in crate::platform::windows::registry) struct MemberMetadataView<'member, 'prefix, 'tx> {
    member: &'member MemberTimeHistory<'prefix, 'tx>,
    initial: Vec<u8>,
    head: Vec<u8>,
    role_raw: Vec<u8>,
    position: HistoryPosition,
    batches: u64,
}

/// Bounded snapshot DATA, not a native-source or active-set capability. Only a
/// Root owner's authenticated enclosing member record can give these historical
/// bytes provenance; complete native prefix replay is still mandatory.
pub(in crate::platform::windows::registry) struct CapturedMetadataPins {
    pub(in crate::platform::windows::registry) bootstrap: Vec<u8>,
    pub(in crate::platform::windows::registry) genesis: Vec<u8>,
    pub(in crate::platform::windows::registry) head: Vec<u8>,
    pub(in crate::platform::windows::registry) waterlog_head: Vec<u8>,
    pub(in crate::platform::windows::registry) role_policy: Vec<u8>,
}

/// Bootstrap/policy and canonical shape only. A historical reader must verify
/// both full native journal prefixes, samples, graphs and waters separately.
pub(in crate::platform::windows::registry) fn validate_captured_pins(
    event: &crate::product_catalog::Event,
    host: &HostRegistration,
    original: &[u8],
    pins: &CapturedMetadataPins,
) -> Result<()> {
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
    let anchor = BootstrapAnchor::new(
        &binding,
        original,
        event.original_root_size,
        &event.original_root_sha256,
    )
    .map_err(|_| Error::StateCorrupt)?;
    anchor
        .check_existing(&pins.bootstrap, original)
        .map_err(|_| Error::StateCorrupt)?;
    if pins.genesis != genesis(anchor.record_bytes())? {
        return Err(Error::StateCorrupt);
    }
    policy::Policy::parse(&pins.role_policy, &Binding::from_host(host))?;
    for raw in [&pins.head, &pins.waterlog_head] {
        let value: serde_json::Value = json::decode(raw, false)?;
        if value.as_object().is_none_or(|object| object.is_empty())
            || json::encode(&value, false)? != *raw
        {
            return Err(Error::StateCorrupt);
        }
    }
    Ok(())
}

pub(in crate::platform::windows::registry) fn visit_metadata_members<'prefix, 'tx>(
    seed: &'tx Seed,
    requester: &HostRegistration,
    guard: &'tx ProductGuard,
    tx: &'tx Handle,
    prefix: Option<&'prefix RootSignaturePrefix<'tx>>,
    mut visitor: impl FnMut(&MemberMetadataView<'_, 'prefix, 'tx>) -> Result<()>,
) -> Result<()> {
    // A later callback can alter an earlier member through another held native
    // handle. Revalidate ALL members without callbacks on both sides and bind
    // every original time/metadata head and policy, rather than only the last.
    let before = census(seed, requester, guard, tx, prefix, |_| Ok(()))?;
    let visited = census(seed, requester, guard, tx, prefix, &mut visitor)?;
    let after = census(seed, requester, guard, tx, prefix, |_| Ok(()))?;
    if before != visited || before != after {
        return Err(Error::ScopeConflict);
    }
    Ok(())
}

fn census<'prefix, 'tx>(
    seed: &'tx Seed,
    requester: &HostRegistration,
    guard: &'tx ProductGuard,
    tx: &'tx Handle,
    prefix: Option<&'prefix RootSignaturePrefix<'tx>>,
    mut visitor: impl FnMut(&MemberMetadataView<'_, 'prefix, 'tx>) -> Result<()>,
) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"pinvou.product-member.current-metadata-census.v1");
    let mut count = 0u64;
    visit_member_histories(seed, requester, guard, tx, prefix, |member| {
        let view = MemberMetadataView::from_member(member)?;
        hash.update(view.fingerprint()?);
        count = count.checked_add(1).ok_or(Error::Unavailable)?;
        visitor(&view)?;
        view.recheck()
    })?;
    hash.update(count.to_be_bytes());
    Ok(hash.finalize().into())
}

impl<'member, 'prefix, 'tx> MemberMetadataView<'member, 'prefix, 'tx> {
    fn from_member(member: &'member MemberTimeHistory<'prefix, 'tx>) -> Result<Self> {
        member.recheck()?;
        let event = member.event();
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
        let anchor = BootstrapAnchor::new(
            &binding,
            member.original_root(),
            event.original_root_size,
            &event.original_root_sha256,
        )
        .map_err(|_| Error::StateCorrupt)?;
        anchor
            .check_existing(
                &read(member.private(), METADATA_BOOTSTRAP)?,
                member.original_root(),
            )
            .map_err(|_| Error::StateCorrupt)?;
        let initial = genesis(anchor.record_bytes())?;
        let head = publication::check_bound_history_in(
            member.private(),
            &initial,
            member.binding(),
            member.transaction(),
        )?;
        let metadata = open(
            member.private().0,
            NAMESPACE,
            false,
            Some(member.transaction()),
        )?
        .ok_or(Error::SetupIncomplete)?;
        let (roles, role_raw) = policy::read_in(&metadata, member.binding())?;
        let context = replay_index::document(&json::encode(
            &serde_json::json!({
                "product":member.binding().product, "component":member.binding().component,
            }),
            false,
        )?)?;
        let mut accumulator = replay::Accumulator::new(&member.source_scope_store())?;
        let position = time_history::visit_member_in(member, &initial, |batch| {
            accumulator.observe(batch, &context)
        })?;
        roles.require_retains(accumulator.required_role_denials())?;
        let batches = accumulator.batches();
        drop(accumulator);
        let view = Self {
            member,
            initial,
            head,
            role_raw,
            position,
            batches,
        };
        view.recheck()?;
        Ok(view)
    }

    pub(in crate::platform::windows::registry) fn member(
        &self,
    ) -> &MemberTimeHistory<'prefix, 'tx> {
        self.member
    }
    pub(in crate::platform::windows::registry) fn batches(&self) -> u64 {
        self.batches
    }

    /// Capture only bounded references from this already authenticated current
    /// source. The Root snapshot owner must bind all five blobs to its member
    /// descriptor in the same TxR; these bytes alone grant no historical trust.
    pub(in crate::platform::windows::registry) fn snapshot_pins(
        &self,
    ) -> Result<CapturedMetadataPins> {
        self.recheck()?;
        let pins = CapturedMetadataPins {
            bootstrap: read(self.member.private(), METADATA_BOOTSTRAP)?,
            genesis: self.initial.clone(),
            head: self.head.clone(),
            waterlog_head: self.position.head_bytes().to_vec(),
            role_policy: self.role_raw.clone(),
        };
        validate_captured_pins(
            self.member.event(),
            self.member.host(),
            self.member.original_root(),
            &pins,
        )?;
        self.recheck()?;
        Ok(pins)
    }

    fn check_pins(&self) -> Result<()> {
        if publication::check_bound_history_in(
            self.member.private(),
            &self.initial,
            self.member.binding(),
            self.member.transaction(),
        )? != self.head
        {
            return Err(Error::ScopeConflict);
        }
        let metadata = open(
            self.member.private().0,
            NAMESPACE,
            false,
            Some(self.member.transaction()),
        )?
        .ok_or(Error::StateCorrupt)?;
        if policy::read_in(&metadata, self.member.binding())?.1 != self.role_raw {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }

    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        self.member.recheck()?;
        self.check_pins()?;
        let mut batches = 0u64;
        let position = time_history::visit_member_in(self.member, &self.initial, |batch| {
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
        self.member.recheck()
    }

    fn fingerprint(&self) -> Result<[u8; 32]> {
        self.recheck()?;
        let mut hash = Sha256::new();
        hash.update(b"pinvou.product-member.current-metadata-pins.v1");
        hash.update(self.member.source_fingerprint()?);
        for raw in [
            &self.initial[..],
            &self.head,
            &self.role_raw,
            self.position.head_bytes(),
        ] {
            hash.update((raw.len() as u64).to_be_bytes());
            hash.update(raw);
        }
        hash.update(self.batches.to_be_bytes());
        Ok(hash.finalize().into())
    }

    /// Stream the exact latest observed complete graph with current deny checks.
    /// Bodies may have expired since observation. Their historical graph/water
    /// proof and exact original-byte provenance were established by construction.
    pub(in crate::platform::windows::registry) fn visit_active(
        &self,
        mut visitor: impl FnMut(&[u8], &Document) -> Result<()>,
    ) -> Result<()> {
        self.recheck()?;
        let global = crate::trusted_time::Policy::parse(
            self.member.current_policy_raw(),
            self.member.binding(),
        )?;
        let roles = policy::Policy::parse(&self.role_raw, self.member.binding())?.by_role();
        let mut found = false;
        let position = time_history::visit_member_in(self.member, &self.initial, |batch| {
            if batch.index() != self.batches {
                return Ok(());
            }
            if found {
                return Err(Error::StateCorrupt);
            }
            found = true;
            let mut visit_original = |raw: Vec<u8>| -> Result<()> {
                let (checked, context) = active_context(
                    &raw,
                    &self.member.binding().product,
                    &self.member.binding().component,
                )?;
                reject_current_denials(
                    &checked,
                    &self.member.current_state().denied_key_ids,
                    &global.denied_key_ids,
                    &roles,
                )?;
                visitor(&raw, &context)
            };
            visit_original(batch.timestamp()?)?;
            visit_original(batch.snapshot()?)?;
            for index in 1..=batch.count() {
                visit_original(batch.member(index)?)?;
            }
            Ok(())
        })?;
        if position != self.position || found != (self.batches != 0) {
            return Err(Error::ScopeConflict);
        }
        self.recheck()
    }

    /// Supplied verified final Root compatibility only. The enclosing owner
    /// still owns complete product census, exact Root binding and atomic commit.
    pub(in crate::platform::windows::registry) fn assert_active_binding(
        &self,
        root: &SignatureCheckedTimeResponse,
    ) -> Result<()> {
        self.visit_active(|raw, expected| {
            root.assert_active_binding(&ActiveMetadataInput::new(raw, expected))
                .map_err(|_| Error::SourceUnavailable)
        })
    }
}

pub(super) fn active_context(
    raw: &[u8],
    product: &str,
    component: &str,
) -> Result<(SchemaCheckedEnvelope, Document)> {
    // This private helper is reached only for originals from the latest graph
    // whose complete signatures, Snapshot references, context and waters passed
    // from_member's Accumulator replay and subsequent original-byte rechecks.
    // Role/scope here preserve that authenticated original context; deriving
    // them from arbitrary incoming bytes would establish no independent trust.
    let checked = decode_canonical_envelope(raw, InputKind::Metadata)
        .map_err(|_| Error::StateCorrupt)?
        .check_full_schema()
        .map_err(|_| Error::StateCorrupt)?;
    let body = checked.envelope().signed().value();
    if body["product"].as_str() != Some(product)
        || body["component"].as_str() != Some(component)
        || !matches!(
            body["role"].as_str(),
            Some("timestamp" | "snapshot" | "target" | "release" | "package")
        )
    {
        return Err(Error::StateCorrupt);
    }
    let expected = replay_index::document(&json::encode(
        &serde_json::json!({
            "role":body["role"], "product":product, "component":component, "scope":body["scope"],
        }),
        false,
    )?)?;
    Ok((checked, expected))
}

pub(super) fn reject_current_denials(
    checked: &SchemaCheckedEnvelope,
    state_global: &[String],
    policy_global: &[String],
    by_role: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    let role = checked.envelope().signed().value()["role"]
        .as_str()
        .ok_or(Error::StateCorrupt)?;
    let role_denied = by_role.get(role).ok_or(Error::StateCorrupt)?;
    for signature in checked.envelope().signatures() {
        for denied in [state_global, policy_global, role_denied] {
            if denied
                .binary_search_by(|id| id.as_str().cmp(signature.key_id()))
                .is_ok()
            {
                return Err(Error::SourceUnavailable);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn timestamp() -> Vec<u8> {
        // Structural schema/context/deny fixture only; no signature proof.
        json::encode(&serde_json::json!({
            "signed":{"protocolVersion":1,"role":"timestamp","product":"pinvou","component":"app",
                "scope":{},"version":1,"issuedAt":1,"expiresAt":2,
                "snapshot":{"role":"snapshot","scope":{},"version":1,"expiresAt":2,
                    "size":1,"envelopeSha256":"b".repeat(64)}},
            "signatures":[{"keyId":"a".repeat(64),"signature":"A".repeat(86)}],
        }), false).unwrap()
    }
    #[test]
    fn active_context_binds_actual_component_without_inventing_body_freshness() {
        let raw = timestamp();
        let (_, expected) = active_context(&raw, "pinvou", "app").unwrap();
        assert_eq!(expected.value()["scope"], serde_json::json!({}));
        assert!(active_context(&raw, "other", "app").is_err());
        assert!(active_context(&raw, "pinvou", "engine").is_err());
        assert!(
            active_context(
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/metadata-component-fixture/root.json"
                )),
                "pinvou",
                "app"
            )
            .is_err()
        );
    }
    #[test]
    fn each_current_global_list_and_only_the_actual_role_deny_is_enforced() {
        let (checked, _) = active_context(&timestamp(), "pinvou", "app").unwrap();
        let mut roles: BTreeMap<String, Vec<String>> =
            ["timestamp", "snapshot", "target", "release", "package"]
                .into_iter()
                .map(|role| (role.into(), Vec::new()))
                .collect();
        let denied = vec!["a".repeat(64)];
        reject_current_denials(&checked, &[], &[], &roles).unwrap();
        assert!(reject_current_denials(&checked, &denied, &[], &roles).is_err());
        assert!(reject_current_denials(&checked, &[], &denied, &roles).is_err());
        roles.insert("package".into(), denied.clone());
        reject_current_denials(&checked, &[], &[], &roles).unwrap();
        roles.insert("timestamp".into(), denied);
        assert!(reject_current_denials(&checked, &[], &[], &roles).is_err());
    }
}
