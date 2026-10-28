//! Protected time-owner DATA and retained cryptographic evidence. No parsed
//! record grants UTC continuity, cleanup completion or execution permission.
#[cfg(test)]
#[path = "../../protocol/verify/tests/support/long_root_fixture.rs"]
mod long_root_fixture;
mod policy_fault;
use crate::{
    error::{Error, Result},
    identity::ProcessSelector,
    json,
    monotonic::CounterObservation,
    registration::HostRegistration,
};
use pinvou_upgrade_codec::{Document, InputKind, decode_canonical_envelope};
use pinvou_upgrade_verifier::{SuppliedTimeObservation, verify_time_response_source};
pub(crate) use policy_fault::PolicyFault;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn fingerprint_root(hasher: &mut Sha256, index: usize, bytes: &[u8]) {
    hasher.update((index as u64).to_be_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Binding {
    pub(crate) installation_scope_id: String,
    pub(crate) product: String,
    pub(crate) component: String,
    pub(crate) target_key: String,
    pub(crate) profile_kind: String,
    pub(crate) profile_id: String,
    pub(crate) genesis_seed_sha256: String,
    pub(crate) genesis_manifest_sha256: String,
    pub(crate) original_install_operation_id: String,
}
impl Binding {
    pub(crate) fn from_host(host: &HostRegistration) -> Self {
        Self {
            installation_scope_id: host.installation_scope_id.clone(),
            product: host.product.clone(),
            component: host.component.clone(),
            target_key: host.target_key.clone(),
            profile_kind: host.profile_kind.clone(),
            profile_id: host.profile_id.clone(),
            genesis_seed_sha256: host.genesis_seed_sha256.clone(),
            genesis_manifest_sha256: host.genesis_manifest_sha256.clone(),
            original_install_operation_id: host.original_install_operation_id.clone(),
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if ![
            &self.product,
            &self.component,
            &self.target_key,
            &self.profile_kind,
            &self.profile_id,
        ]
        .iter()
        .all(|s| json::identifier(s))
            || self.installation_scope_id.is_empty()
            || self.installation_scope_id.len() > 128
            || self.original_install_operation_id.is_empty()
            || self.original_install_operation_id.len() > 128
            || !json::digest(&self.genesis_seed_sha256)
            || !json::digest(&self.genesis_manifest_sha256)
        {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Incarnation {
    pub(crate) host_epoch: u64,
    pub(crate) instance_nonce: String,
    pub(crate) process: ProcessSelector,
}
impl Incarnation {
    pub(crate) fn from_host(host: &HostRegistration) -> Result<Self> {
        let a = host
            .startup_attestation
            .as_ref()
            .ok_or(Error::SetupIncomplete)?;
        let value = Self {
            host_epoch: host.host_epoch,
            instance_nonce: a.instance_nonce.clone(),
            process: ProcessSelector {
                process_id: a.process_id,
                creation_file_time: a.creation_file_time,
            },
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.host_epoch == 0
            || self.host_epoch > json::SAFE_MAX
            || !json::digest(&self.instance_nonce)
        {
            return Err(Error::StateCorrupt);
        }
        self.process.validate().map_err(|_| Error::StateCorrupt)
    }
}
/// Protected per-original Policy DATA. Only fresh original enrollment writes the
/// approved initial limits; reads never supply a fallback for missing policy.
/// Later administrative changes cannot reset persisted time or budget state.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Policy {
    pub(crate) protocol_version: u8,
    pub(crate) binding: Binding,
    pub(crate) max_round_trip_ms: u64,
    pub(crate) max_uncertainty_ms: u64,
    pub(crate) denied_key_ids: Vec<String>,
}
impl Policy {
    pub(crate) fn initial(binding: Binding) -> Result<Self> {
        binding.validate()?;
        Ok(Self {
            protocol_version: 1,
            binding,
            max_round_trip_ms: 30_000,
            max_uncertainty_ms: 1_000,
            denied_key_ids: Vec::new(),
        })
    }
    pub(crate) fn parse(bytes: &[u8], binding: &Binding) -> Result<Self> {
        let p: Self = json::decode(bytes, false)?;
        if p.protocol_version != 1
            || p.binding != *binding
            || p.max_round_trip_ms > json::SAFE_MAX
            || p.max_uncertainty_ms > json::SAFE_MAX
            || json::encode(&p, false)? != bytes
        {
            return Err(Error::StateCorrupt);
        }
        p.binding.validate()?;
        check_denied(&p.denied_key_ids)?;
        Ok(p)
    }
}
fn check_denied(ids: &[String]) -> Result<()> {
    if ids.len() > 4096
        || ids.iter().any(|s| !json::digest(s))
        || ids.windows(2).any(|a| a[0] >= a[1])
    {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

/// Decimal strings preserve all native u64 ticks; safe-JSON numbers are used
/// only after checked enclosing millisecond conversion in the existing module.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CounterEvidence {
    interrupt_before: String,
    awake_before: String,
    awake_after: String,
    interrupt_after: String,
}
impl CounterEvidence {
    pub(crate) fn from_data(c: CounterObservation) -> Self {
        Self {
            interrupt_before: c.suspend_inclusive().earliest_100ns().to_string(),
            interrupt_after: c.suspend_inclusive().latest_100ns().to_string(),
            awake_before: c.awake().earliest_100ns().to_string(),
            awake_after: c.awake().latest_100ns().to_string(),
        }
    }
    pub(crate) fn data(&self) -> Result<CounterObservation> {
        fn ticks(s: &str) -> Result<u64> {
            if s.is_empty()
                || s.len() > 20
                || s.len() > 1 && s.starts_with('0')
                || !s.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Error::StateCorrupt);
            }
            s.parse().map_err(|_| Error::StateCorrupt)
        }
        CounterObservation::from_bracket(
            ticks(&self.interrupt_before)?,
            ticks(&self.awake_before)?,
            ticks(&self.awake_after)?,
            ticks(&self.interrupt_after)?,
        )
        .map_err(|_| Error::StateCorrupt)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Evidence {
    pub(crate) incarnation: Incarnation,
    pub(crate) request: String,
    pub(crate) response: String,
    pub(crate) sent: CounterEvidence,
    pub(crate) received: CounterEvidence,
    pub(crate) policy: String,
    pub(crate) floor_before: u64,
    pub(crate) base_root_count: usize,
    pub(crate) denied_key_ids: Vec<String>,
    pub(crate) earliest: u64,
    pub(crate) latest: u64,
}
impl Evidence {
    /// Check an additional independently protected deny list against this
    /// batch's successors and signed time response, using the already accepted
    /// predecessor as the trust anchor without re-denying its old signatures.
    /// The caller must first verify this evidence and authenticate the list.
    pub(crate) fn check_additional_denied(
        &self,
        binding: &Binding,
        original: &[u8],
        roots: &[String],
        denied: &[String],
    ) -> Result<()> {
        check_denied(denied)?;
        let policy = Policy::parse(self.policy.as_bytes(), binding)?;
        let sent = self.sent.data()?;
        let received = self.received.data()?;
        received
            .elapsed_since(sent)
            .map_err(|_| Error::StateCorrupt)?;
        let request = Document::parse(self.request.as_bytes(), InputKind::Credential)
            .map_err(|_| Error::StateCorrupt)?
            .time_request_shape()
            .map_err(|_| Error::StateCorrupt)?;
        if self.base_root_count > roots.len() {
            return Err(Error::StateCorrupt);
        }
        let base = if self.base_root_count == 0 {
            original
        } else {
            roots[self.base_root_count - 1].as_bytes()
        };
        let successors = &roots[self.base_root_count..];
        verify_time_response_source(
            self.response.as_bytes(),
            base,
            successors.len(),
            |index| Ok(std::borrow::Cow::Borrowed(successors[index].as_bytes())),
            &request,
            SuppliedTimeObservation {
                sent_monotonic_millis: sent.suspend_inclusive().floor_millis()?,
                received_monotonic_millis: received.suspend_inclusive().ceil_millis()?,
                max_round_trip_millis: policy.max_round_trip_ms,
                max_uncertainty_millis: policy.max_uncertainty_ms,
                trusted_time_floor_millis: self.floor_before,
            },
            denied,
        )
        .map_err(|_| Error::ScopeConflict)?;
        Ok(())
    }
    pub(crate) fn verify(
        &self,
        binding: &Binding,
        original: &[u8],
        roots: &[String],
    ) -> Result<()> {
        self.verify_source(binding, original, roots.len(), |index| {
            Ok(std::borrow::Cow::Borrowed(roots[index].as_bytes()))
        })
    }

    /// Verify one historical evidence batch using original Root objects read
    /// on demand. The caller owns source identity, transaction/snapshot
    /// stability and its exact count; this function grants no storage trust.
    /// The overlapping Root bytes are compared across the two passes.
    /// Source failures remain failures, never an end-of-history marker.
    pub(crate) fn verify_source<'a>(
        &self,
        binding: &Binding,
        original: &[u8],
        count: usize,
        mut read: impl FnMut(usize) -> Result<std::borrow::Cow<'a, [u8]>>,
    ) -> Result<()> {
        self.incarnation.validate()?;
        let policy = Policy::parse(self.policy.as_bytes(), binding)?;
        check_denied(&self.denied_key_ids)?;
        if !policy
            .denied_key_ids
            .iter()
            .all(|id| self.denied_key_ids.contains(id))
        {
            return Err(Error::StateCorrupt);
        }
        let sent = self.sent.data()?;
        let received = self.received.data()?;
        received
            .elapsed_since(sent)
            .map_err(|_| Error::StateCorrupt)?;
        let request = Document::parse(self.request.as_bytes(), InputKind::Credential)
            .map_err(|_| Error::StateCorrupt)?
            .time_request_shape()
            .map_err(|_| Error::StateCorrupt)?;
        if request.canonical_bytes() != self.request.as_bytes()
            || request.product() != binding.product
            || request.component() != binding.component
        {
            return Err(Error::StateCorrupt);
        }
        if self.base_root_count > count {
            return Err(Error::StateCorrupt);
        }
        let observation = SuppliedTimeObservation {
            sent_monotonic_millis: sent.suspend_inclusive().floor_millis()?,
            received_monotonic_millis: received.suspend_inclusive().ceil_millis()?,
            max_round_trip_millis: policy.max_round_trip_ms,
            max_uncertainty_millis: policy.max_uncertainty_ms,
            trusted_time_floor_millis: self.floor_before,
        };
        // Preserve source I/O errors separately from verifier failures. Neither
        // missing data nor an unavailable source may become an empty chain.
        let mut source_error = None;
        let first_checked = self.base_root_count.saturating_sub(1);
        let mut first_fingerprint = Sha256::new();
        let checked = verify_time_response_source(
            self.response.as_bytes(),
            original,
            count,
            |index| {
                read(index)
                    .map(|bytes| {
                        if index >= first_checked {
                            fingerprint_root(&mut first_fingerprint, index, &bytes);
                        }
                        bytes
                    })
                    .map_err(|error| {
                        source_error = Some(error);
                        pinvou_upgrade_verifier::TimeVerificationError::InvalidObservation
                    })
            },
            &request,
            observation,
            &[],
        );
        if let Some(error) = source_error {
            return Err(error);
        }
        let checked = checked.map_err(|_| Error::StateCorrupt)?;
        // Authenticate retained lineage without retroactively revoking an
        // already protected historical Root. Apply current known deny to the
        // actual protected predecessor + every newly accepted successor and
        // the time signature. transition() binds this predecessor to old state.
        let mut second_fingerprint = Sha256::new();
        let base = if self.base_root_count == 0 {
            std::borrow::Cow::Borrowed(original)
        } else {
            let index = self.base_root_count - 1;
            let bytes = read(index)?;
            fingerprint_root(&mut second_fingerprint, index, &bytes);
            bytes
        };
        let mut source_error = None;
        let result = verify_time_response_source(
            self.response.as_bytes(),
            &base,
            count - self.base_root_count,
            |index| {
                let index = self.base_root_count + index;
                read(index)
                    .map(|bytes| {
                        fingerprint_root(&mut second_fingerprint, index, &bytes);
                        bytes
                    })
                    .map_err(|error| {
                        source_error = Some(error);
                        pinvou_upgrade_verifier::TimeVerificationError::InvalidObservation
                    })
            },
            &request,
            observation,
            &self.denied_key_ids,
        );
        if let Some(error) = source_error {
            return Err(error);
        }
        result.map_err(|_| Error::StateCorrupt)?;
        if first_fingerprint.finalize() != second_fingerprint.finalize() {
            return Err(Error::StateCorrupt);
        }
        if checked.earliest_millis() != self.earliest || checked.latest_millis() != self.latest {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}

/// One historical advancement and its actual profile binding. The caller
/// supplies its authenticated member deny snapshots separately during replay.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProductRootBatch {
    pub(crate) binding: Binding,
    pub(crate) evidence: Evidence,
    pub(crate) successor_count: usize,
}

/// A streaming replay cursor. The protected owner must supply the exact original,
/// ordered batches, profile bindings and complete member snapshots from one
/// stable authenticated storage view. `finish` must receive that view's protected
/// head count and hash; a caller-provided unprotected head proves nothing.
/// Bootstrap must first verify the original Root's self-signature threshold and
/// exact pinned bytes. The storage reader must enforce per-object input limits
/// before deserialization; checks here cannot undo an earlier allocation.
/// Success grants no time continuity, root promotion or execution authority.
pub(crate) struct ProductRootReplay {
    head: String,
    root_count: usize,
    batch_count: u64,
    latest_issue: u64,
    product: String,
}
fn root_issue(envelope: &pinvou_upgrade_codec::CanonicalEnvelopeShape) -> Result<u64> {
    let value = envelope.signed().value()["issuedAt"]
        .as_f64()
        .filter(|n| *n >= 0.0 && *n <= json::SAFE_MAX as f64 && n.fract() == 0.0)
        .ok_or(Error::StateCorrupt)?;
    Ok(value as u64)
}
pub(crate) fn root_issue_bytes(raw: &[u8]) -> Result<u64> {
    let envelope =
        decode_canonical_envelope(raw, InputKind::Metadata).map_err(|_| Error::StateCorrupt)?;
    root_issue(&envelope)
}
pub(crate) fn check_history_time_bound(latest_issue: u64, earliest: u64) -> Result<()> {
    if earliest < latest_issue {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}
impl ProductRootReplay {
    pub(crate) fn new(product: &str, original: &str) -> Result<Self> {
        if original.len() > json::RECORD_MAX || !json::identifier(product) {
            return Err(Error::StateCorrupt);
        }
        let root = decode_canonical_envelope(original.as_bytes(), InputKind::Metadata)
            .map_err(|_| Error::StateCorrupt)?;
        let issue = root_issue(&root)?;
        if root.signed().value()["product"] != product {
            return Err(Error::StateCorrupt);
        }
        Ok(Self {
            head: original.into(),
            root_count: 0,
            batch_count: 0,
            latest_issue: issue,
            product: product.into(),
        })
    }
    pub(crate) fn advance(
        &mut self,
        batch: &ProductRootBatch,
        mut read_root: impl FnMut(usize) -> Result<Vec<u8>>,
        mut visit_members: impl FnMut(&mut dyn FnMut(&[String]) -> Result<()>) -> Result<()>,
    ) -> Result<()> {
        // Bound each object before copying or parsing it; independent Root
        // originals are streamed rather than treated as one JSON array.
        if batch.binding.product != self.product
            || batch.evidence.base_root_count != self.root_count
            || batch.successor_count == 0
            || batch.evidence.request.len() > json::FRAME_MAX
            || batch.evidence.response.len() > json::FRAME_MAX
            || batch.evidence.policy.len() > json::RECORD_MAX
        {
            return Err(Error::StateCorrupt);
        }
        batch.binding.validate()?;
        batch.evidence.incarnation.validate()?;
        check_denied(&batch.evidence.denied_key_ids)?;
        batch.evidence.sent.data()?;
        batch.evidence.received.data()?;
        let mut evidence = batch.evidence.clone();
        evidence.base_root_count = 0;
        let mut latest_issue = self.latest_issue;
        let mut fingerprint = Sha256::new();
        let mut reads = 0usize;
        let mut head = None;
        evidence.verify_source(
            &batch.binding,
            self.head.as_bytes(),
            batch.successor_count,
            |index| {
                let raw = read_root(index)?;
                if raw.len() > json::RECORD_MAX {
                    return Err(Error::StateCorrupt);
                }
                if reads < batch.successor_count {
                    if index != reads {
                        return Err(Error::StateCorrupt);
                    }
                    let envelope = decode_canonical_envelope(&raw, InputKind::Metadata)
                        .map_err(|_| Error::StateCorrupt)?;
                    latest_issue = latest_issue.max(root_issue(&envelope)?);
                    fingerprint_root(&mut fingerprint, index, &raw);
                    if index + 1 == batch.successor_count {
                        head = Some(raw.clone());
                    }
                }
                reads = reads.checked_add(1).ok_or(Error::Unavailable)?;
                Ok(std::borrow::Cow::Owned(raw))
            },
        )?;
        let fingerprint = fingerprint.finalize();
        let response =
            decode_canonical_envelope(evidence.response.as_bytes(), InputKind::Credential)
                .map_err(|_| Error::StateCorrupt)?;
        let mut member_error = None;
        let visit_result = visit_members(&mut |ids| {
            let result = (|| {
                check_denied(ids)?;
                if ids.is_empty() {
                    return Ok(());
                }
                let mut denied = response.signatures().iter().any(|signature| {
                    ids.binary_search_by(|id| id.as_str().cmp(signature.key_id()))
                        .is_ok()
                });
                let mut observed = Sha256::new();
                for index in 0..batch.successor_count {
                    let raw = read_root(index)?;
                    if raw.len() > json::RECORD_MAX {
                        return Err(Error::StateCorrupt);
                    }
                    fingerprint_root(&mut observed, index, &raw);
                    let envelope = decode_canonical_envelope(&raw, InputKind::Metadata)
                        .map_err(|_| Error::StateCorrupt)?;
                    denied |= envelope.signatures().iter().any(|signature| {
                        ids.binary_search_by(|id| id.as_str().cmp(signature.key_id()))
                            .is_ok()
                    });
                }
                if observed.finalize() != fingerprint {
                    return Err(Error::StateCorrupt);
                }
                if denied {
                    return Err(Error::ScopeConflict);
                }
                Ok(())
            })();
            if result.is_err() && member_error.is_none() {
                member_error = Some(result);
            }
            result
        });
        if let Some(error) = member_error {
            return error;
        }
        visit_result?;
        if latest_issue > evidence.earliest {
            return Err(Error::StateCorrupt);
        }
        let root_count = self
            .root_count
            .checked_add(batch.successor_count)
            .ok_or(Error::StateCorrupt)?;
        let batch_count = self.batch_count.checked_add(1).ok_or(Error::StateCorrupt)?;
        self.head =
            String::from_utf8(head.ok_or(Error::StateCorrupt)?).map_err(|_| Error::StateCorrupt)?;
        self.root_count = root_count;
        self.batch_count = batch_count;
        self.latest_issue = latest_issue;
        Ok(())
    }
    pub(crate) fn finish(
        &self,
        expected_batches: u64,
        expected_roots: usize,
        expected_head_sha256: &str,
    ) -> Result<()> {
        if self.batch_count != expected_batches
            || self.root_count != expected_roots
            || !json::digest(expected_head_sha256)
            || json::sha256(self.head.as_bytes()) != expected_head_sha256
        {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
    /// Return the replayed Root only after checking the authenticated head
    /// facts. A caller must still retain and recheck its protected read set.
    pub(crate) fn finish_root(
        &self,
        expected_batches: u64,
        expected_roots: usize,
        expected_head_sha256: &str,
    ) -> Result<&[u8]> {
        self.finish(expected_batches, expected_roots, expected_head_sha256)?;
        Ok(self.head.as_bytes())
    }
    /// The maximum issuance time belongs to the same authenticated prefix as
    /// the returned Root, not merely to the last Root in that prefix.
    pub(crate) fn finish_latest_issue(
        &self,
        expected_batches: u64,
        expected_roots: usize,
        expected_head_sha256: &str,
    ) -> Result<u64> {
        self.finish(expected_batches, expected_roots, expected_head_sha256)?;
        Ok(self.latest_issue)
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Unknown,
    CleanupPending,
    CleanupVerifiedZero,
}
/// Exact protected product history position associated with this member's
/// time evidence. These bytes are only a reference, never authentication.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProductRootPosition {
    pub(crate) head_sha256: String,
    pub(crate) root_sha256: String,
    pub(crate) batch: u64,
    pub(crate) root_count: u64,
}
impl ProductRootPosition {
    fn validate(&self) -> Result<()> {
        if !json::digest(&self.head_sha256)
            || !json::digest(&self.root_sha256)
            || self.batch > json::SAFE_MAX
            || self.root_count > json::SAFE_MAX
            || (self.batch == 0) != (self.root_count == 0)
            || self.batch > self.root_count
        {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct State {
    pub(crate) protocol_version: u8,
    pub(crate) binding: Binding,
    pub(crate) revision: u64,
    pub(crate) previous_sha256: Option<String>,
    pub(crate) incarnation: Option<Incarnation>,
    pub(crate) status: Status,
    pub(crate) cleanup_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) policy_fault: Option<PolicyFault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) zero_retention: Option<crate::retention_custody::ZeroRetentionReference>,
    pub(crate) floor: Option<u64>,
    /// Exact canonical successors, starting at immutable original Root + 1.
    pub(crate) roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) product_root: Option<ProductRootPosition>,
    pub(crate) denied_key_ids: Vec<String>,
    pub(crate) evidence: Option<Evidence>,
}
impl State {
    pub(crate) fn genesis(binding: Binding, original: &[u8]) -> Result<Self> {
        root_version(original, &binding.product)?;
        let state = Self {
            protocol_version: 1,
            binding,
            revision: 1,
            previous_sha256: None,
            incarnation: None,
            status: Status::Unknown,
            cleanup_pending: true,
            policy_fault: None,
            zero_retention: None,
            floor: None,
            roots: Vec::new(),
            product_root: None,
            denied_key_ids: Vec::new(),
            evidence: None,
        };
        state.validate(original)?;
        Ok(state)
    }
    /// Pure eligibility DATA only. The native live source must additionally
    /// authenticate the actual store, live SCM incarnation and fresh counters.
    pub(crate) fn anchor_for_live(
        &self,
        actual_policy: &[u8],
        incarnation: &Incarnation,
    ) -> Result<&Evidence> {
        match (
            self.status,
            self.cleanup_pending,
            self.zero_retention.is_some(),
        ) {
            (Status::CleanupPending, true, false) | (Status::CleanupVerifiedZero, false, true) => {}
            _ => return Err(Error::SourceUnavailable),
        }
        let evidence = self.evidence.as_ref().ok_or(Error::SourceUnavailable)?;
        if self.incarnation.as_ref() != Some(incarnation) || evidence.incarnation != *incarnation {
            return Err(Error::ServiceIdentityRefused);
        }
        // Even a loosening or exact semantic rewrite requires a fresh anchor;
        // this source never borrows new policy into an old signed observation.
        Policy::parse(actual_policy, &self.binding)?;
        if actual_policy != evidence.policy.as_bytes()
            || self.denied_key_ids != evidence.denied_key_ids
        {
            return Err(Error::SourceUnavailable);
        }
        if self.floor != Some(evidence.earliest) {
            return Err(Error::StateCorrupt);
        }
        Ok(evidence)
    }
    pub(crate) fn current_root<'a>(&'a self, original: &'a [u8]) -> &'a [u8] {
        self.roots.last().map_or(original, |s| s.as_bytes())
    }
    pub(crate) fn parse(raw: &[u8], original: &[u8]) -> Result<Self> {
        let s: Self = json::decode(raw, false)?;
        if json::encode(&s, false)? != raw {
            return Err(Error::StateCorrupt);
        }
        s.validate(original)?;
        Ok(s)
    }
    pub(crate) fn validate(&self, original: &[u8]) -> Result<()> {
        self.validate_common()?;
        // A detached state cannot authenticate a product history reference.
        // The protected owner must validate it with the same locked read set.
        if self.product_root.is_some() {
            return Err(Error::PrerequisiteUnavailable);
        }
        let mut version = root_version(original, &self.binding.product)?;
        for root in &self.roots {
            let next = root_version(root.as_bytes(), &self.binding.product)?;
            if version.checked_add(1) != Some(next) {
                return Err(Error::StateCorrupt);
            }
            version = next;
        }
        match &self.evidence {
            None if self.floor.is_none()
                && self.roots.is_empty()
                && self.status == Status::Unknown => {}
            Some(e) if self.floor == Some(e.earliest) && self.incarnation.is_some() => {
                e.verify(&self.binding, original, &self.roots)?;
                if !e
                    .denied_key_ids
                    .iter()
                    .all(|id| self.denied_key_ids.contains(id))
                {
                    return Err(Error::StateCorrupt);
                }
            }
            _ => return Err(Error::StateCorrupt),
        }
        Ok(())
    }
    /// Validate local compact-state invariants only. The protected history
    /// owner must independently authenticate the exact position and evidence
    /// before accepting this state or applying any transition.
    pub(crate) fn validate_compact_shape(&self) -> Result<()> {
        self.validate_common()?;
        if self.product_root.is_none() {
            return Err(Error::StateCorrupt);
        }
        match &self.evidence {
            None if self.floor.is_none() && self.status == Status::Unknown => Ok(()),
            Some(e) if self.floor == Some(e.earliest) && self.incarnation.is_some() => {
                if !e
                    .denied_key_ids
                    .iter()
                    .all(|id| self.denied_key_ids.contains(id))
                {
                    return Err(Error::StateCorrupt);
                }
                Ok(())
            }
            _ => Err(Error::StateCorrupt),
        }
    }
    // This checks only local state shape. It never authenticates a Root or
    // evidence and must not be used as a standalone source of authority.
    pub(crate) fn validate_common(&self) -> Result<()> {
        self.binding.validate()?;
        check_denied(&self.denied_key_ids)?;
        if let Some(position) = &self.product_root {
            position.validate()?;
            if !self.roots.is_empty() {
                return Err(Error::StateCorrupt);
            }
        }
        if self.protocol_version != 1
            || self.revision == 0
            || self.revision > json::SAFE_MAX
            || self.roots.len() > 4096
            || self.floor.is_some_and(|n| n > json::SAFE_MAX)
            || (self.revision == 1) != (self.previous_sha256.is_none())
            || self
                .previous_sha256
                .as_ref()
                .is_some_and(|s| !json::digest(s))
        {
            return Err(Error::StateCorrupt);
        }
        match (self.status, self.cleanup_pending, &self.zero_retention) {
            (Status::Unknown | Status::CleanupPending, true, None) => {}
            (Status::CleanupVerifiedZero, false, Some(reference)) => {
                reference.validate()?;
                if reference.completion_revision != self.revision {
                    return Err(Error::StateCorrupt);
                }
            }
            _ => return Err(Error::StateCorrupt),
        }
        if let Some(i) = &self.incarnation {
            i.validate()?;
        }
        if let Some(fault) = &self.policy_fault {
            fault.validate(
                self.revision,
                self.previous_sha256.as_deref(),
                self.status,
                self.incarnation.as_ref(),
            )?;
        }
        Ok(())
    }
    pub(crate) fn next_unknown(&self, incarnation: Incarnation, previous: &[u8]) -> Result<Self> {
        let mut next = self.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .filter(|n| *n <= json::SAFE_MAX)
            .ok_or(Error::Unavailable)?;
        next.previous_sha256 = Some(json::sha256(previous));
        next.incarnation = Some(incarnation);
        next.status = Status::Unknown;
        next.cleanup_pending = true;
        next.zero_retention = None;
        Ok(next)
    }
    pub(crate) fn transition(&self, next: &Self, previous: &[u8], original: &[u8]) -> Result<()> {
        next.validate(original)?;
        PolicyFault::transition(
            self.policy_fault.as_ref(),
            next.policy_fault.as_ref(),
            next.status,
            next.revision,
            previous,
        )?;
        if next.binding != self.binding
            || next.revision != self.revision.checked_add(1).ok_or(Error::Unavailable)?
            || next.previous_sha256 != Some(json::sha256(previous))
            || next.floor.unwrap_or(0) < self.floor.unwrap_or(0)
            || !next.roots.starts_with(&self.roots)
            || !self
                .denied_key_ids
                .iter()
                .all(|id| next.denied_key_ids.contains(id))
        {
            return Err(Error::StateCorrupt);
        }
        match next.status {
            Status::Unknown => {
                if next.floor != self.floor
                    || next.roots != self.roots
                    || next.evidence != self.evidence
                {
                    return Err(Error::StateCorrupt);
                }
            }
            Status::CleanupVerifiedZero => {
                if self.status != Status::CleanupPending
                    || next.floor != self.floor
                    || next.roots != self.roots
                    || next.evidence != self.evidence
                    || next.denied_key_ids != self.denied_key_ids
                    || next.incarnation != self.incarnation
                {
                    return Err(Error::StateCorrupt);
                }
                // This proves a transition shape only. The native fixed publisher
                // authenticates the inventory/completion in the SAME transaction.
            }
            Status::CleanupPending => {
                let e = next.evidence.as_ref().ok_or(Error::StateCorrupt)?;
                if next.incarnation != self.incarnation
                    || Some(&e.incarnation) != next.incarnation.as_ref()
                    || next.denied_key_ids != e.denied_key_ids
                    // Native publication additionally requires exact equality
                    // with max(actual time floor, protected budget live floor).
                    || e.floor_before < self.floor.unwrap_or(0)
                    || e.base_root_count != self.roots.len()
                    || self.policy_fault.as_ref().is_some_and(PolicyFault::is_active)
                        && self.evidence.as_ref().is_some_and(|old| old.request == e.request)
                {
                    return Err(Error::StateCorrupt);
                }
            }
        }
        Ok(())
    }
    /// Transition shape for independently authenticated compact positions.
    /// Both positions and evidence must first be replayed against the same
    /// protected product Head by the native owner; this method grants no trust.
    pub(crate) fn transition_compact_shape(&self, next: &Self, previous: &[u8]) -> Result<()> {
        next.validate_compact_shape()?;
        PolicyFault::transition(
            self.policy_fault.as_ref(),
            next.policy_fault.as_ref(),
            next.status,
            next.revision,
            previous,
        )?;
        let target = next.product_root.as_ref().ok_or(Error::StateCorrupt)?;
        let old = self.product_root.as_ref();
        if self.binding != next.binding
            || next.revision != self.revision.checked_add(1).ok_or(Error::Unavailable)?
            || next.previous_sha256 != Some(json::sha256(previous))
            || next.floor.unwrap_or(0) < self.floor.unwrap_or(0)
            || !self
                .denied_key_ids
                .iter()
                .all(|id| next.denied_key_ids.contains(id))
            || old.is_none() && !self.roots.is_empty()
            || old.is_some_and(|p| {
                match (
                    target.batch.checked_sub(p.batch),
                    target.root_count.checked_sub(p.root_count),
                ) {
                    (Some(batches), Some(roots)) => {
                        roots < batches || (batches == 0 && target != p)
                    }
                    _ => true,
                }
            })
        {
            return Err(Error::StateCorrupt);
        }
        let same_position = old == Some(target);
        let joining = old.is_none()
            && self.floor.is_none()
            && self.evidence.is_none()
            && self.status == Status::Unknown;
        match next.status {
            Status::Unknown => {
                if next.floor != self.floor
                    || next.evidence != self.evidence
                    || (!same_position && !joining)
                {
                    return Err(Error::StateCorrupt);
                }
            }
            Status::CleanupVerifiedZero => {
                if !same_position
                    || self.status != Status::CleanupPending
                    || next.floor != self.floor
                    || next.evidence != self.evidence
                    || next.denied_key_ids != self.denied_key_ids
                    || next.incarnation != self.incarnation
                {
                    return Err(Error::StateCorrupt);
                }
            }
            Status::CleanupPending => {
                let evidence = next.evidence.as_ref().ok_or(Error::StateCorrupt)?;
                let base = old.map_or(0, |p| p.root_count);
                if next.incarnation != self.incarnation
                    || Some(&evidence.incarnation) != next.incarnation.as_ref()
                    || next.denied_key_ids != evidence.denied_key_ids
                    || evidence.floor_before < self.floor.unwrap_or(0)
                    || u64::try_from(evidence.base_root_count)
                        .ok()
                        .is_none_or(|count| count < base || count > target.root_count)
                    || self
                        .policy_fault
                        .as_ref()
                        .is_some_and(PolicyFault::is_active)
                        && self
                            .evidence
                            .as_ref()
                            .is_some_and(|old| old.request == evidence.request)
                {
                    return Err(Error::StateCorrupt);
                }
            }
        }
        Ok(())
    }
    /// Transition DATA only. Native production callers must positively observe
    /// invalid protected Policy bytes and authenticate the intact original state.
    pub(crate) fn next_policy_fault(
        &self,
        incarnation: Incarnation,
        previous: &[u8],
        policy_sha256: String,
    ) -> Result<Self> {
        if !json::digest(&policy_sha256)
            || self
                .policy_fault
                .as_ref()
                .is_some_and(PolicyFault::is_active)
        {
            return Err(Error::ScopeConflict);
        }
        let mut next = self.next_unknown(incarnation.clone(), previous)?;
        next.policy_fault = Some(PolicyFault::observed(
            next.revision,
            previous,
            policy_sha256,
            incarnation,
        ));
        Ok(next)
    }
}
pub(crate) fn root_version(raw: &[u8], product: &str) -> Result<u64> {
    let env = decode_canonical_envelope(raw, InputKind::Metadata)
        .map_err(|_| Error::StateCorrupt)?
        .check_full_schema()
        .map_err(|_| Error::StateCorrupt)?;
    let shape = env
        .envelope()
        .signed()
        .root_policy_shape()
        .map_err(|_| Error::StateCorrupt)?;
    if shape.product() != product {
        return Err(Error::StateCorrupt);
    }
    Ok(shape.version())
}

/// Enclosing UTC DATA at one counter observation. These numbers alone cannot
/// prove SCM continuity, a live source, a cleanup census or a current permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UtcInterval {
    earliest: u64,
    latest: u64,
}
impl UtcInterval {
    pub(crate) fn earliest_millis(self) -> u64 {
        self.earliest
    }
    pub(crate) fn latest_millis(self) -> u64 {
        self.latest
    }
}

/// Advance the entire signed anchor interval using enclosing native elapsed
/// bounds. The Windows owner separately proves that both samples belong to the
/// same real SCM incarnation and that the anchor/policy are still protected.
/// Suspend-inclusive native elapsed is the established project's elapsed-time
/// reference; this adds no drift, anchor-age or absolute-UTC metrology policy.
pub(crate) fn advance_interval(
    anchor_earliest: u64,
    anchor_latest: u64,
    received: CounterObservation,
    current: CounterObservation,
) -> Result<UtcInterval> {
    if anchor_earliest > anchor_latest || anchor_latest > json::SAFE_MAX {
        return Err(Error::Unavailable);
    }
    // The original received bracket must remain the origin. A caller cannot
    // replace it with a fresh sample to erase sleep or already elapsed time.
    let elapsed = current.elapsed_since(received)?.suspend_inclusive();
    let earliest = anchor_earliest
        .checked_add(elapsed.floor_millis()?)
        .filter(|n| *n <= json::SAFE_MAX)
        .ok_or(Error::Unavailable)?;
    let latest = anchor_latest
        .checked_add(elapsed.ceil_millis()?)
        .filter(|n| *n <= json::SAFE_MAX)
        .ok_or(Error::Unavailable)?;
    Ok(UtcInterval { earliest, latest })
}

/// Context/window checks only. Actual Root custody and the accepted continuous
/// signature lineage belong to the native source, not this pure DATA helper.
pub(crate) fn check_root_interval(raw: &[u8], product: &str, interval: UtcInterval) -> Result<()> {
    let envelope = decode_canonical_envelope(raw, InputKind::Metadata)
        .map_err(|_| Error::StateCorrupt)?
        .check_full_schema()
        .map_err(|_| Error::StateCorrupt)?;
    let signed = envelope.envelope().signed();
    let shape = signed
        .root_policy_shape()
        .map_err(|_| Error::StateCorrupt)?;
    if shape.product() != product {
        return Err(Error::StateCorrupt);
    }
    // root_policy_shape validates these as safe, positive integer fields. Keep
    // explicit checks here rather than relying on a lossy numeric cast.
    let time = |name: &str| -> Result<u64> {
        signed.value()[name]
            .as_f64()
            .filter(|n| {
                n.is_finite() && *n >= 0.0 && *n <= json::SAFE_MAX as f64 && n.trunc() == *n
            })
            .map(|n| n as u64)
            .ok_or(Error::StateCorrupt)
    };
    let issued = time("issuedAt")?;
    let expires = time("expiresAt")?;
    if issued > interval.earliest || expires <= interval.latest {
        return Err(Error::SourceUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod live_interval_tests {
    use super::*;
    fn sample(low: u64, awake_low: u64, awake_high: u64, high: u64) -> CounterObservation {
        CounterObservation::from_bracket(low, awake_low, awake_high, high).unwrap()
    }
    #[test]
    fn advancing_preserves_both_anchor_edges_and_outward_fractional_rounding() {
        let received = sample(10_000, 8_000, 15_000, 20_000);
        let current = sample(30_001, 25_000, 35_000, 50_001);
        let interval = advance_interval(100, 120, received, current).unwrap();
        assert_eq!(interval.earliest_millis(), 101);
        assert_eq!(interval.latest_millis(), 125);
        // A point estimate or using only awake time would lose this enclosure.
        assert!(interval.latest_millis() - interval.earliest_millis() > 20);
    }
    #[test]
    fn suspend_time_is_not_erased_and_exact_and_submillisecond_bounds_differ() {
        let received = sample(10_000, 8_000, 8_000, 10_000);
        let exact = sample(20_000, 8_000, 8_000, 20_000);
        assert_eq!(
            advance_interval(100, 120, received, exact).unwrap(),
            UtcInterval {
                earliest: 101,
                latest: 121
            }
        );
        let fractional = sample(19_999, 8_000, 8_000, 19_999);
        assert_eq!(
            advance_interval(100, 120, received, fractional).unwrap(),
            UtcInterval {
                earliest: 100,
                latest: 121
            }
        );
    }
    #[test]
    fn reverse_and_overflowing_observations_never_become_an_interval() {
        let received = sample(10_000, 8_000, 8_000, 10_000);
        let earlier = sample(9_999, 7_999, 7_999, 9_999);
        assert!(advance_interval(100, 120, received, earlier).is_err());
        assert!(advance_interval(121, 120, received, received).is_err());
        let later = sample(20_000, 9_000, 9_000, 20_000);
        assert!(advance_interval(json::SAFE_MAX, json::SAFE_MAX, received, later).is_err());
        assert!(advance_interval(0, json::SAFE_MAX + 1, received, received).is_err());
    }
    #[test]
    fn accepted_root_must_cover_the_complete_current_interval_at_both_edges() {
        let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../../../specs/upgrade/v1/vectors/time/anchor.json"
        )))
        .unwrap();
        let raw = vectors["cases"][1]["trustedRootBytes"]
            .as_str()
            .unwrap()
            .as_bytes();
        let root: serde_json::Value = serde_json::from_slice(raw).unwrap();
        let issued = root["signed"]["issuedAt"].as_u64().unwrap();
        let expires = root["signed"]["expiresAt"].as_u64().unwrap();
        check_root_interval(
            raw,
            "pinvou",
            UtcInterval {
                earliest: issued,
                latest: expires - 1,
            },
        )
        .unwrap();
        assert!(
            check_root_interval(
                raw,
                "pinvou",
                UtcInterval {
                    earliest: issued - 1,
                    latest: issued
                }
            )
            .is_err()
        );
        assert!(
            check_root_interval(
                raw,
                "pinvou",
                UtcInterval {
                    earliest: expires - 1,
                    latest: expires
                }
            )
            .is_err()
        );
        assert!(
            check_root_interval(
                raw,
                "other",
                UtcInterval {
                    earliest: issued,
                    latest: issued
                }
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn product_replay_retries_4097_signed_roots_after_missing_final_object() {
        let fixture = long_root_fixture::generate();
        let (state, _, _) = anchored();
        let mut evidence = state.evidence.unwrap();
        evidence.request = serde_json::to_string(&fixture.request).unwrap();
        evidence.response = String::from_utf8(fixture.response).unwrap();
        evidence.sent = CounterEvidence::from_data(
            CounterObservation::from_bracket(100_000, 90_000, 90_000, 100_000).unwrap(),
        );
        evidence.received = CounterEvidence::from_data(
            CounterObservation::from_bracket(200_000, 190_000, 190_000, 200_000).unwrap(),
        );
        evidence.floor_before = 0;
        evidence.base_root_count = 0;
        evidence.earliest = 99_995;
        evidence.latest = 100_015;
        let batch = ProductRootBatch {
            binding: binding(),
            successor_count: fixture.roots.len(),
            evidence,
        };
        assert_eq!(batch.successor_count, 4097);
        let mut replay =
            ProductRootReplay::new("pinvou", std::str::from_utf8(&fixture.original).unwrap())
                .unwrap();
        assert_eq!(
            replay.advance(
                &batch,
                |i| {
                    if i == 4096 {
                        Err(Error::Unavailable)
                    } else {
                        Ok(fixture.roots[i].clone())
                    }
                },
                |visit| visit(&[])
            ),
            Err(Error::Unavailable)
        );
        replay
            .advance(&batch, |i| Ok(fixture.roots[i].clone()), |visit| visit(&[]))
            .unwrap();
        assert!(
            replay
                .finish(1, 4097, &json::sha256(fixture.roots.last().unwrap()))
                .is_ok()
        );
    }
    #[test]
    fn initial_policy_is_canonical_and_bound_to_the_original_installation() {
        let b = binding();
        let policy = Policy::initial(b.clone()).unwrap();
        assert_eq!(policy.max_round_trip_ms, 30_000);
        assert_eq!(policy.max_uncertainty_ms, 1_000);
        assert!(policy.denied_key_ids.is_empty());
        let raw = json::encode(&policy, false).unwrap();
        Policy::parse(&raw, &b).unwrap();
        let mut other = b.clone();
        other.original_install_operation_id = "another-original".into();
        assert!(Policy::parse(&raw, &other).is_err());
        other = b.clone();
        other.genesis_manifest_sha256 = "c".repeat(64);
        assert!(Policy::parse(&raw, &other).is_err());
        other = b;
        other.installation_scope_id.clear();
        assert!(Policy::initial(other).is_err());
        assert!(Policy::parse(b"{}", &binding()).is_err());
    }

    #[test]
    fn initial_policy_verifies_real_signed_evidence_without_granting_fresh_time() {
        let (mut state, _, original) = anchored();
        let raw = json::encode(&Policy::initial(state.binding.clone()).unwrap(), false).unwrap();
        state.evidence.as_mut().unwrap().policy = String::from_utf8(raw.clone()).unwrap();
        state.validate(&original).unwrap();
        state
            .anchor_for_live(&raw, state.incarnation.as_ref().unwrap())
            .unwrap();
        let initial = State::genesis(state.binding.clone(), &original).unwrap();
        assert!(initial.status == Status::Unknown);
        assert!(initial.cleanup_pending && initial.floor.is_none() && initial.evidence.is_none());
        assert!(
            initial
                .anchor_for_live(&raw, state.incarnation.as_ref().unwrap())
                .is_err()
        );
    }

    #[test]
    fn signed_evidence_replay_reads_one_root_at_a_time_and_preserves_source_errors() {
        let (state, _, original) = anchored();
        let evidence = state.evidence.as_ref().unwrap();
        let mut calls = Vec::new();
        evidence
            .verify_source(&state.binding, &original, state.roots.len(), |index| {
                calls.push(index);
                Ok(std::borrow::Cow::Owned(
                    state.roots[index].as_bytes().to_vec(),
                ))
            })
            .unwrap();
        assert_eq!(calls, vec![0, 0]);
        let mut calls = 0;
        assert_eq!(
            evidence.verify_source(&state.binding, &original, state.roots.len(), |index| {
                calls += 1;
                if calls == 2 {
                    Err(Error::Unavailable)
                } else {
                    Ok(std::borrow::Cow::Borrowed(state.roots[index].as_bytes()))
                }
            }),
            Err(Error::Unavailable)
        );
        let mut with_base = evidence.clone();
        with_base.base_root_count = 1;
        let mut calls = 0;
        assert_eq!(
            with_base.verify_source(&state.binding, &original, state.roots.len(), |index| {
                calls += 1;
                if calls == 2 {
                    Err(Error::Unavailable)
                } else {
                    Ok(std::borrow::Cow::Borrowed(state.roots[index].as_bytes()))
                }
            }),
            Err(Error::Unavailable)
        );
        let mut a = Sha256::new();
        let mut b = Sha256::new();
        fingerprint_root(&mut a, 0, b"ab");
        fingerprint_root(&mut a, 1, b"c");
        fingerprint_root(&mut b, 0, b"a");
        fingerprint_root(&mut b, 1, b"bc");
        assert_ne!(a.finalize(), b.finalize());
        assert_eq!(
            evidence.verify_source(&state.binding, &original, state.roots.len(), |_| Err(
                Error::Unavailable
            )),
            Err(Error::Unavailable)
        );
        assert_eq!(
            evidence.verify_source(&state.binding, &original, state.roots.len(), |_| Err(
                Error::StateCorrupt
            )),
            Err(Error::StateCorrupt)
        );
        assert!(
            evidence
                .verify_source(&state.binding, &original, state.roots.len(), |_| {
                    Ok(std::borrow::Cow::Owned(b"{}".to_vec()))
                })
                .is_err()
        );
        assert!(
            evidence
                .verify_source(&state.binding, &original, 0, |_| unreachable!())
                .is_err()
        );
    }

    #[test]
    fn additional_member_denies_apply_to_real_signed_time_and_root_batch() {
        let (state, _, original) = anchored();
        let evidence = state.evidence.as_ref().unwrap();
        evidence
            .check_additional_denied(&state.binding, &original, &state.roots, &[])
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&evidence.response).unwrap();
        let signer = response["signatures"][0]["keyId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            evidence.check_additional_denied(&state.binding, &original, &state.roots, &[signer]),
            Err(Error::ScopeConflict)
        );
        {
            let successor = state
                .roots
                .first()
                .expect("fixture includes a successor Root");
            let root: serde_json::Value = serde_json::from_str(successor).unwrap();
            let signer = root["signatures"][0]["keyId"].as_str().unwrap().to_owned();
            assert_eq!(
                evidence.check_additional_denied(
                    &state.binding,
                    &original,
                    &state.roots,
                    &[signer]
                ),
                Err(Error::ScopeConflict)
            );
        }
        assert_eq!(
            evidence.check_additional_denied(
                &state.binding,
                &original,
                &state.roots,
                &["invalid".into()]
            ),
            Err(Error::StateCorrupt)
        );
    }

    #[test]
    fn compact_position_requires_protected_history_authentication() {
        let (mut state, _, original) = anchored();
        state.roots.clear();
        state.product_root = Some(ProductRootPosition {
            head_sha256: "a".repeat(64),
            root_sha256: "b".repeat(64),
            batch: 1,
            root_count: 1,
        });
        assert!(state.validate_common().is_ok());
        assert_eq!(
            state.validate(&original),
            Err(Error::PrerequisiteUnavailable)
        );
        state.roots.push("unverified".into());
        assert_eq!(state.validate_common(), Err(Error::StateCorrupt));
        state.roots.clear();
        state.product_root.as_mut().unwrap().root_count = 0;
        assert_eq!(state.validate_common(), Err(Error::StateCorrupt));
        state.product_root.as_mut().unwrap().root_count = 1;
        state.product_root.as_mut().unwrap().head_sha256 = "not-a-digest".into();
        assert_eq!(state.validate_common(), Err(Error::StateCorrupt));
    }

    #[test]
    fn compact_transition_shape_preserves_predecessor_and_time_floor() {
        let (sample, _, original) = anchored();
        let mut prior = State::genesis(sample.binding.clone(), &original).unwrap();
        prior.incarnation = sample.incarnation.clone();
        let mut next = prior
            .next_unknown(prior.incarnation.clone().unwrap(), b"prior")
            .unwrap();
        let mut evidence = sample.evidence.unwrap();
        evidence.base_root_count = 0;
        evidence.floor_before = 0;
        next.product_root = Some(ProductRootPosition {
            head_sha256: "a".repeat(64),
            root_sha256: "b".repeat(64),
            batch: 1,
            root_count: 1,
        });
        next.status = Status::CleanupPending;
        next.floor = Some(evidence.earliest);
        next.denied_key_ids = evidence.denied_key_ids.clone();
        next.evidence = Some(evidence);
        assert!(prior.transition_compact_shape(&next, b"prior").is_ok());
        assert_eq!(
            prior.transition_compact_shape(&next, b"different"),
            Err(Error::StateCorrupt)
        );
        next.evidence.as_mut().unwrap().base_root_count = 2;
        assert_eq!(
            prior.transition_compact_shape(&next, b"prior"),
            Err(Error::StateCorrupt)
        );
        next.evidence.as_mut().unwrap().base_root_count = 0;
        next.floor = None;
        assert_eq!(
            prior.transition_compact_shape(&next, b"prior"),
            Err(Error::StateCorrupt)
        );
    }

    #[test]
    fn compact_transition_rejects_insufficient_root_growth_and_preserves_state() {
        let (sample, _, _) = anchored();
        let mut prior = sample.clone();
        prior.roots.clear();
        prior.product_root = Some(ProductRootPosition {
            head_sha256: "a".repeat(64),
            root_sha256: "b".repeat(64),
            batch: 1,
            root_count: 2,
        });
        let incarnation = prior.incarnation.clone().unwrap();
        let mut next = prior.next_unknown(incarnation.clone(), b"prior").unwrap();
        assert!(prior.transition_compact_shape(&next, b"prior").is_ok());
        next.floor = Some(prior.floor.unwrap() + 1);
        assert_eq!(
            prior.transition_compact_shape(&next, b"prior"),
            Err(Error::StateCorrupt)
        );
        next = prior.next_unknown(incarnation.clone(), b"prior").unwrap();
        prior.denied_key_ids.push("f".repeat(64));
        assert_eq!(
            prior.transition_compact_shape(&next, b"prior"),
            Err(Error::StateCorrupt)
        );
        prior.denied_key_ids.clear();
        next = prior.next_unknown(incarnation, b"prior").unwrap();
        next.status = Status::CleanupPending;
        let evidence = next.evidence.as_mut().unwrap();
        evidence.floor_before = prior.floor.unwrap();
        evidence.base_root_count = 2;
        next.product_root = Some(ProductRootPosition {
            head_sha256: "c".repeat(64),
            root_sha256: "d".repeat(64),
            batch: 3,
            root_count: 4,
        });
        assert!(prior.transition_compact_shape(&next, b"prior").is_ok());
        next.product_root.as_mut().unwrap().root_count = 1;
        assert_eq!(
            prior.transition_compact_shape(&next, b"prior"),
            Err(Error::StateCorrupt)
        );
        next.product_root.as_mut().unwrap().root_count = 3;
        assert_eq!(
            prior.transition_compact_shape(&next, b"prior"),
            Err(Error::StateCorrupt)
        );
        let mut zero = prior
            .next_unknown(prior.incarnation.clone().unwrap(), b"prior")
            .unwrap();
        zero.status = Status::CleanupVerifiedZero;
        assert_eq!(
            prior.transition_compact_shape(&zero, b"prior"),
            Err(Error::StateCorrupt)
        );
    }

    #[test]
    fn compact_transition_checks_valid_shapes_and_numeric_boundaries() {
        let (sample, _, _) = anchored();
        let mut prior = sample;
        prior.roots.clear();
        prior.product_root = Some(ProductRootPosition {
            head_sha256: "a".repeat(64),
            root_sha256: "b".repeat(64),
            batch: 2,
            root_count: 4,
        });
        let inc = prior.incarnation.clone().unwrap();
        let mut next = prior.next_unknown(inc.clone(), b"prior").unwrap();
        next.status = Status::CleanupPending;
        next.evidence.as_mut().unwrap().floor_before = prior.floor.unwrap();
        next.evidence.as_mut().unwrap().base_root_count = 4;
        assert!(prior.transition_compact_shape(&next, b"prior").is_ok());
        for position in [
            ProductRootPosition {
                head_sha256: "c".repeat(64),
                root_sha256: "d".repeat(64),
                batch: 3,
                root_count: 3,
            },
            ProductRootPosition {
                head_sha256: "c".repeat(64),
                root_sha256: "d".repeat(64),
                batch: 1,
                root_count: 4,
            },
            ProductRootPosition {
                head_sha256: "c".repeat(64),
                root_sha256: "b".repeat(64),
                batch: 2,
                root_count: 4,
            },
            ProductRootPosition {
                head_sha256: "a".repeat(64),
                root_sha256: "b".repeat(64),
                batch: 2,
                root_count: 5,
            },
        ] {
            let mut bad = next.clone();
            bad.product_root = Some(position);
            assert!(bad.validate_compact_shape().is_ok());
            assert_eq!(
                prior.transition_compact_shape(&bad, b"prior"),
                Err(Error::StateCorrupt)
            );
        }
        let mut complete = prior.next_unknown(inc, b"prior").unwrap();
        complete.status = Status::CleanupVerifiedZero;
        complete.cleanup_pending = false;
        complete.zero_retention = Some(crate::retention_custody::ZeroRetentionReference {
            completion_revision: complete.revision,
            completion_sha256: "e".repeat(64),
        });
        assert!(prior.transition_compact_shape(&complete, b"prior").is_ok());
        let fault = prior
            .next_policy_fault(prior.incarnation.clone().unwrap(), b"prior", "f".repeat(64))
            .unwrap();
        assert!(prior.transition_compact_shape(&fault, b"prior").is_ok());
        let mut erased = fault
            .next_unknown(fault.incarnation.clone().unwrap(), b"fault")
            .unwrap();
        erased.policy_fault = None;
        assert_eq!(
            fault.transition_compact_shape(&erased, b"fault"),
            Err(Error::StateCorrupt)
        );
        let mut at_limit = prior.clone();
        at_limit.product_root.as_mut().unwrap().batch = json::SAFE_MAX - 1;
        at_limit.product_root.as_mut().unwrap().root_count = json::SAFE_MAX - 1;
        let mut max_next = at_limit
            .next_unknown(at_limit.incarnation.clone().unwrap(), b"limit")
            .unwrap();
        max_next.status = Status::CleanupPending;
        max_next.evidence.as_mut().unwrap().floor_before = at_limit.floor.unwrap();
        max_next.evidence.as_mut().unwrap().base_root_count =
            usize::try_from(json::SAFE_MAX - 1).unwrap();
        let target = max_next.product_root.as_mut().unwrap();
        target.batch = json::SAFE_MAX;
        target.root_count = json::SAFE_MAX;
        target.head_sha256 = "c".repeat(64);
        target.root_sha256 = "d".repeat(64);
        assert!(
            at_limit
                .transition_compact_shape(&max_next, b"limit")
                .is_ok()
        );
        prior.revision = json::SAFE_MAX;
        assert_eq!(
            prior
                .next_unknown(prior.incarnation.clone().unwrap(), b"prior")
                .err(),
            Some(Error::Unavailable)
        );
    }

    #[test]
    fn product_root_history_replays_signed_batches_with_historical_denials() {
        #[derive(Clone)]
        struct TestBatch {
            batch: ProductRootBatch,
            successors: Vec<String>,
            member_denies: Vec<Vec<String>>,
        }
        impl std::ops::Deref for TestBatch {
            type Target = ProductRootBatch;
            fn deref(&self) -> &Self::Target {
                &self.batch
            }
        }
        impl std::ops::DerefMut for TestBatch {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.batch
            }
        }
        fn advance(cursor: &mut ProductRootReplay, batch: &TestBatch) -> Result<()> {
            cursor.advance(
                &batch.batch,
                |i| {
                    batch
                        .successors
                        .get(i)
                        .map(|r| r.as_bytes().to_vec())
                        .ok_or(Error::Unavailable)
                },
                |visit| {
                    for member in &batch.member_denies {
                        visit(member)?;
                    }
                    Ok(())
                },
            )
        }
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/product-root-history.json"
        )))
        .unwrap();
        let original = fixture["original"].as_str().unwrap().as_bytes();
        let (state, _, _) = anchored();
        let template = state.evidence.unwrap();
        let mut batches: Vec<TestBatch> = fixture["batches"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let mut evidence = template.clone();
                evidence.request = serde_json::to_string(&entry["request"]).unwrap();
                evidence.response = entry["response"].as_str().unwrap().into();
                evidence.base_root_count = if index == 0 { 0 } else { 2 };
                evidence.earliest = entry["earliest"].as_u64().unwrap();
                evidence.latest = entry["latest"].as_u64().unwrap();
                TestBatch {
                    batch: ProductRootBatch {
                        binding: binding(),
                        evidence,
                        successor_count: entry["successors"].as_array().unwrap().len(),
                    },
                    successors: entry["successors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|root| root.as_str().unwrap().into())
                        .collect(),
                    member_denies: vec![vec![]],
                }
            })
            .collect();
        // Each batch carries its own authenticated profile binding and policy.
        batches[1].binding.profile_id = "other-profile".into();
        let mut other_policy = policy();
        other_policy.binding = batches[1].binding.clone();
        batches[1].evidence.policy =
            String::from_utf8(json::encode(&other_policy, false).unwrap()).unwrap();
        let expected_head = json::sha256(batches[1].successors[0].as_bytes());
        let replay = |batches: &[TestBatch]| -> Result<()> {
            let mut cursor =
                ProductRootReplay::new("pinvou", std::str::from_utf8(original).unwrap())?;
            for batch in batches {
                advance(&mut cursor, batch)?;
            }
            cursor.finish(2, 3, &expected_head)
        };
        assert!(matches!(
            ProductRootReplay::new("pinvou", &"x".repeat(json::RECORD_MAX + 1)),
            Err(Error::StateCorrupt)
        ));
        // Each batch-level bound rejects before the root or member source is
        // accessed. Every failed attempt leaves this cursor usable for retry.
        let mut cursor =
            ProductRootReplay::new("pinvou", std::str::from_utf8(original).unwrap()).unwrap();
        for kind in 0..4 {
            let mut bad = batches[0].clone();
            match kind {
                0 => bad.evidence.request = "x".repeat(json::FRAME_MAX + 1),
                1 => bad.evidence.response = "x".repeat(json::FRAME_MAX + 1),
                2 => bad.evidence.policy = "x".repeat(json::RECORD_MAX + 1),
                _ => bad.successor_count = 0,
            }
            let mut reads = 0;
            let mut visits = 0;
            assert_eq!(
                cursor.advance(
                    &bad.batch,
                    |_| {
                        reads += 1;
                        Err(Error::Unavailable)
                    },
                    |_| {
                        visits += 1;
                        Ok(())
                    }
                ),
                Err(Error::StateCorrupt)
            );
            assert_eq!((reads, visits), (0, 0));
        }
        let mut reads = 0;
        let mut visits = 0;
        assert_eq!(
            cursor.advance(
                &batches[0].batch,
                |_| {
                    reads += 1;
                    Ok(vec![b'x'; json::RECORD_MAX + 1])
                },
                |_| {
                    visits += 1;
                    Ok(())
                }
            ),
            Err(Error::StateCorrupt)
        );
        assert_eq!((reads, visits), (1, 0));
        let mut reads = 0;
        assert_eq!(
            cursor.advance(
                &batches[0].batch,
                |i| {
                    reads += 1;
                    if reads > 4 {
                        Ok(vec![b'x'; json::RECORD_MAX + 1])
                    } else {
                        Ok(batches[0].successors[i].as_bytes().to_vec())
                    }
                },
                |visit| visit(&["f".repeat(64)])
            ),
            Err(Error::StateCorrupt)
        );
        assert_eq!(reads, 5);
        advance(&mut cursor, &batches[0]).unwrap();
        advance(&mut cursor, &batches[1]).unwrap();
        assert_eq!(cursor.finish(2, 3, &expected_head), Ok(()));
        let historical_issue = cursor.finish_latest_issue(2, 3, &expected_head).unwrap();
        assert!(historical_issue > 1_700_000_000_195);
        assert!(historical_issue > root_issue_bytes(batches[1].successors[0].as_bytes()).unwrap());
        assert_eq!(
            check_history_time_bound(historical_issue, 1_700_000_000_195),
            Err(Error::StateCorrupt)
        );
        assert_eq!(
            check_history_time_bound(historical_issue, historical_issue),
            Ok(())
        );
        assert!(cursor.finish_latest_issue(2, 3, &"0".repeat(64)).is_err());
        let mut cursor =
            ProductRootReplay::new("pinvou", std::str::from_utf8(original).unwrap()).unwrap();
        let mut reads = 0;
        assert_eq!(
            cursor.advance(
                &batches[0].batch,
                |i| {
                    reads += 1;
                    if reads > 4 && i == 0 {
                        Ok(batches[0].successors[1].as_bytes().to_vec())
                    } else {
                        Ok(batches[0].successors[i].as_bytes().to_vec())
                    }
                },
                |visit| visit(&["f".repeat(64)])
            ),
            Err(Error::StateCorrupt)
        );
        let mut reads = 0;
        assert_eq!(
            cursor.advance(
                &batches[0].batch,
                |i| {
                    reads += 1;
                    if reads > 4 {
                        Err(Error::Unavailable)
                    } else {
                        Ok(batches[0].successors[i].as_bytes().to_vec())
                    }
                },
                |visit| visit(&["f".repeat(64)])
            ),
            Err(Error::Unavailable)
        );
        advance(&mut cursor, &batches[0]).unwrap();
        let first: serde_json::Value = serde_json::from_str(&batches[0].successors[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(&batches[1].successors[0]).unwrap();
        let historical = first["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["keyId"].as_str().unwrap())
            .find(|id| {
                !second["signatures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s["keyId"] == *id)
            })
            .unwrap()
            .to_owned();
        batches[1].member_denies.push(vec![historical.clone()]);
        assert_eq!(replay(&batches), Ok(()));
        assert_eq!(replay(&batches[..1]), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad[1].binding.profile_id = "unmatched-profile".into();
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad[0].member_denies.push(vec![historical]);
        assert_eq!(replay(&bad), Err(Error::ScopeConflict));
        let signer = serde_json::from_str::<serde_json::Value>(&batches[1].evidence.response)
            .unwrap()["signatures"][0]["keyId"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut bad = batches.clone();
        bad[1].member_denies.push(vec![signer]);
        assert_eq!(replay(&bad), Err(Error::ScopeConflict));
        let mut bad = batches.clone();
        bad[1].evidence.base_root_count = 0;
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad.swap(0, 1);
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad[1].evidence.response = batches[0].evidence.response.clone();
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad[1].successors[0].push(' ');
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad[1].member_denies.push(vec!["invalid".into()]);
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad[1].successors.clear();
        assert_eq!(replay(&bad), Err(Error::Unavailable));
        // The intermediate Root of a multi-successor batch is also checked.
        let intermediate: serde_json::Value =
            serde_json::from_str(&batches[0].successors[0]).unwrap();
        let mut bad = batches.clone();
        bad[0].member_denies.push(vec![
            intermediate["signatures"][0]["keyId"]
                .as_str()
                .unwrap()
                .into(),
        ]);
        assert_eq!(replay(&bad), Err(Error::ScopeConflict));
        // This signed response passes against its immediate predecessor, but
        // predates an earlier Root's issuedAt and therefore fails full replay.
        let mut bad = batches.clone();
        bad[1].evidence.response = fixture["batches"][1]["earlyResponse"]
            .as_str()
            .unwrap()
            .into();
        bad[1].evidence.earliest = 1_700_000_000_195;
        bad[1].evidence.latest = 1_700_000_000_225;
        let mut standalone = bad[1].evidence.clone();
        standalone.base_root_count = 0;
        assert_eq!(
            standalone.verify(
                &bad[1].binding,
                bad[0].successors[1].as_bytes(),
                &bad[1].successors
            ),
            Ok(())
        );
        // A newly caught-up member checks the exact current Root without
        // successors. Signature verification alone also accepts this early
        // response; its authenticated history bound must reject it.
        assert_eq!(
            standalone.verify(&bad[1].binding, bad[1].successors[0].as_bytes(), &[]),
            Ok(())
        );
        let mut complete =
            ProductRootReplay::new("pinvou", std::str::from_utf8(original).unwrap()).unwrap();
        advance(&mut complete, &batches[0]).unwrap();
        advance(&mut complete, &batches[1]).unwrap();
        let bound = complete.finish_latest_issue(2, 3, &expected_head).unwrap();
        assert_eq!(
            check_history_time_bound(bound, standalone.earliest),
            Err(Error::StateCorrupt)
        );
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut cursor =
            ProductRootReplay::new("pinvou", std::str::from_utf8(original).unwrap()).unwrap();
        advance(&mut cursor, &batches[0]).unwrap();
        assert_eq!(advance(&mut cursor, &bad[1]), Err(Error::StateCorrupt));
        advance(&mut cursor, &batches[1]).unwrap();
        assert_eq!(cursor.finish(2, 3, &expected_head), Ok(()));
        // Change a signature while preserving canonical envelope encoding.
        let mut bad = batches.clone();
        let mut response: serde_json::Value =
            serde_json::from_str(&bad[1].evidence.response).unwrap();
        let signature = response["signatures"][0]["signature"].as_str().unwrap();
        let replacement = if signature.starts_with('A') { "B" } else { "A" };
        response["signatures"][0]["signature"] =
            format!("{}{}", replacement, &signature[1..]).into();
        bad[1].evidence.response = serde_json::to_string(&response).unwrap();
        assert!(
            decode_canonical_envelope(bad[1].evidence.response.as_bytes(), InputKind::Credential)
                .unwrap()
                .check_full_schema()
                .is_ok()
        );
        let mut altered = bad[1].evidence.clone();
        altered.base_root_count = 0;
        assert_eq!(
            altered.verify(
                &bad[1].binding,
                bad[0].successors[1].as_bytes(),
                &bad[1].successors
            ),
            Err(Error::StateCorrupt)
        );
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut bad_root = batches.clone();
        let mut root: serde_json::Value = serde_json::from_str(&bad_root[0].successors[0]).unwrap();
        let signature = root["signatures"][0]["signature"].as_str().unwrap();
        let replacement = if signature.starts_with('A') { "B" } else { "A" };
        root["signatures"][0]["signature"] = format!("{}{}", replacement, &signature[1..]).into();
        bad_root[0].successors[0] = serde_json::to_string(&root).unwrap();
        assert!(
            decode_canonical_envelope(bad_root[0].successors[0].as_bytes(), InputKind::Metadata)
                .unwrap()
                .check_full_schema()
                .is_ok()
        );
        assert_eq!(replay(&bad_root), Err(Error::StateCorrupt));
        let mut denied = batches[1].clone();
        let signer = response["signatures"][0]["keyId"]
            .as_str()
            .unwrap()
            .to_owned();
        denied.member_denies.push(vec![signer]);
        let mut cursor =
            ProductRootReplay::new("pinvou", std::str::from_utf8(original).unwrap()).unwrap();
        advance(&mut cursor, &batches[0]).unwrap();
        assert_eq!(advance(&mut cursor, &denied), Err(Error::ScopeConflict));
        assert_eq!(
            cursor.advance(
                &batches[1].batch,
                |i| Ok(batches[1].successors[i].as_bytes().to_vec()),
                |_| Err(Error::Unavailable)
            ),
            Err(Error::Unavailable)
        );
        assert_eq!(
            cursor.advance(
                &batches[1].batch,
                |i| Ok(batches[1].successors[i].as_bytes().to_vec()),
                |visit| {
                    let _ = visit(denied.member_denies.last().unwrap());
                    Ok(())
                }
            ),
            Err(Error::ScopeConflict)
        );
        advance(&mut cursor, &batches[1]).unwrap();
        assert_eq!(cursor.finish(2, 3, &expected_head), Ok(()));
        let mut many = batches.clone();
        many[1]
            .member_denies
            .extend((0..4097).map(|i| vec![format!("{i:064x}")]));
        assert_eq!(replay(&many), Ok(()));
        many[1]
            .member_denies
            .push(denied.member_denies.last().unwrap().clone());
        assert_eq!(replay(&many), Err(Error::ScopeConflict));
        let mut limits = batches.clone();
        limits[1]
            .member_denies
            .push((0..4096).map(|i| format!("{i:064x}")).collect());
        assert_eq!(replay(&limits), Ok(()));
        limits[1]
            .member_denies
            .last_mut()
            .unwrap()
            .push(format!("{:064x}", 4096));
        assert_eq!(replay(&limits), Err(Error::StateCorrupt));
        let mut bad = batches.clone();
        bad[1].member_denies = vec![vec!["f".repeat(64); 4097]];
        assert_eq!(replay(&bad), Err(Error::StateCorrupt));
        let mut cursor =
            ProductRootReplay::new("pinvou", std::str::from_utf8(original).unwrap()).unwrap();
        advance(&mut cursor, &batches[0]).unwrap();
        assert_eq!(advance(&mut cursor, &bad[1]), Err(Error::StateCorrupt));
        advance(&mut cursor, &batches[1]).unwrap();
        assert_eq!(
            cursor.finish(1, 3, &expected_head),
            Err(Error::StateCorrupt)
        );
        assert_eq!(
            cursor.finish(2, 2, &expected_head),
            Err(Error::StateCorrupt)
        );
        assert_eq!(
            cursor.finish(2, 3, &"f".repeat(64)),
            Err(Error::StateCorrupt)
        );
        assert_eq!(cursor.finish(2, 3, &expected_head), Ok(()));
        assert_eq!(
            cursor.finish_root(2, 3, &expected_head).unwrap(),
            batches[1].successors.last().unwrap().as_bytes()
        );
        assert!(cursor.finish_root(2, 3, &"f".repeat(64)).is_err());
    }

    fn vector() -> serde_json::Value {
        serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../../../specs/upgrade/v1/vectors/time/anchor.json"
        )))
        .unwrap()
    }
    fn binding() -> Binding {
        Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-nsis-perMachine".into(),
            profile_kind: "production".into(),
            profile_id: "host".into(),
            genesis_seed_sha256: "a".repeat(64),
            genesis_manifest_sha256: "b".repeat(64),
            original_install_operation_id: "original".into(),
        }
    }
    fn policy() -> Policy {
        Policy {
            protocol_version: 1,
            binding: binding(),
            max_round_trip_ms: 20,
            max_uncertainty_ms: 5,
            denied_key_ids: Vec::new(),
        }
    }
    fn incarnation(epoch: u64) -> Incarnation {
        Incarnation {
            host_epoch: epoch,
            instance_nonce: "c".repeat(64),
            process: ProcessSelector {
                process_id: 3,
                creation_file_time: crate::identity::FileTime::from_native(1, 2),
            },
        }
    }
    fn anchored() -> (State, Vec<u8>, Vec<u8>) {
        let v = vector();
        let c = &v["cases"][0];
        let original = c["trustedRootBytes"].as_str().unwrap().as_bytes().to_vec();
        let initial = State::genesis(binding(), &original).unwrap();
        let before = json::encode(&initial, false).unwrap();
        let unknown = initial.next_unknown(incarnation(1), &before).unwrap();
        let raw = json::encode(&unknown, false).unwrap();
        let mut s = unknown.clone();
        s.revision += 1;
        s.previous_sha256 = Some(json::sha256(&raw));
        s.status = Status::CleanupPending;
        s.roots = c["rootSuccessors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect();
        s.floor = Some(c["expected"]["earliest"].as_u64().unwrap());
        s.evidence = Some(Evidence {
            incarnation: incarnation(1),
            request: serde_json::to_string(&c["request"]).unwrap(),
            response: c["responseBytes"].as_str().unwrap().into(),
            sent: CounterEvidence::from_data(
                CounterObservation::from_bracket(10_000_000, 9_000_000, 9_000_000, 10_000_000)
                    .unwrap(),
            ),
            received: CounterEvidence::from_data(
                CounterObservation::from_bracket(10_200_000, 9_200_000, 9_200_000, 10_200_000)
                    .unwrap(),
            ),
            policy: String::from_utf8(json::encode(&policy(), false).unwrap()).unwrap(),
            floor_before: 0,
            base_root_count: 0,
            denied_key_ids: Vec::new(),
            earliest: s.floor.unwrap(),
            latest: c["expected"]["latest"].as_u64().unwrap(),
        });
        unknown.transition(&s, &raw, &original).unwrap();
        (s, raw, original)
    }
    #[test]
    fn policy_fault_preserves_original_state_and_survives_reopen_and_incarnation_change() {
        let (mut state, _, original) = anchored();
        state.denied_key_ids.push("f".repeat(64));
        state.validate(&original).unwrap();
        let before = json::encode(&state, false).unwrap();
        let fault = state
            .next_policy_fault(incarnation(1), &before, "a".repeat(64))
            .unwrap();
        state.transition(&fault, &before, &original).unwrap();
        assert!(
            fault.status == Status::Unknown
                && fault.cleanup_pending
                && fault.zero_retention.is_none()
        );
        assert!(
            fault.floor == state.floor
                && fault.roots == state.roots
                && fault.evidence == state.evidence
                && fault.denied_key_ids == state.denied_key_ids
        );
        let raw = json::encode(&fault, false).unwrap();
        let reopened = State::parse(&raw, &original).unwrap();
        let next = reopened.next_unknown(incarnation(2), &raw).unwrap();
        reopened.transition(&next, &raw, &original).unwrap();
        assert!(next.policy_fault == fault.policy_fault);
        assert!(
            next.next_policy_fault(
                incarnation(2),
                &json::encode(&next, false).unwrap(),
                "b".repeat(64)
            )
            .is_err()
        );
        // Restored valid policy bytes and an old signed anchor are not recovery.
        assert!(
            fault
                .anchor_for_live(
                    state.evidence.as_ref().unwrap().policy.as_bytes(),
                    &incarnation(1)
                )
                .is_err()
        );
        let mut erased = next;
        erased.policy_fault = None;
        assert!(fault.transition(&erased, &raw, &original).is_err());
    }
    #[test]
    fn policy_fault_closes_only_with_a_new_anchor_and_zero_completion_shape() {
        // Real public signed vector DATA, not an installed SCM or live source.
        let (signed, _, original) = anchored();
        let initial = State::genesis(binding(), &original).unwrap();
        let before = json::encode(&initial, false).unwrap();
        let fault = initial
            .next_policy_fault(incarnation(1), &before, "a".repeat(64))
            .unwrap();
        initial.transition(&fault, &before, &original).unwrap();
        let fault_raw = json::encode(&fault, false).unwrap();
        let mut pending = signed;
        pending.revision = fault.revision + 1;
        pending.previous_sha256 = Some(json::sha256(&fault_raw));
        pending.policy_fault = fault.policy_fault.clone();
        fault.transition(&pending, &fault_raw, &original).unwrap();
        let pending_raw = json::encode(&pending, false).unwrap();
        let mut completed = pending.clone();
        completed.revision += 1;
        completed.previous_sha256 = Some(json::sha256(&pending_raw));
        completed.status = Status::CleanupVerifiedZero;
        completed.cleanup_pending = false;
        completed.zero_retention = Some(crate::retention_custody::ZeroRetentionReference {
            completion_revision: completed.revision,
            completion_sha256: "b".repeat(64),
        });
        // Active incidents cannot be ignored by an otherwise complete shape.
        assert!(
            pending
                .transition(&completed, &pending_raw, &original)
                .is_err()
        );
        completed.policy_fault = pending
            .policy_fault
            .as_ref()
            .map(|f| f.recovered(completed.revision));
        pending
            .transition(&completed, &pending_raw, &original)
            .unwrap();
        assert!(!completed.policy_fault.as_ref().unwrap().is_active());
        let raw = json::encode(&completed, false).unwrap();
        let future = completed.next_unknown(incarnation(2), &raw).unwrap();
        completed.transition(&future, &raw, &original).unwrap();
        assert!(future.policy_fault == completed.policy_fault); // History not erased.
        let future_raw = json::encode(&future, false).unwrap();
        let again = future
            .next_policy_fault(incarnation(2), &future_raw, "c".repeat(64))
            .unwrap();
        future.transition(&again, &future_raw, &original).unwrap();
        assert!(again.policy_fault.as_ref().unwrap().is_active());
        assert!(completed.policy_fault != again.policy_fault);
    }
    #[test]
    fn active_policy_fault_rejects_replayed_anchor_and_mutated_incident() {
        let (state, _, original) = anchored();
        let raw = json::encode(&state, false).unwrap();
        let fault = state
            .next_policy_fault(incarnation(1), &raw, "a".repeat(64))
            .unwrap();
        let fault_raw = json::encode(&fault, false).unwrap();
        let mut replayed = state.clone();
        replayed.revision = fault.revision + 1;
        replayed.previous_sha256 = Some(json::sha256(&fault_raw));
        replayed.policy_fault = fault.policy_fault.clone();
        assert!(fault.transition(&replayed, &fault_raw, &original).is_err());
        for (field, value) in [
            ("detectedRevision", serde_json::json!(0)),
            ("previousTimeSha256", serde_json::json!("b".repeat(64))),
            ("policySha256", serde_json::json!("invalid")),
            ("recoveredRevision", serde_json::json!(fault.revision)),
            ("kind", serde_json::json!("offline")),
        ] {
            let mut bad = serde_json::to_value(&fault).unwrap();
            bad["policyFault"][field] = value;
            assert!(State::parse(&json::encode(&bad, false).unwrap(), &original).is_err());
        }
    }
    #[test]
    fn live_anchor_data_rejects_unknown_policy_deny_and_cross_incarnation() {
        // DATA controls using an actual public signature vector. This helper
        // does not mint a native live source or a successful SCM fixture.
        let (state, _, _) = anchored();
        let policy = state.evidence.as_ref().unwrap().policy.as_bytes();
        let current_incarnation = state.incarnation.as_ref().unwrap();
        state.anchor_for_live(policy, current_incarnation).unwrap();
        let mut unknown = state.clone();
        unknown.status = Status::Unknown;
        assert!(
            unknown
                .anchor_for_live(policy, current_incarnation)
                .is_err()
        );
        assert!(state.anchor_for_live(policy, &incarnation(2)).is_err());
        let mut changed: Policy = json::decode(policy, false).unwrap();
        changed.max_round_trip_ms += 1;
        assert!(
            state
                .anchor_for_live(&json::encode(&changed, false).unwrap(), current_incarnation)
                .is_err()
        );
        let mut denied = state.clone();
        denied.denied_key_ids.push("a".repeat(64));
        assert!(denied.anchor_for_live(policy, current_incarnation).is_err());
        let mut absent = state.clone();
        absent.evidence = None;
        assert!(absent.anchor_for_live(policy, current_incarnation).is_err());
    }
    #[test]
    fn retained_real_signature_vector_rejects_response_root_nonce_and_floor_mutation() {
        let (s, _, original) = anchored();
        let bytes = json::encode(&s, false).unwrap();
        State::parse(&bytes, &original).unwrap();
        for change in 0..4 {
            let mut bad = s.clone();
            match change {
                0 => bad.floor = Some(bad.floor.unwrap() + 1),
                1 => {
                    bad.evidence.as_mut().unwrap().response = bad
                        .evidence
                        .as_ref()
                        .unwrap()
                        .response
                        .replace("1700000000100", "1700000000101")
                }
                2 => {
                    bad.evidence.as_mut().unwrap().request = bad
                        .evidence
                        .as_ref()
                        .unwrap()
                        .request
                        .replace("BwcHBwc", "AwcHBwc")
                }
                _ => bad.roots.clear(),
            }
            assert!(bad.validate(&original).is_err());
        }
    }
    #[test]
    fn incarnation_unknown_retains_floor_original_evidence_and_uncleared_barrier() {
        let (s, _, original) = anchored();
        let raw = json::encode(&s, false).unwrap();
        let next = s.next_unknown(incarnation(2), &raw).unwrap();
        s.transition(&next, &raw, &original).unwrap();
        assert!(next.status == Status::Unknown && next.cleanup_pending && next.floor == s.floor);
        assert!(next.evidence.as_ref().unwrap().incarnation == incarnation(1));
        assert!(next.incarnation == Some(incarnation(2)));
        let next_raw = json::encode(&next, false).unwrap();
        let mut stale = next.clone();
        stale.revision += 1;
        stale.previous_sha256 = Some(json::sha256(&next_raw));
        stale.status = Status::CleanupPending;
        let e = stale.evidence.as_mut().unwrap();
        e.floor_before = next.floor.unwrap();
        e.base_root_count = next.roots.len();
        // Historical counters must retain the original incarnation and cannot
        // become a fresh anchor merely by changing the current incarnation.
        assert!(next.transition(&stale, &next_raw, &original).is_err());
        let mut bad = next.clone();
        bad.floor = None;
        assert!(s.transition(&bad, &raw, &original).is_err());
        let mut bad = next.clone();
        bad.cleanup_pending = false;
        assert!(bad.validate(&original).is_err());
        let mut bad = next;
        bad.binding.genesis_manifest_sha256 = "d".repeat(64);
        assert!(s.transition(&bad, &raw, &original).is_err());
    }
    #[test]
    fn observed_deny_survives_failed_refresh_and_cannot_be_omitted_from_new_evidence() {
        let (old, _, original) = anchored();
        let raw = json::encode(&old, false).unwrap();
        let mut pending = old.next_unknown(incarnation(1), &raw).unwrap();
        pending.denied_key_ids.push("a".repeat(64));
        old.transition(&pending, &raw, &original).unwrap();
        let saved = json::encode(&pending, false).unwrap();
        let mut forgotten = pending.next_unknown(incarnation(1), &saved).unwrap();
        forgotten.denied_key_ids.clear();
        assert!(pending.transition(&forgotten, &saved, &original).is_err());
        // The real signed vector is reused only as DATA to isolate this
        // transition guard; this does not assert a new live nonce/SCM source.
        let mut fresh = pending.clone();
        fresh.revision += 1;
        fresh.previous_sha256 = Some(json::sha256(&saved));
        fresh.status = Status::CleanupPending;
        let e = fresh.evidence.as_mut().unwrap();
        e.floor_before = pending.floor.unwrap();
        e.base_root_count = pending.roots.len();
        assert!(pending.transition(&fresh, &saved, &original).is_err());
        fresh.evidence.as_mut().unwrap().denied_key_ids = pending.denied_key_ids.clone();
        pending.transition(&fresh, &saved, &original).unwrap();
    }
    #[test]
    fn policy_has_no_missing_defaults_and_is_bound_to_original_scope() {
        let p = policy();
        let raw = json::encode(&p, false).unwrap();
        Policy::parse(&raw, &binding()).unwrap();
        let mut other = binding();
        other.installation_scope_id = "other".into();
        assert!(Policy::parse(&raw, &other).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        v.as_object_mut().unwrap().remove("maxUncertaintyMs");
        assert!(Policy::parse(&json::encode(&v, false).unwrap(), &binding()).is_err());
        let mut zero = p;
        zero.max_round_trip_ms = 0;
        zero.max_uncertainty_ms = 0;
        Policy::parse(&json::encode(&zero, false).unwrap(), &binding()).unwrap();
    }
    #[test]
    fn counter_evidence_never_accepts_alias_ticks_or_independently_truncated_bounds() {
        let mut c = CounterEvidence::from_data(
            CounterObservation::from_bracket(9999, 9000, 9001, 10001).unwrap(),
        );
        assert_eq!(
            c.data()
                .unwrap()
                .suspend_inclusive()
                .floor_millis()
                .unwrap(),
            0
        );
        assert_eq!(
            c.data().unwrap().suspend_inclusive().ceil_millis().unwrap(),
            2
        );
        c.interrupt_before = "09999".into();
        assert!(c.data().is_err());
    }
    #[test]
    fn zero_completion_changes_no_anchor_and_unknown_cannot_retain_it() {
        // Administrative transition DATA only. The native publisher alone must
        // authenticate the referenced custody/completion and actual read set.
        let (pending, _, original) = anchored();
        let before = json::encode(&pending, false).unwrap();
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&before)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("zeroRetention")
        );
        let mut complete = pending.clone();
        complete.revision += 1;
        complete.previous_sha256 = Some(json::sha256(&before));
        complete.status = Status::CleanupVerifiedZero;
        complete.cleanup_pending = false;
        complete.zero_retention = Some(crate::retention_custody::ZeroRetentionReference {
            completion_revision: complete.revision,
            completion_sha256: "a".repeat(64),
        });
        pending.transition(&complete, &before, &original).unwrap();
        for field in ["floor", "cleanupPending", "zeroRetention"] {
            let mut value = serde_json::to_value(&complete).unwrap();
            value[field] = match field {
                "floor" => serde_json::json!(0),
                "cleanupPending" => serde_json::json!(true),
                _ => serde_json::Value::Null,
            };
            assert!(State::parse(&json::encode(&value, false).unwrap(), &original).is_err());
        }
        let raw = json::encode(&complete, false).unwrap();
        let unknown = complete.next_unknown(incarnation(2), &raw).unwrap();
        complete.transition(&unknown, &raw, &original).unwrap();
        assert!(unknown.cleanup_pending && unknown.zero_retention.is_none());
        assert!(
            unknown.floor == complete.floor
                && unknown.evidence == complete.evidence
                && unknown.roots == complete.roots
        );
        let mut forged = complete.clone();
        forged.denied_key_ids.push("f".repeat(64));
        assert!(pending.transition(&forged, &before, &original).is_err());
    }
}
