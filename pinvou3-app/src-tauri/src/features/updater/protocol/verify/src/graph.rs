//! Complete public graph under supplied existing trust; no persistent acceptance.
use crate::{VerificationError, VerificationInputs, verify_with_supplied_root};
use pinvou_upgrade_codec::{
    Document, InputKind, MetadataReferenceError, PublicGraphError, RootPolicyShape,
    SchemaCheckedEnvelope, SuppliedProtocolTime, assert_supplied_public_graph,
    assert_supplied_public_graph_source, derive_metadata_reference,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicChainError {
    Verification(VerificationError),
    Graph(PublicGraphError),
    InvalidInterval,
    SourceUnavailable,
}
impl std::fmt::Display for PublicChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verification(error) => error.fmt(f),
            Self::Graph(error) => error.fmt(f),
            Self::InvalidInterval => f.write_str("PUBLIC_CHAIN_INTERVAL_INVALID"),
            Self::SourceUnavailable => f.write_str("PUBLIC_CHAIN_SOURCE_UNAVAILABLE"),
        }
    }
}

/// Result of checking the caller-supplied originals, not a protected source,
/// committed state, trusted time, or installation authority. It retains only
/// bounded reference data rather than the member originals.
pub struct SignatureCheckedPublicSourceInterval {
    member_count: usize,
    earliest: f64,
    latest: f64,
}
impl SignatureCheckedPublicSourceInterval {
    pub fn member_count(&self) -> usize {
        self.member_count
    }
    pub fn earliest_millis(&self) -> f64 {
        self.earliest
    }
    pub fn latest_millis(&self) -> f64 {
        self.latest
    }
}

/// Verify an exact Snapshot member inventory by reading one bounded original at
/// a time. Each repeated read is checked against the same reference and signed
/// Snapshot; source errors are never converted into missing/empty objects.
/// The caller must maintain an immutable protected source, authenticate Root,
/// time and denials, and recheck them and atomic persistence before any use.
/// The source must enforce the per-object byte limit before allocating each
/// returned buffer; validation here cannot reverse an earlier allocation.
/// If multiple inputs are invalid, the first error may differ from the slice
/// API because source and endpoint checks run in a different order.
pub fn verify_public_chain_source_interval(
    timestamp_bytes: &[u8],
    snapshot_bytes: &[u8],
    member_count: usize,
    mut read: impl FnMut(usize) -> Result<Vec<u8>, PublicChainError>,
    inputs: PublicChainInputs<'_>,
    latest: &SuppliedProtocolTime,
) -> Result<SignatureCheckedPublicSourceInterval, PublicChainError> {
    let earliest = inputs.now.as_millis();
    let latest_millis = latest.as_millis();
    if earliest > latest_millis {
        return Err(PublicChainError::InvalidInterval);
    }
    let latest_inputs = PublicChainInputs {
        root: inputs.root,
        context: inputs.context,
        now: latest,
        denied: inputs.denied,
        denied_by_role: inputs.denied_by_role.clone(),
    };
    let timestamp = verify_member(timestamp_bytes, "\"timestamp\"", "{}", &inputs)?;
    let snapshot = verify_member(snapshot_bytes, "\"snapshot\"", "{}", &inputs)?;
    let timestamp_last = verify_member(timestamp_bytes, "\"timestamp\"", "{}", &latest_inputs)?;
    let snapshot_last = verify_member(snapshot_bytes, "\"snapshot\"", "{}", &latest_inputs)?;
    parse(
        timestamp.envelope().signed().value()["snapshot"]
            .to_string()
            .as_bytes(),
    )?
    .metadata_reference_shape()
    .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?
    .assert_original_envelope(snapshot_bytes)
    .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?;
    let entries = snapshot.envelope().signed().value()["entries"]
        .as_array()
        .ok_or(PublicChainError::Graph(PublicGraphError::InvalidFields))?;
    if member_count > entries.len() {
        return Err(PublicChainError::Graph(
            PublicGraphError::MemberUnreferenced,
        ));
    }
    // Bind each reference to the authenticated bounded Snapshot before
    // retaining it; otherwise a hostile source could accumulate thousands of
    // large, unrelated scopes before the graph comparison rejects them.
    let mut declared = BTreeMap::new();
    for entry in entries {
        let expected = parse(entry.to_string().as_bytes())?
            .metadata_reference_shape()
            .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?;
        let hash = entry["envelopeSha256"]
            .as_str()
            .ok_or(PublicChainError::Graph(PublicGraphError::InvalidFields))?;
        if declared.insert(hash, expected).is_some() {
            return Err(PublicChainError::Graph(PublicGraphError::MemberDuplicate));
        }
    }
    let mut references = Vec::with_capacity(member_count);
    let mut seen = BTreeSet::new();
    for index in 0..member_count {
        let raw = read(index)?;
        let actual = derive_metadata_reference(&raw)
            .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?;
        let fields = parse(actual.canonical_bytes())?;
        let hash = fields.value()["envelopeSha256"]
            .as_str()
            .ok_or(PublicChainError::Graph(PublicGraphError::InvalidFields))?;
        let expected = declared.get(hash).ok_or(PublicChainError::Graph(
            PublicGraphError::MemberUnreferenced,
        ))?;
        if actual.canonical_bytes() != expected.canonical_bytes() {
            return Err(PublicChainError::Graph(PublicGraphError::Reference(
                MetadataReferenceError::Mismatch,
            )));
        }
        if !seen.insert(hash.to_owned()) {
            return Err(PublicChainError::Graph(PublicGraphError::MemberDuplicate));
        }
        references.push(actual);
    }
    for (ts, sn, now_inputs) in [
        (&timestamp, &snapshot, &inputs),
        (&timestamp_last, &snapshot_last, &latest_inputs),
    ] {
        let mut failure = None;
        let result =
            assert_supplied_public_graph_source(ts, sn, &references, inputs.context, |index| {
                let attempt = (|| {
                    let raw = read(index)?;
                    references[index]
                        .assert_original_envelope(&raw)
                        .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?;
                    let reference = parse(references[index].canonical_bytes())?;
                    verify_member(
                        &raw,
                        &reference.value()["role"].to_string(),
                        &reference.value()["scope"].to_string(),
                        now_inputs,
                    )
                })();
                attempt.map_err(|error| {
                    failure = Some(error);
                    PublicGraphError::InvalidFields
                })
            });
        if let Some(error) = failure {
            return Err(error);
        }
        result.map_err(PublicChainError::Graph)?;
    }
    Ok(SignatureCheckedPublicSourceInterval {
        member_count,
        earliest,
        latest: latest_millis,
    })
}

/// A complete chain checked over caller-supplied inclusive time bounds. These
/// bounds are DATA, not an attested clock, persistence or upgrade authority.
pub struct SignatureCheckedPublicInterval<'a> {
    chain: SignatureCheckedPublicChain<'a>,
    earliest: f64,
    latest: f64,
}
impl<'a> SignatureCheckedPublicInterval<'a> {
    pub fn chain(&self) -> &SignatureCheckedPublicChain<'a> {
        &self.chain
    }
    pub fn earliest_millis(&self) -> f64 {
        self.earliest
    }
    pub fn latest_millis(&self) -> f64 {
        self.latest
    }
}

/// Verify the same bytes, Root, scope and denials at both inclusive bounds.
/// The current complete public-chain rules only compare time to each Root or
/// non-Package object's single [issuedAt, expiresAt) window. All other checks
/// are time-independent, so success at both endpoints covers the whole interval.
/// Callers must separately obtain and freshly recheck a trusted interval,
/// denial state, high waters, protected persistence and online qualification.
pub fn verify_public_chain_interval<'a>(
    timestamp_bytes: &[u8],
    snapshot_bytes: &[u8],
    member_bytes: &[&[u8]],
    inputs: PublicChainInputs<'a>,
    latest: &'a SuppliedProtocolTime,
) -> Result<SignatureCheckedPublicInterval<'a>, PublicChainError> {
    let earliest = inputs.now.as_millis();
    let latest_millis = latest.as_millis();
    if earliest > latest_millis {
        return Err(PublicChainError::InvalidInterval);
    }
    let latest_inputs = PublicChainInputs {
        root: inputs.root,
        context: inputs.context,
        now: latest,
        denied: inputs.denied,
        denied_by_role: inputs.denied_by_role.clone(),
    };
    verify_public_chain(timestamp_bytes, snapshot_bytes, member_bytes, inputs)?;
    let chain = verify_public_chain(timestamp_bytes, snapshot_bytes, member_bytes, latest_inputs)?;
    Ok(SignatureCheckedPublicInterval {
        chain,
        earliest,
        latest: latest_millis,
    })
}
impl std::error::Error for PublicChainError {}

/// Independent context and caller-owned existing trust/time/denial facts.
/// This operation deliberately has no high-water or Development option.
pub struct PublicChainInputs<'a> {
    root: &'a RootPolicyShape,
    context: &'a Document,
    now: &'a SuppliedProtocolTime,
    denied: &'a [String],
    denied_by_role: BTreeMap<&'a str, &'a [String]>,
}
impl<'a> PublicChainInputs<'a> {
    pub fn new(
        root: &'a RootPolicyShape,
        context: &'a Document,
        now: &'a SuppliedProtocolTime,
    ) -> Self {
        Self {
            root,
            context,
            now,
            denied: &[],
            denied_by_role: BTreeMap::new(),
        }
    }
    pub fn with_denied_key_ids(mut self, ids: &'a [String]) -> Self {
        self.denied = ids;
        self
    }
    /// Only the corresponding verified role consults this entry; other entries
    /// are ignored as in the frozen operation. This is a trusted caller input.
    pub fn with_role_denied_key_ids(mut self, role: &'a str, ids: &'a [String]) -> Self {
        self.denied_by_role.insert(role, ids);
        self
    }
}

/// Authenticated original objects only. This does not reproduce the reference's
/// derived result arrays, attest protected custody or grant current online rights.
pub struct SignatureCheckedPublicChain<'a> {
    timestamp: SchemaCheckedEnvelope,
    snapshot: SchemaCheckedEnvelope,
    members: Vec<SchemaCheckedEnvelope>,
    root: &'a RootPolicyShape,
    supplied_now: f64,
}
impl SignatureCheckedPublicChain<'_> {
    pub fn timestamp(&self) -> &SchemaCheckedEnvelope {
        &self.timestamp
    }
    pub fn snapshot(&self) -> &SchemaCheckedEnvelope {
        &self.snapshot
    }
    /// Original input order, after exact complete Snapshot membership checking.
    pub fn members(&self) -> &[SchemaCheckedEnvelope] {
        &self.members
    }
    pub fn supplied_root(&self) -> &RootPolicyShape {
        self.root
    }
    pub fn supplied_time_millis(&self) -> f64 {
        self.supplied_now
    }
}

/// Compose the frozen complete public-chain operation. Every original object
/// passes ordinary fresh-Root, Production and all-signature checks; relationships
/// are checked by the unchanged codec. No valid prefix is returned after failure.
pub fn verify_public_chain<'a>(
    timestamp_bytes: &[u8],
    snapshot_bytes: &[u8],
    member_bytes: &[&[u8]],
    inputs: PublicChainInputs<'a>,
) -> Result<SignatureCheckedPublicChain<'a>, PublicChainError> {
    let timestamp = verify_member(timestamp_bytes, "\"timestamp\"", "{}", &inputs)?;
    parse(
        timestamp.envelope().signed().value()["snapshot"]
            .to_string()
            .as_bytes(),
    )?
    .metadata_reference_shape()
    .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?
    .assert_original_envelope(snapshot_bytes)
    .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?;
    let snapshot = verify_member(snapshot_bytes, "\"snapshot\"", "{}", &inputs)?;
    let entries = snapshot.envelope().signed().value()["entries"]
        .as_array()
        .ok_or(PublicChainError::Graph(PublicGraphError::InvalidFields))?;
    // This necessary bound follows the original exact membership equality. It
    // is not an independent aggregate byte policy or artifact download limit.
    if member_bytes.len() > entries.len() {
        return Err(PublicChainError::Graph(
            PublicGraphError::MemberUnreferenced,
        ));
    }
    let mut available = BTreeMap::new();
    let mut references = Vec::with_capacity(member_bytes.len());
    for (index, bytes) in member_bytes.iter().enumerate() {
        let reference = derive_metadata_reference(bytes)
            .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?;
        let fields = parse(reference.canonical_bytes())?;
        let hash = fields.value()["envelopeSha256"]
            .as_str()
            .ok_or(PublicChainError::Graph(PublicGraphError::InvalidFields))?
            .to_owned();
        if available.insert(hash, index).is_some() {
            return Err(PublicChainError::Graph(PublicGraphError::MemberDuplicate));
        }
        references.push(reference);
    }
    let mut checked: Vec<Option<SchemaCheckedEnvelope>> =
        (0..member_bytes.len()).map(|_| None).collect();
    for reference in entries {
        let hash = reference["envelopeSha256"]
            .as_str()
            .ok_or(PublicChainError::Graph(PublicGraphError::InvalidFields))?;
        let index = *available
            .get(hash)
            .ok_or(PublicChainError::Graph(PublicGraphError::MemberMissing))?;
        let expected_reference = parse(reference.to_string().as_bytes())?
            .metadata_reference_shape()
            .map_err(|e| PublicChainError::Graph(PublicGraphError::Reference(e)))?;
        if expected_reference.canonical_bytes() != references[index].canonical_bytes() {
            return Err(PublicChainError::Graph(PublicGraphError::Reference(
                MetadataReferenceError::Mismatch,
            )));
        }
        if checked[index].is_none() {
            checked[index] = Some(verify_member(
                member_bytes[index],
                &reference["role"].to_string(),
                &reference["scope"].to_string(),
                &inputs,
            )?);
        }
    }
    let members = checked
        .into_iter()
        .map(|item| {
            item.ok_or(PublicChainError::Graph(
                PublicGraphError::MemberUnreferenced,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_supplied_public_graph(&timestamp, &snapshot, &members, inputs.context)
        .map_err(PublicChainError::Graph)?;
    Ok(SignatureCheckedPublicChain {
        timestamp,
        snapshot,
        members,
        root: inputs.root,
        supplied_now: inputs.now.as_millis(),
    })
}

fn parse(bytes: &[u8]) -> Result<Document, PublicChainError> {
    Document::parse(bytes, InputKind::Metadata)
        .map_err(|e| PublicChainError::Graph(PublicGraphError::Json(e)))
}
fn verify_member(
    bytes: &[u8],
    role_json: &str,
    scope_json: &str,
    inputs: &PublicChainInputs<'_>,
) -> Result<SchemaCheckedEnvelope, PublicChainError> {
    // Value Display performs JSON escaping. Only bounded independent Document
    // fields and full-Schema authenticated Snapshot fields reach this helper.
    let expected = parse(
        format!(
            "{{\"role\":{},\"product\":{},\"component\":{},\"scope\":{}}}",
            role_json,
            inputs.context.value()["product"],
            inputs.context.value()["component"],
            scope_json,
        )
        .as_bytes(),
    )?;
    let role = expected.value()["role"]
        .as_str()
        .ok_or(PublicChainError::Graph(PublicGraphError::InvalidRole))?;
    let role_denied = inputs.denied_by_role.get(role).copied().unwrap_or(&[]);
    let denied: Vec<String> = inputs.denied.iter().chain(role_denied).cloned().collect();
    let proof = verify_with_supplied_root(
        bytes,
        VerificationInputs::new(inputs.root, &expected, inputs.now).with_denied_key_ids(&denied),
    )
    .map_err(PublicChainError::Verification)?;
    // Consume the private successful proof immediately. No reference to its
    // temporary expected context or denial collection escapes this helper.
    Ok(proof.envelope)
}
