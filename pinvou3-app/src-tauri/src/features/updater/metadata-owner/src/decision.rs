//! Pure metadata decisions over supplied trust and a complete protected read set.
//! Results are not durable acceptance, a trusted clock, or installation authority.
use std::collections::{BTreeMap, BTreeSet};

use pinvou_upgrade_codec::{
    Document, HighWaterError, InputKind, RootPolicyShape, SchemaCheckedEnvelope,
    SuppliedProtocolTime, assert_supplied_high_water, decode_canonical_envelope,
};
use pinvou_upgrade_verifier::{
    PublicChainInputs, ReleaseRenewalInputs, verify_public_chain_interval, verify_release_renewal,
};
use serde_json::json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionError {
    InvalidInput,
    Verification,
    PriorUnavailable,
    InvalidPrior,
    Rollback,
    Equivocation,
    ReleaseRenewal,
}

/// Prior facts read from the caller's authenticated protected snapshot.
/// For an advancing Release, its exact previous original and the authenticated
/// historical Root that accepted it must be supplied as well.
pub struct PriorWater<'a> {
    pub record: &'a Document,
    pub previous_release: Option<(&'a [u8], &'a RootPolicyShape)>,
}

/// All inputs are caller-supplied facts: none prove protected storage or time.
pub struct DecisionInputs<'a> {
    pub root: &'a RootPolicyShape,
    pub context: &'a Document,
    pub earliest: &'a SuppliedProtocolTime,
    pub latest: &'a SuppliedProtocolTime,
    pub denied: &'a [String],
    pub denied_by_role: &'a BTreeMap<String, Vec<String>>,
}

/// A bounded, fully checked proposed high-water update. No caller may create
/// one without completing the whole graph verification and prior comparisons.
pub struct WaterUpdate {
    context: Vec<u8>,
    version: u64,
    sha256: String,
}
impl WaterUpdate {
    pub fn context(&self) -> &[u8] {
        &self.context
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}
pub struct Decision {
    updates: Vec<WaterUpdate>,
}
impl Decision {
    pub fn updates(&self) -> &[WaterUpdate] {
        &self.updates
    }
}

/// Verify a complete public graph and compare every versioned original to its
/// exact context's previous water. The callback is called once per versioned
/// context; `None` is valid only when the protected owner has proved absence.
/// It must fail on unavailable/incomplete storage. The owner must recheck its
/// root, time, deny state and complete read set, then atomically commit all
/// originals, active references and updates before granting any authority.
/// Product Root high water and Root transitions belong to the product owner.
pub fn decide_public_metadata<'a>(
    timestamp: &[u8],
    snapshot: &[u8],
    members: &[&[u8]],
    inputs: DecisionInputs<'a>,
    mut prior: impl FnMut(&Document) -> Result<Option<PriorWater<'a>>, DecisionError>,
) -> Result<Decision, DecisionError> {
    let mut chain_inputs = PublicChainInputs::new(inputs.root, inputs.context, inputs.earliest)
        .with_denied_key_ids(inputs.denied);
    for (role, denied) in inputs.denied_by_role {
        chain_inputs = chain_inputs.with_role_denied_key_ids(role, denied);
    }
    let checked =
        verify_public_chain_interval(timestamp, snapshot, members, chain_inputs, inputs.latest)
            .map_err(|_| DecisionError::Verification)?;
    let mut seen = BTreeSet::new();
    let mut updates = Vec::new();
    for envelope in std::iter::once(checked.chain().timestamp())
        .chain(std::iter::once(checked.chain().snapshot()))
        .chain(checked.chain().members().iter())
    {
        let value = envelope.envelope().signed().value();
        let role = value["role"].as_str().ok_or(DecisionError::InvalidInput)?;
        let version_field = match role {
            "timestamp" | "snapshot" | "target" => "version",
            "release" => "revision",
            "package" => continue,
            _ => return Err(DecisionError::InvalidInput),
        };
        let version = positive_safe(&value[version_field]).ok_or(DecisionError::InvalidInput)?;
        let context = document(&json!({"role":value["role"],"product":value["product"],
            "component":value["component"],"scope":value["scope"]}))?;
        let context_bytes = context
            .canonical_bytes()
            .map_err(|_| DecisionError::InvalidInput)?;
        if !seen.insert(context_bytes.clone()) {
            return Err(DecisionError::InvalidInput);
        }
        if let Some(old) = prior(&context)? {
            let old_version =
                positive_safe(&old.record.value()["version"]).ok_or(DecisionError::InvalidPrior)?;
            let old_hash = old.record.value()["envelopeSha256"]
                .as_str()
                .filter(|s| digest(s))
                .ok_or(DecisionError::InvalidPrior)?;
            assert_supplied_high_water(envelope.envelope(), old.record).map_err(|e| match e {
                HighWaterError::Rollback => DecisionError::Rollback,
                HighWaterError::Equivocation => DecisionError::Equivocation,
                _ => DecisionError::InvalidPrior,
            })?;
            if role == "release" && version > old_version {
                let (old_bytes, old_root) = old
                    .previous_release
                    .ok_or(DecisionError::PriorUnavailable)?;
                if super::sha256(old_bytes) != old_hash {
                    return Err(DecisionError::InvalidPrior);
                }
                let previous = decode_canonical_envelope(old_bytes, InputKind::Metadata)
                    .and_then(|e| {
                        e.check_full_schema()
                            .map_err(|_| pinvou_upgrade_codec::EnvelopeShapeError::InvalidEnvelope)
                    })
                    .map_err(|_| DecisionError::InvalidPrior)?;
                assert_supplied_high_water(previous.envelope(), old.record)
                    .map_err(|_| DecisionError::InvalidPrior)?;
                if positive_safe(&previous.envelope().signed().value()["revision"])
                    != Some(old_version)
                {
                    return Err(DecisionError::InvalidPrior);
                }
                verify_renewal(&previous, envelope, old_root, &inputs)?;
            }
        }
        updates.push(WaterUpdate {
            context: context_bytes,
            version,
            sha256: super::sha256(envelope.envelope().raw_bytes()),
        });
    }
    Ok(Decision { updates })
}

pub(super) fn verify_renewal(
    old: &SchemaCheckedEnvelope,
    next: &SchemaCheckedEnvelope,
    old_root: &RootPolicyShape,
    inputs: &DecisionInputs<'_>,
) -> Result<(), DecisionError> {
    let value = next.envelope().signed().value();
    let context = document(
        &json!({"product":value["product"],"component":value["component"],"releaseId":value["scope"]["releaseId"]}),
    )?;
    let denied: Vec<String> = inputs
        .denied
        .iter()
        .chain(inputs.denied_by_role.get("release").into_iter().flatten())
        .cloned()
        .collect();
    verify_release_renewal(
        old.envelope().raw_bytes(),
        next.envelope().raw_bytes(),
        ReleaseRenewalInputs::new(old_root, inputs.root, &context, inputs.latest)
            .with_denied_key_ids(&denied),
    )
    .map_err(|_| DecisionError::ReleaseRenewal)?;
    Ok(())
}
fn document(v: &serde_json::Value) -> Result<Document, DecisionError> {
    let raw = serde_json::to_vec(v).map_err(|_| DecisionError::InvalidInput)?;
    Document::parse(&raw, InputKind::Metadata).map_err(|_| DecisionError::InvalidInput)
}
fn positive_safe(v: &serde_json::Value) -> Option<u64> {
    v.as_f64()
        .filter(|n| n.is_finite() && n.fract() == 0.0 && *n >= 1.0 && *n <= 9_007_199_254_740_991.0)
        .map(|n| n as u64)
}
fn digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
