//! Native pending-operation time proof. No DTO constructor or live-clock right.
use super::super::monotonic::IncarnationCounterSample;
use super::*;
use crate::trusted_time::{Binding, UtcInterval, advance_interval};
use pinvou_upgrade_verifier::SignatureCheckedTimeResponse;

/// Constructed only by TimeOwner's actual verified-response branch. The two
/// native samples and exact scratch/service borrows cannot be reconstructed
/// from serialized Evidence. One bounded base original is retained for rechecks.
pub(in crate::platform::windows) struct PendingRootTime<'host, 'scratch> {
    host: &'host StartedServiceContext,
    successors: &'scratch RootScratch,
    sent: IncarnationCounterSample,
    verified_at: IncarnationCounterSample,
    evidence: Evidence,
    binding: Binding,
    incarnation: Incarnation,
    base_root: Vec<u8>,
    base_sha256: String,
    base_count: usize,
    final_sha256: String,
}

impl<'host, 'scratch> PendingRootTime<'host, 'scratch> {
    pub(super) fn new(
        host: &'host StartedServiceContext,
        successors: &'scratch RootScratch,
        sent: IncarnationCounterSample,
        verified_at: IncarnationCounterSample,
        evidence: Evidence,
        base_root: &[u8],
        checked: &SignatureCheckedTimeResponse,
    ) -> Result<Self> {
        if base_root.is_empty() || base_root.len() > json::RECORD_MAX {
            return Err(Error::SourceUnavailable);
        }
        let pending = Self {
            host,
            successors,
            sent,
            verified_at,
            binding: Binding::from_host(&host.startup),
            incarnation: Incarnation::from_host(&host.startup)?,
            base_root: base_root.to_vec(),
            base_sha256: json::sha256(base_root),
            base_count: evidence.base_root_count,
            final_sha256: checked.root_sha256().to_owned(),
            evidence,
        };
        if checked.earliest_millis() != pending.evidence.earliest
            || checked.latest_millis() != pending.evidence.latest
            || checked.checked_root_steps() != successors.len()
        {
            return Err(Error::ScopeConflict);
        }
        pending.require_context(
            host,
            &pending.evidence,
            successors,
            base_root,
            pending.base_count,
        )?;
        Ok(pending)
    }

    pub(in crate::platform::windows) fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Recheck actual protected publisher context before any late sample. All
    /// cryptography and scratch reads happen here, never after that sample.
    pub(in crate::platform::windows) fn require_context(
        &self,
        host: &StartedServiceContext,
        evidence: &Evidence,
        successors: &RootScratch,
        actual_base_root: &[u8],
        base_count: usize,
    ) -> Result<()> {
        if !std::ptr::eq(self.host, host)
            || !std::ptr::eq(self.successors, successors)
            || self.evidence != *evidence
            || base_count != self.base_count
            || actual_base_root != self.base_root
            || json::sha256(actual_base_root) != self.base_sha256
            || Binding::from_host(&host.startup) != self.binding
            || Incarnation::from_host(&host.startup)? != self.incarnation
            || self.evidence.incarnation != self.incarnation
            || self.evidence.sent != CounterEvidence::from_data(self.sent.counters())
            || self.evidence.received != CounterEvidence::from_data(self.verified_at.counters())
        {
            return Err(Error::ScopeConflict);
        }
        self.verified_at.elapsed_since(&self.sent)?;
        successors.verify_all()?;
        let mut local = self.evidence.clone();
        local.base_root_count = 0;
        let checked = local.verify_source_checked(
            &self.binding,
            actual_base_root,
            successors.len(),
            |index| Ok(std::borrow::Cow::Owned(successors.read(index)?)),
        )?;
        if checked.root_sha256() != self.final_sha256 {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }

    /// Invoke only after complete metadata replay/source checks. The resulting
    /// bounds describe this actual sample, not the later physical COMMIT time.
    /// Candidate Head bytes are a binding; the Root owner checks its native Head.
    pub(in crate::platform::windows) fn sample_late<'pending>(
        &'pending self,
        host: &StartedServiceContext,
        clock: &super::super::registry::time::RootPublicationClock<'_>,
        final_root: &[u8],
        candidate_head: &[u8],
    ) -> Result<LateRootAcceptance<'pending, 'host, 'scratch>> {
        self.require_context(
            host,
            &self.evidence,
            self.successors,
            &self.base_root,
            self.base_count,
        )?;
        if final_root.is_empty()
            || final_root.len() > json::RECORD_MAX
            || json::sha256(final_root) != self.final_sha256
            || candidate_head.is_empty()
            || candidate_head.len() > json::RECORD_MAX
        {
            return Err(Error::ScopeConflict);
        }
        let candidate_head_sha256 = json::sha256(candidate_head);
        // Finish bounded decoding, full schema/policy validation and temporary
        // Root allocations before sampling. Only numeric window facts survive.
        let window = parse_root_window(final_root, &self.binding.product)?;
        // This Root-only native sampler checks exact transaction-bound
        // registration pins and actual SCM identity on both sides. The generic
        // sampler's Store::read would replay all Root history after the sample.
        let current = host.sample_monotonic_for_root(clock)?;
        current.elapsed_since(&self.verified_at)?;
        let bounds = checked_late_bounds(
            (self.evidence.earliest, self.evidence.latest),
            self.verified_at.counters(),
            current.counters(),
            &window,
        )?;
        Ok(LateRootAcceptance {
            pending: self,
            current,
            bounds,
            candidate_head_sha256,
        })
    }
}

/// Non-cloneable, non-serializable proof borrowing the exact native operation.
/// Getters are DATA at the sampled instant and cannot mint a Known/live clock.
pub(in crate::platform::windows) struct LateRootAcceptance<'pending, 'host, 'scratch> {
    pending: &'pending PendingRootTime<'host, 'scratch>,
    current: IncarnationCounterSample,
    bounds: UtcInterval,
    candidate_head_sha256: String,
}
impl LateRootAcceptance<'_, '_, '_> {
    pub(in crate::platform::windows) fn bounds(&self) -> UtcInterval {
        self.bounds
    }
    pub(in crate::platform::windows) fn binding(&self) -> &Binding {
        &self.pending.binding
    }
    pub(in crate::platform::windows) fn incarnation(&self) -> &Incarnation {
        &self.pending.incarnation
    }
    pub(in crate::platform::windows) fn candidate_head_sha256(&self) -> &str {
        &self.candidate_head_sha256
    }
    pub(in crate::platform::windows) fn root_sha256(&self) -> &str {
        &self.pending.final_sha256
    }
    pub(in crate::platform::windows) fn counter_evidence(&self) -> CounterEvidence {
        CounterEvidence::from_data(self.current.counters())
    }
    /// Identity/data comparison only; no post-sample crypto or counter refresh.
    pub(in crate::platform::windows) fn require_context(
        &self,
        host: &StartedServiceContext,
        pending: &PendingRootTime<'_, '_>,
        candidate_head: &[u8],
    ) -> Result<()> {
        if !std::ptr::eq(self.pending, pending)
            || !std::ptr::eq(self.pending.host, host)
            || candidate_head.is_empty()
            || candidate_head.len() > json::RECORD_MAX
            || json::sha256(candidate_head) != self.candidate_head_sha256
        {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
}

// Pure interval DATA calculation, not a Pending/Late proof constructor.
fn checked_late_bounds(
    anchor: (u64, u64),
    received: crate::monotonic::CounterObservation,
    current: crate::monotonic::CounterObservation,
    window: &RootWindow,
) -> Result<UtcInterval> {
    let bounds = advance_interval(anchor.0, anchor.1, received, current)?;
    window.check(bounds)?;
    Ok(bounds)
}

/// Numeric facts from a fully schema-checked supplied Root, not authority.
struct RootWindow {
    issued: u64,
    expires: u64,
}
impl RootWindow {
    fn check(&self, interval: UtcInterval) -> Result<()> {
        if self.issued > interval.earliest_millis() || self.expires <= interval.latest_millis() {
            return Err(Error::SourceUnavailable);
        }
        Ok(())
    }
}

// Match trusted_time::check_root_interval's schema/context/integer semantics,
// separating its parse phase from the final fixed-size numeric window check.
fn parse_root_window(raw: &[u8], product: &str) -> Result<RootWindow> {
    let envelope = pinvou_upgrade_codec::decode_canonical_envelope(raw, InputKind::Metadata)
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
    let time = |name: &str| -> Result<u64> {
        signed.value()[name]
            .as_f64()
            .filter(|n| {
                n.is_finite() && *n >= 0.0 && *n <= json::SAFE_MAX as f64 && n.trunc() == *n
            })
            .map(|n| n as u64)
            .ok_or(Error::StateCorrupt)
    };
    Ok(RootWindow {
        issued: time("issuedAt")?,
        expires: time("expiresAt")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monotonic::CounterObservation;

    #[test]
    fn late_interval_preserves_original_origin_and_rejects_root_expiry() {
        // Pure DATA calculation only; this creates no SCM sample or Pending/Late
        // capability. The original signed fixture supplies the real Root window.
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/product-root-history.json"
        )))
        .unwrap();
        let batch = &fixture["batches"][0];
        let root = batch["successors"][0].as_str().unwrap().as_bytes();
        let body: serde_json::Value = serde_json::from_slice(root).unwrap();
        let expiry = body["signed"]["expiresAt"].as_u64().unwrap();
        let anchor = (expiry - 2, expiry - 1);
        let window = parse_root_window(root, "pinvou").unwrap();
        let zero = CounterObservation::from_bracket(0, 0, 0, 0).unwrap();
        let one_ms = CounterObservation::from_bracket(10_000, 10_000, 10_000, 10_000).unwrap();
        let before = checked_late_bounds(anchor, zero, zero, &window).unwrap();
        assert_eq!(before.latest_millis(), expiry - 1);
        assert!(checked_late_bounds(anchor, zero, one_ms, &window).is_err());
        assert!(parse_root_window(root, "another-product").is_err());
        assert!(checked_late_bounds(anchor, one_ms, zero, &window).is_err());
        for point in [window.issued - 1, window.issued, expiry - 1, expiry] {
            let interval = advance_interval(point, point, zero, zero).unwrap();
            assert_eq!(
                window.check(interval),
                crate::trusted_time::check_root_interval(root, "pinvou", interval)
            );
        }
    }
}
