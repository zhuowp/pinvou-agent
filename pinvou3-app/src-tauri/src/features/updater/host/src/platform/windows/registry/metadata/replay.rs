//! Complete historical metadata replay. Results are proposed historical DATA,
//! never current time, durable acceptance, Root promotion or install authority.
use super::replay_index::{Index, document, root};
use super::time_history::{HistoryPosition, TimeCheckedBatch};
use super::*;
use crate::platform::windows::{installed::StartedServiceContext, registry::time::LiveTimeReadSet};
use pinvou_upgrade_codec::Document;
use pinvou_upgrade_metadata_owner::{
    Decision, DecisionError, DecisionInputs, OwnedPriorWater, decide_public_metadata_source,
};
use std::cell::Cell;
use std::collections::BTreeMap;

#[allow(dead_code)]
pub(in crate::platform::windows::registry) struct Replay<'read, 'tx> {
    source: &'read LiveTimeReadSet<'tx>,
    index: Index,
    batches: u64,
    position: HistoryPosition,
    required_role_denials: BTreeMap<String, Vec<String>>,
}

#[allow(dead_code)]
impl Replay<'_, '_> {
    pub(in crate::platform::windows::registry) fn require_source(
        &self,
        source: &LiveTimeReadSet<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self.source, source) {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }

    pub(in crate::platform::windows::registry) fn recheck(
        &self,
        host: &StartedServiceContext,
    ) -> Result<()> {
        let position = self.source.visit_metadata_time(host, |_| Ok(()))?;
        if position != self.position {
            return Err(Error::ScopeConflict);
        }
        self.source.recheck(host)
    }

    pub(in crate::platform::windows::registry) fn batches(&self) -> u64 {
        self.batches
    }

    /// Historical DATA only. The publisher must compare the actual current
    /// native policy against this map within its still-held source transaction.
    pub(in crate::platform::windows::registry) fn required_role_denials(
        &self,
    ) -> &BTreeMap<String, Vec<String>> {
        &self.required_role_denials
    }

    /// The index can only be read after the whole traversal and rechecks have
    /// succeeded. Its borrow binds it to the original, still-held source TxR.
    pub(in crate::platform::windows::registry) fn prior(
        &self,
        host: &StartedServiceContext,
        context: &Document,
    ) -> Result<Option<OwnedPriorWater>> {
        self.recheck(host)?;
        let prior = self.index.read(context)?;
        self.recheck(host)?;
        Ok(prior)
    }
}

// The pure decision's public error enum cannot carry a native error. Retain
// that error out of band, preserving cancellation, I/O and identity failures.
fn supplied<T>(
    result: Result<T>,
    error: &Cell<Option<Error>>,
) -> std::result::Result<T, DecisionError> {
    result.map_err(|failure| {
        if error.get().is_none() {
            error.set(Some(failure));
        }
        DecisionError::SourceUnavailable
    })
}

fn decide(
    batch: &TimeCheckedBatch<'_, '_, '_>,
    index: &Index,
    context: &Document,
) -> Result<Decision> {
    let selected_root = root(batch.root())?;
    if context.value()["product"].as_str() != Some(selected_root.product()) {
        return Err(Error::StateCorrupt);
    }
    let interval = batch.interval();
    let earliest = document(interval.earliest_millis().to_string().as_bytes())?
        .protocol_time_shape()
        .map_err(|_| Error::StateCorrupt)?;
    let latest = document(interval.latest_millis().to_string().as_bytes())?
        .protocol_time_shape()
        .map_err(|_| Error::StateCorrupt)?;
    let timestamp = batch.timestamp()?;
    let snapshot = batch.snapshot()?;
    let error = Cell::new(None);
    let decision = decide_public_metadata_source(
        &timestamp,
        &snapshot,
        batch.count() as usize,
        |i| {
            supplied(
                batch.member(
                    u32::try_from(i)
                        .map_err(|_| DecisionError::SourceUnavailable)?
                        .checked_add(1)
                        .ok_or(DecisionError::SourceUnavailable)?,
                ),
                &error,
            )
        },
        DecisionInputs {
            root: &selected_root,
            context,
            earliest: &earliest,
            latest: &latest,
            denied: batch.global_denied(),
            denied_by_role: batch.role_denied(),
        },
        |context| supplied(index.read(context), &error),
    );
    if let Some(error) = error.get() {
        return Err(error);
    }
    decision.map_err(|_| Error::StateCorrupt)
}

fn retain(
    index: &mut Index,
    decision: &Decision,
    batch: &TimeCheckedBatch<'_, '_, '_>,
) -> Result<()> {
    let mut count = 0usize;
    let mut put = |raw: Vec<u8>| -> Result<()> {
        let hash = json::sha256(&raw);
        if let Some(update) = decision.updates().iter().find(|u| u.sha256() == hash) {
            index.put(update, &raw, batch.root(), batch.index())?;
            count = count.checked_add(1).ok_or(Error::Unavailable)?;
        }
        Ok(())
    };
    put(batch.timestamp()?)?;
    put(batch.snapshot()?)?;
    for i in 1..=batch.count() {
        put(batch.member(i)?)?;
    }
    if count != decision.updates().len() {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

#[allow(dead_code)]
pub(in crate::platform::windows::registry) fn replay<'read, 'tx>(
    source: &'read LiveTimeReadSet<'tx>,
    host: &StartedServiceContext,
) -> Result<Replay<'read, 'tx>> {
    source.recheck(host)?;
    let binding = &source.state().binding;
    let context = document(&json::encode(
        &serde_json::json!({
            "product":binding.product, "component":binding.component,
        }),
        false,
    )?)?;
    let mut index = Index::new(&Store::new(&host.context.seed))?;
    let mut batches = 0u64;
    let mut required_role_denials = BTreeMap::new();
    let position = source.visit_metadata_time(host, |batch| {
        if batch.index() != batches.checked_add(1).ok_or(Error::Unavailable)? {
            return Err(Error::StateCorrupt);
        }
        super::policy::require_retained_denials(batch.role_denied(), &required_role_denials)?;
        // No put is reachable before complete signature/graph/water success.
        let decision = decide(batch, &index, &context)?;
        retain(&mut index, &decision, batch)?;
        // Monotonicity makes the last successful snapshot the complete bounded
        // role knowledge. Keep historical verification on each batch's policy.
        required_role_denials = batch.role_denied().clone();
        batches = batch.index();
        Ok(())
    })?;
    source.recheck(host)?;
    // Every earlier error drops Index and its last transaction handle. Scratch
    // keys are rolled back; no partial Replay or committed index can escape.
    Ok(Replay {
        source,
        index,
        batches,
        position,
        required_role_denials,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_source_failures_are_preserved_and_never_become_absence() {
        for failure in [
            Error::Unavailable,
            Error::Busy,
            Error::TimeCanceled,
            Error::SecurityRefused,
        ] {
            let error = Cell::new(None);
            assert!(matches!(
                supplied::<Option<OwnedPriorWater>>(Err(failure), &error),
                Err(DecisionError::SourceUnavailable)
            ));
            assert_eq!(error.get(), Some(failure));
            assert!(matches!(
                supplied::<Option<OwnedPriorWater>>(Ok(None), &error),
                Ok(None)
            ));
            assert_eq!(error.get(), Some(failure));
        }
    }
}
