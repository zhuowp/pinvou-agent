//! Retain only an actual pending Root operation's late sampled time floor.
//! No numeric floor input, budget window, Root authority or current-use grant.
use super::*;
use crate::platform::windows::time_owner::{LateRootAcceptance, PendingRootTime};

/// Capture/validate the bounded budget Head before late native sampling. The
/// owner retains its product guard and TxR through the fixed final write.
pub(in crate::platform::windows::registry) struct PendingRootFloor<'tx> {
    key: Key,
    transaction: &'tx Handle,
    host: HostRegistration,
    head: Head,
    before: Vec<u8>,
}

impl<'tx> PendingRootFloor<'tx> {
    pub(in crate::platform::windows::registry) fn prepare(
        private: &Key,
        host: &HostRegistration,
        transaction: &'tx Handle,
    ) -> Result<Self> {
        let key =
            open(private.0, NAMESPACE, true, Some(transaction))?.ok_or(Error::SetupIncomplete)?;
        let (head, before) = read_head(&key, &Binding::from_host(host), Some(transaction))?;
        Ok(Self {
            key,
            transaction,
            host: host.clone(),
            head,
            before,
        })
    }

    /// Consume the prepared Head and native positive sample in the Root
    /// publisher's still-held transaction. This is knowledge at the sampled
    /// instant, not UTC at physical COMMIT and not a durable live-clock token.
    pub(in crate::platform::windows::registry) fn retain(
        self,
        service: &StartedServiceContext,
        pending: &PendingRootTime<'_, '_>,
        sample: &LateRootAcceptance<'_, '_, '_>,
        candidate_head: &[u8],
    ) -> Result<RootFloorPosition> {
        sample.require_context(service, pending, candidate_head)?;
        if sample.binding() != &Binding::from_host(&self.host)
            || sample.incarnation() != &Incarnation::from_host(&self.host)?
            || read(&self.key, "Head")? != self.before
        {
            return Err(Error::ScopeConflict);
        }
        let lower = sample.bounds().earliest_millis();
        // UTC's protocol domain already has the lower bound zero. A first
        // sample at zero adds no numeric floor knowledge or budget action.
        if self.head.live_floor.unwrap_or(0) >= lower {
            return Ok(RootFloorPosition {
                raw: self.before,
                revision: self.head.revision,
                binding: self.head.binding,
            });
        }
        let mut next = self.head.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .filter(|value| *value <= json::SAFE_MAX)
            .ok_or(Error::Unavailable)?;
        next.previous_sha256 = Some(json::sha256(&self.before));
        next.live_floor = Some(lower);
        self.head.successor(&next, &self.before)?;
        let raw = json::encode(&next, false)?;
        let history = open(self.key.0, "history", true, Some(self.transaction))?
            .ok_or(Error::StateCorrupt)?;
        let row = create(
            history.0,
            &revision_name(next.revision),
            self.transaction,
            false,
            true,
        )?;
        write(&row, "Record", &raw)?;
        write(&self.key, "Head", &raw)?;
        if read(&row, "Record")? != raw || read(&self.key, "Head")? != raw {
            return Err(Error::StateCorrupt);
        }
        Ok(RootFloorPosition {
            raw,
            revision: next.revision,
            binding: next.binding,
        })
    }
}

/// Intended protected Head DATA for the owning publisher's post-COMMIT check.
pub(in crate::platform::windows::registry) struct RootFloorPosition {
    raw: Vec<u8>,
    revision: u64,
    binding: Binding,
}

impl RootFloorPosition {
    #[allow(unsafe_code)]
    pub(in crate::platform::windows::registry) fn flush_and_recheck(
        &self,
        private: &Key,
        host: &HostRegistration,
    ) -> Result<()> {
        if Binding::from_host(host) != self.binding {
            return Err(Error::StateCommitUnknown);
        }
        let key = open(private.0, NAMESPACE, false, None)?.ok_or(Error::StateCommitUnknown)?;
        let history = open(key.0, "history", false, None)?.ok_or(Error::StateCommitUnknown)?;
        let row = open(history.0, &revision_name(self.revision), false, None)?
            .ok_or(Error::StateCommitUnknown)?;
        if read(&row, "Record")? != self.raw
            || read_head(&key, &self.binding, None)?.1 != self.raw
            || unsafe { RegFlushKey(row.0) } != 0
            || unsafe { RegFlushKey(history.0) } != 0
            || unsafe { RegFlushKey(key.0) } != 0
        {
            return Err(Error::StateCommitUnknown);
        }
        Ok(())
    }
}
