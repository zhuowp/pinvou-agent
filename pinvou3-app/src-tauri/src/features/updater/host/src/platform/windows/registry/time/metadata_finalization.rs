//! Sealed metadata finalization after all callbacks and full source replay.
//! No DTO clock, generic source port, cleanup completion or current-use right.
use super::*;
use crate::monotonic::CounterObservation;
use crate::trusted_time::{PreparedRootWindow, UtcInterval, advance_interval, prepare_root_window};

/// Only the actual current readset can prepare this bounded same-TxR view.
/// Private native keys and source/transaction borrows cannot be deserialized.
pub(in crate::platform::windows) struct MetadataFinalization<'read, 'tx> {
    source: &'read LiveTimeReadSet<'tx>,
    host: HostRegistration,
    pins: NativeMetadataPins<'tx>,
    anchor_earliest: u64,
    anchor_latest: u64,
    received: CounterObservation,
    window: PreparedRootWindow,
    floor: u64,
}

/// Native byte/ACL comparisons only. These pins authenticate neither a clock
/// nor a service; the real factory and native owner supply those separately.
struct NativeMetadataPins<'tx> {
    private: &'tx Key,
    host_raw: Vec<u8>,
    host_row: Key,
    time: Key,
    time_row: Key,
    root: Key,
    root_head: Vec<u8>,
    time_head: Vec<u8>,
    policy: Vec<u8>,
    original: Vec<u8>,
}

fn root_path(seed: &Seed) -> String {
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    format!(
        "Software\\Pinvou\\{leaf}\\products\\{}\\root-state-v1",
        json::sha256(seed.product.as_bytes())
    )
}

impl<'tx> NativeMetadataPins<'tx> {
    fn capture(
        source: &LiveTimeReadSet<'tx>,
        seed: &Seed,
        host: &HostRegistration,
    ) -> Result<Self> {
        let host_raw = read(source.private, "Head")?;
        if host_raw != json::encode(host, false)? {
            return Err(Error::ScopeConflict);
        }
        let host_row = open(
            source.private.0,
            &format!("history\\{}", revision_name(host.revision)),
            false,
            Some(source.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let time = open(source.private.0, NAMESPACE, false, Some(source.transaction))?
            .ok_or(Error::SetupIncomplete)?;
        let time_row = open(
            time.0,
            &format!("history\\{}", revision_name(source.state().revision)),
            false,
            Some(source.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let root = open(
            HKEY_LOCAL_MACHINE,
            &root_path(seed),
            false,
            Some(source.transaction),
        )?
        .ok_or(Error::StateCorrupt)?;
        let root_head = read(&root, "Head")?;
        Ok(Self {
            private: source.private,
            host_raw,
            host_row,
            time,
            time_row,
            root,
            root_head,
            time_head: source.snapshot.raw.clone(),
            policy: source.policy.raw.clone(),
            original: source.snapshot.original_root.clone(),
        })
    }

    fn check(&self) -> Result<()> {
        for key in [
            self.private,
            &self.host_row,
            &self.time,
            &self.time_row,
            &self.root,
        ] {
            inspect_registry(key.0, true)?;
        }
        if read(self.private, "Head")? != self.host_raw
            || read(&self.host_row, "Record")? != self.host_raw
            || read(&self.time, "Head")? != self.time_head
            || read(&self.time_row, "Record")? != self.time_head
            || read(&self.time, "Policy")? != self.policy
            || read(self.private, METADATA_BOOTSTRAP_ROOT)? != self.original
            || read(&self.root, "Head")? != self.root_head
        {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
}

impl<'tx> LiveTimeReadSet<'tx> {
    /// Caller must finish graph/prefix checks, all callbacks and final Original
    /// validation first. This factory authenticates the real time source before
    /// sealing; generic source.recheck remains unchanged for other consumers.
    pub(in crate::platform::windows::registry) fn prepare_metadata_finalization<'read>(
        &'read self,
        service: &StartedServiceContext,
    ) -> Result<MetadataFinalization<'read, 'tx>> {
        self.recheck(service)?;
        let seed = &service.context.seed;
        let original = service.original_root_source()?;
        if original.root_bytes(service)? != self.original_root() {
            return Err(Error::StateCorrupt);
        }
        let host = read_guarded_in(
            &Store::new(seed),
            seed,
            self.product_guard,
            self.transaction,
        )?
        .ok_or(Error::SetupIncomplete)?;
        service.authenticate_running(&host)?;
        if host.digest()? != self.host_digest
            || self.state().binding != Binding::from_host(&service.startup)
        {
            return Err(Error::ScopeConflict);
        }
        let incarnation = Incarnation::from_host(&service.startup)?;
        let evidence = self
            .state()
            .anchor_for_live(&self.policy.raw, &incarnation)?;
        let window = prepare_root_window(self.current_root(), &self.state().binding.product)?;
        let floor = self.protected_floor_millis()?;
        let pins = NativeMetadataPins::capture(self, seed, &host)?;
        // Complete the expensive revalidation before exposing the bounded view.
        self.recheck(service)?;
        let prepared = MetadataFinalization {
            source: self,
            host,
            pins,
            anchor_earliest: evidence.earliest,
            anchor_latest: evidence.latest,
            received: evidence.received.data()?,
            window,
            floor,
        };
        prepared.recheck(service)?;
        Ok(prepared)
    }
}

impl<'read, 'tx> MetadataFinalization<'read, 'tx> {
    pub(in crate::platform::windows) fn require_source(
        &self,
        source: &LiveTimeReadSet<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self.source, source) {
            return Err(Error::ScopeConflict);
        }
        source.require_metadata_transaction(self.source.private, self.source.transaction)
    }

    /// Bounded native pins only; own metadata/journal/budget Heads may advance.
    pub(in crate::platform::windows) fn recheck(
        &self,
        service: &StartedServiceContext,
    ) -> Result<()> {
        self.registration(service).map(|_| ())
    }

    pub(in crate::platform::windows) fn registration(
        &self,
        service: &StartedServiceContext,
    ) -> Result<&HostRegistration> {
        self.source
            .product_guard
            .check_seed(&service.context.seed)?;
        self.pins.check()?;
        service.authenticate_running(&self.host)?;
        Ok(&self.host)
    }

    /// Pure bounded interval DATA calculation from the prepared actual anchor.
    pub(in crate::platform::windows) fn bounds_at(
        &self,
        current: CounterObservation,
    ) -> Result<UtcInterval> {
        let bounds = advance_interval(
            self.anchor_earliest,
            self.anchor_latest,
            self.received,
            current,
        )?;
        self.window.check(bounds)?;
        if bounds.earliest_millis() < self.floor {
            return Err(Error::SourceUnavailable);
        }
        Ok(bounds)
    }

    pub(in crate::platform::windows::registry) fn observe<'finalize>(
        &'finalize self,
        service: &StartedServiceContext,
        initial: &CapturedHistoricalSample<'read, 'tx>,
    ) -> Result<FinalMetadataObservation<'finalize, 'read, 'tx>> {
        self.require_source(initial.source)?;
        let live = initial
            .live_for(self.source)?
            .recheck_metadata(service, self)?;
        let sample = CapturedHistoricalSample::from_live(self.source, live)?;
        Ok(FinalMetadataObservation {
            finalization: self,
            sample,
        })
    }
}

/// Native DATA probe only. No finalization/service/counter capability is made;
/// the existing isolated runner owns and abandons this transaction.
#[cfg(feature = "metadata-component-tests")]
pub(in crate::platform::windows::registry) fn component_test_metadata_finalization_pins_in(
    private: &Key,
    seed: &Seed,
    host: &HostRegistration,
    guard: &super::super::product_catalog::ProductGuard,
    tx: &Handle,
) -> Result<()> {
    let source = current_in(private, seed, host, guard, tx)?;
    let pins = NativeMetadataPins::capture(&source, seed, host)?;
    pins.check()?;
    // Production pins retain read-only handles. The isolated probe obtains
    // separate write handles in the same abandoned transaction for mutations.
    let host_row = open(
        private.0,
        &format!("history\\{}", revision_name(host.revision)),
        true,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)?;
    let time = open(private.0, NAMESPACE, true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    let time_row = open(
        time.0,
        &format!("history\\{}", revision_name(source.state().revision)),
        true,
        Some(tx),
    )?
    .ok_or(Error::StateCorrupt)?;
    let root =
        open(HKEY_LOCAL_MACHINE, &root_path(seed), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    for (key, name) in [
        (private, "Head"),
        (&host_row, "Record"),
        (&time, "Head"),
        (&time_row, "Record"),
        (&time, "Policy"),
        (&root, "Head"),
        (private, METADATA_BOOTSTRAP_ROOT),
    ] {
        // Mutate one real value at a time; all the other Heads remain fixed.
        let original = read(key, name)?;
        let mut changed = original.clone();
        changed.push(b'x');
        write(key, name, &changed)?;
        let refused = pins.check();
        write(key, name, &original)?;
        if refused != Err(Error::ScopeConflict) {
            return Err(Error::StateCorrupt);
        }
        pins.check()?;
    }
    Ok(())
}

/// Genuine final native observation; an initial/generic sample cannot replace it.
/// Its bytes remain the unchanged HistoricalSample record, never current rights.
pub(in crate::platform::windows) struct FinalMetadataObservation<'finalize, 'read, 'tx> {
    finalization: &'finalize MetadataFinalization<'read, 'tx>,
    sample: CapturedHistoricalSample<'read, 'tx>,
}
impl<'read, 'tx> FinalMetadataObservation<'_, 'read, 'tx> {
    pub(in crate::platform::windows::registry) fn bounds(&self) -> UtcInterval {
        self.sample.bounds()
    }
    pub(in crate::platform::windows::registry) fn live_for(
        &self,
        source: &LiveTimeReadSet<'_>,
    ) -> Result<&super::super::super::live_time::LiveTimeInterval<'read, 'tx>> {
        self.finalization.require_source(source)?;
        self.sample.live_for(source)
    }
    pub(in crate::platform::windows::registry) fn bytes_for(
        &self,
        service: &StartedServiceContext,
        source: &LiveTimeReadSet<'_>,
    ) -> Result<Vec<u8>> {
        self.finalization.require_source(source)?;
        self.finalization.recheck(service)?;
        json::encode(&self.sample.sample, false)
    }
}
