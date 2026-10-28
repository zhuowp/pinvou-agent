//! Authenticated Root/time lineage prefix, never metadata or current authority.
//! Only the completed Root-history owner can mint this capability. Its source
//! fingerprint rechecks every retained original, evidence and member snapshot
//! without recursively invoking semantic Root or metadata replay.
use super::*;

type ProductGuard = super::super::super::product_catalog::ProductGuard;

/// The ceiling grants access only to already authenticated ancestor positions.
/// The pinned source may contain later batches; they grant no prefix authority.
pub(in crate::platform::windows::registry) struct RootSignaturePrefix<'tx> {
    seed: &'tx Seed,
    guard: &'tx ProductGuard,
    tx: &'tx Handle,
    genesis: Vec<u8>,
    original: Vec<u8>,
    terminal: Vec<u8>,
    batch: u64,
    root_count: u64,
    source_fingerprint: [u8; 32],
}

fn product_in(seed: &Seed, tx: &Handle) -> Result<Key> {
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let path = format!(
        "Software\\Pinvou\\{leaf}\\products\\{}",
        json::sha256(seed.product.as_bytes())
    );
    open(HKEY_LOCAL_MACHINE, &path, false, Some(tx))?.ok_or(Error::StateCorrupt)
}

fn frame(hash: &mut Sha256, raw: &[u8]) {
    hash.update((raw.len() as u64).to_be_bytes());
    hash.update(raw);
}

// Same fixed Root-tree depth as flush_persisted, plus the product parent.
// Names and bodies are released per visit; no lifetime-history Vec is built.
// Enumeration-order changes conservatively refuse rather than reusing a proof.
fn fingerprint_tree(key: &Key, tx: &Handle, depth: usize, hash: &mut Sha256) -> Result<()> {
    if depth > 9 {
        return Err(Error::StateCorrupt);
    }
    hash.update(b"key");
    super::super::super::product_catalog::visit(key, true, |name| {
        hash.update(b"value");
        frame(hash, name.as_bytes());
        frame(hash, &read(key, name)?);
        Ok(())
    })?;
    hash.update(b"children");
    super::super::super::product_catalog::visit(key, false, |name| {
        frame(hash, name.as_bytes());
        let child = open(key.0, name, false, Some(tx))?.ok_or(Error::StateCorrupt)?;
        fingerprint_tree(&child, tx, depth + 1, hash)
    })?;
    hash.update(b"end");
    Ok(())
}

/// Complete bytes of the actual product Root/directory source, not just Head.
/// Current profile state is independently authenticated by the member owner.
pub(super) fn fingerprint(seed: &Seed, guard: &ProductGuard, tx: &Handle) -> Result<[u8; 32]> {
    guard.check_seed(seed)?;
    let product = product_in(seed, tx)?;
    let mut hash = Sha256::new();
    frame(&mut hash, b"pinvou.product-root.signature-prefix-source.v1");
    frame(&mut hash, seed.product.as_bytes());
    frame(&mut hash, seed.profile_kind.as_bytes());
    fingerprint_tree(&product, tx, 0, &mut hash)?;
    Ok(hash.finalize().into())
}

pub(super) fn from_verified<'tx>(view: &VerifiedHistory<'tx>) -> Result<RootSignaturePrefix<'tx>> {
    view.recheck_head()?;
    super::super::root_read_set::require_unchanged(
        &view.source_fingerprint,
        &fingerprint(view.seed, view.guard, view.tx)?,
    )?;
    let product = product_in(view.seed, view.tx)?;
    let root =
        open(product.0, "root-state-v1", false, Some(view.tx))?.ok_or(Error::StateCorrupt)?;
    let terminal = view.current_head.clone();
    let head = BatchHead::parse(&terminal)?;
    let prefix = RootSignaturePrefix {
        seed: view.seed,
        guard: view.guard,
        tx: view.tx,
        genesis: read(&root, "Genesis")?,
        original: read(&product, "Root")?,
        terminal,
        batch: counter(&head.batch)?,
        root_count: counter(&head.root_count)?,
        source_fingerprint: view.source_fingerprint,
    };
    prefix.recheck()?;
    Ok(prefix)
}

fn require_ceiling(batch: u64, root_count: u64, position: &ProductRootPosition) -> Result<()> {
    if position.batch > batch || position.root_count > root_count {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_test_in(parent: &Key, tx: &Handle) -> Result<()> {
    let tree = create(parent.0, "prefix-source-test", tx, false, true)?;
    write(&tree, "Head", b"unchanged-head")?;
    let child = create(tree.0, "earlier-batch", tx, false, true)?;
    write(&child, "Original", b"original")?;
    let fingerprint = || -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        fingerprint_tree(&tree, tx, 0, &mut hash)?;
        Ok(hash.finalize().into())
    };
    let before = fingerprint()?;
    assert_eq!(before, fingerprint()?);
    write(&child, "Original", b"replaced")?;
    assert_eq!(read(&tree, "Head")?, b"unchanged-head");
    assert_eq!(
        super::super::root_read_set::require_unchanged(&before, &fingerprint()?),
        Err(Error::ScopeConflict)
    );
    write(&child, "Original", b"original")?;
    assert_eq!(before, fingerprint()?);
    write(&child, "Extra", b"unexpected")?;
    assert_ne!(before, fingerprint()?);
    Ok(())
}

impl<'tx> RootSignaturePrefix<'tx> {
    pub(in crate::platform::windows::registry) fn check_context(
        &self,
        seed: &Seed,
        guard: &ProductGuard,
        tx: &Handle,
    ) -> Result<()> {
        if !std::ptr::eq(self.seed, seed)
            || !std::ptr::eq(self.guard, guard)
            || !std::ptr::eq(self.tx, tx)
        {
            return Err(Error::ScopeConflict);
        }
        self.guard.check_seed(seed)
    }

    pub(in crate::platform::windows::registry) fn recheck(&self) -> Result<()> {
        self.guard.check_seed(self.seed)?;
        super::super::root_read_set::require_unchanged(
            &self.source_fingerprint,
            &fingerprint(self.seed, self.guard, self.tx)?,
        )
    }

    /// Resolve compact historical state only. This never samples current time.
    pub(in crate::platform::windows::registry) fn resolve_member_state(
        &self,
        state: &State,
    ) -> Result<ReplayedPosition> {
        self.recheck()?;
        if state.binding.product != self.seed.product
            || state.binding.profile_kind != self.seed.profile_kind
        {
            return Err(Error::StateCorrupt);
        }
        let position = state.product_root.as_ref().ok_or(Error::StateCorrupt)?;
        require_ceiling(self.batch, self.root_count, position)?;
        if position.batch == self.batch && position.head_sha256 != json::sha256(&self.terminal) {
            return Err(Error::StateCorrupt);
        }
        let product = product_in(self.seed, self.tx)?;
        let root =
            open(product.0, "root-state-v1", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let history =
            open(root.0, "history-v2", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let batches =
            open(history.0, "batches", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
        let original = std::str::from_utf8(&self.original).map_err(|_| Error::StateCorrupt)?;
        let resolved = position_from_verified_prefix(
            &batches,
            self.tx,
            &self.genesis,
            original,
            position,
            state,
        )?;
        resolved.authenticate_compact(state)?;
        self.recheck()?;
        Ok(resolved)
    }

    /// Restrict an already authenticated source to the predecessor of batch N.
    /// This does not authenticate a new batch or advance any persistent Head.
    pub(in crate::platform::windows::registry) fn before_batch(&self, batch: u64) -> Result<Self> {
        let ceiling = batch.checked_sub(1).ok_or(Error::StateCorrupt)?;
        if ceiling > self.batch {
            return Err(Error::StateCorrupt);
        }
        self.recheck()?;
        let terminal = if ceiling == 0 {
            self.genesis.clone()
        } else {
            let product = product_in(self.seed, self.tx)?;
            let root = open(product.0, "root-state-v1", false, Some(self.tx))?
                .ok_or(Error::StateCorrupt)?;
            let history =
                open(root.0, "history-v2", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
            let batches =
                open(history.0, "batches", false, Some(self.tx))?.ok_or(Error::StateCorrupt)?;
            let batch = open(batches.0, &revision_name(ceiling), false, Some(self.tx))?
                .ok_or(Error::StateCorrupt)?;
            read(&batch, "Record")?
        };
        let root_count = if ceiling == 0 {
            0
        } else {
            let head = BatchHead::parse(&terminal)?;
            if counter(&head.batch)? != ceiling {
                return Err(Error::StateCorrupt);
            }
            counter(&head.root_count)?
        };
        let restricted = Self {
            seed: self.seed,
            guard: self.guard,
            tx: self.tx,
            genesis: self.genesis.clone(),
            original: self.original.clone(),
            terminal,
            batch: ceiling,
            root_count,
            source_fingerprint: self.source_fingerprint,
        };
        restricted.recheck()?;
        Ok(restricted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ceiling_rejects_future_batch_and_root_count() {
        let mut position = ProductRootPosition {
            head_sha256: "1".repeat(64),
            root_sha256: "2".repeat(64),
            batch: 2,
            root_count: 7,
        };
        assert!(require_ceiling(2, 7, &position).is_ok());
        assert_eq!(require_ceiling(1, 7, &position), Err(Error::StateCorrupt));
        assert_eq!(require_ceiling(2, 6, &position), Err(Error::StateCorrupt));
        position.batch = 0;
        position.root_count = 0;
        assert!(require_ceiling(0, 0, &position).is_ok());
    }
    #[test]
    fn fingerprints_bind_framing_and_non_head_bytes() {
        fn digest(parts: &[&[u8]]) -> [u8; 32] {
            let mut hash = Sha256::new();
            for part in parts {
                frame(&mut hash, part);
            }
            hash.finalize().into()
        }
        let before = digest(&[b"Head", b"same", b"old-evidence"]);
        assert_eq!(
            super::super::super::root_read_set::require_unchanged(
                &before,
                &digest(&[b"Head", b"same", b"changed-evidence"])
            ),
            Err(Error::ScopeConflict)
        );
        assert_ne!(digest(&[b"ab", b"c"]), digest(&[b"a", b"bc"]));
    }
}
