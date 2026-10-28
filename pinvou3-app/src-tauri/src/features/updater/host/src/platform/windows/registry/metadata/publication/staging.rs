//! Same-transaction bounded originals outside the authoritative waterlog.
use super::*;

const STAGING: &str = "metadata-publication-staging-v1";

pub(super) struct Staged<'tx> {
    key: Key,
    members: Key,
    tx: &'tx Handle,
    timestamp_sha256: String,
    snapshot_sha256: String,
    hashes: Vec<String>,
}
fn bounded(raw: &[u8]) -> Result<()> {
    if raw.is_empty() || raw.len() > json::RECORD_MAX {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}
impl<'tx> Staged<'tx> {
    pub(super) fn create_in(
        private: &Key,
        tx: &'tx Handle,
        timestamp: &[u8],
        snapshot: &[u8],
        count: u32,
        mut read_member: impl FnMut(u32) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        bounded(timestamp)?;
        bounded(snapshot)?;
        if count > 4096 {
            return Err(Error::StateCorrupt);
        }
        // A crash cannot leave this key: it is created and deleted in the same
        // outer TxR. An existing key is damage/conflict, never adopted scratch.
        let key = create(private.0, STAGING, tx, false, true)?;
        let members = create(key.0, "members", tx, false, true)?;
        write(&key, "Timestamp", timestamp)?;
        write(&key, "Snapshot", snapshot)?;
        let mut hashes = Vec::with_capacity(count as usize);
        for i in 1..=count {
            crate::platform::windows::time_cancel::check()?;
            let raw = read_member(i)?;
            bounded(&raw)?;
            let row = create(members.0, &revision_name(u64::from(i)), tx, false, true)?;
            write(&row, "Original", &raw)?;
            hashes.push(json::sha256(&raw));
        }
        Ok(Self {
            key,
            members,
            tx,
            timestamp_sha256: json::sha256(timestamp),
            snapshot_sha256: json::sha256(snapshot),
            hashes,
        })
    }
    fn original(key: &Key, name: &str, expected: &str) -> Result<Vec<u8>> {
        let raw = read_limited(key, name, json::RECORD_MAX)?;
        bounded(&raw)?;
        if json::sha256(&raw) != expected {
            return Err(Error::ScopeConflict);
        }
        Ok(raw)
    }
    pub(super) fn timestamp(&self) -> Result<Vec<u8>> {
        Self::original(&self.key, "Timestamp", &self.timestamp_sha256)
    }
    pub(super) fn snapshot(&self) -> Result<Vec<u8>> {
        Self::original(&self.key, "Snapshot", &self.snapshot_sha256)
    }
    pub(super) fn member(&self, i: u32) -> Result<Vec<u8>> {
        let expected = i
            .checked_sub(1)
            .and_then(|i| self.hashes.get(i as usize))
            .ok_or(Error::StateCorrupt)?;
        let row = open(
            self.members.0,
            &revision_name(u64::from(i)),
            false,
            Some(self.tx),
        )?
        .ok_or(Error::StateCorrupt)?;
        waterlog::exact_counts(&row, 1, 0)?;
        Self::original(&row, "Original", expected)
    }
    pub(super) fn recheck(&self) -> Result<()> {
        waterlog::exact_counts(&self.key, 2, 1)?;
        waterlog::exact_counts(&self.members, 0, self.hashes.len() as u64)?;
        self.timestamp()?;
        self.snapshot()?;
        for i in 1..=self.hashes.len() {
            self.member(i as u32)?;
        }
        Ok(())
    }
    /// Delete only the fixed task-owned transacted key, bottom-up. No detached
    /// native delete and no computed external filesystem path is involved.
    #[allow(unsafe_code)]
    pub(super) fn remove(self, private: &Key, tx: &Handle) -> Result<()> {
        if !std::ptr::eq(self.tx, tx) {
            return Err(Error::ScopeConflict);
        }
        self.recheck()?;
        let count = self.hashes.len();
        drop(self.members);
        drop(self.key);
        for i in 1..=count {
            let path = wide(&format!(
                "{}\\members\\{}",
                STAGING,
                revision_name(i as u64)
            ));
            if unsafe {
                RegDeleteKeyTransactedW(
                    private.0,
                    path.as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                    tx.raw(),
                    ptr::null(),
                )
            } != 0
            {
                return Err(Error::Unavailable);
            }
        }
        for path in [format!("{}\\members", STAGING), STAGING.to_owned()] {
            if unsafe {
                RegDeleteKeyTransactedW(
                    private.0,
                    wide(&path).as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                    tx.raw(),
                    ptr::null(),
                )
            } != 0
            {
                return Err(Error::Unavailable);
            }
        }
        if open(private.0, STAGING, false, Some(tx))?.is_some() {
            return Err(Error::ScopeConflict);
        }
        Ok(())
    }
}

/// Native storage primitive only: these are untrusted bytes, not a graph or a
/// forged service/sample capability. The caller must roll back on partial=true.
#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_test_in(private: &Key, tx: &Handle, partial: bool) -> Result<()> {
    let mut calls = 0;
    let result = Staged::create_in(private, tx, b"timestamp", b"snapshot", 2, |i| {
        calls += 1;
        if partial && i == 2 {
            return Err(Error::Unavailable);
        }
        Ok(format!("member-{i}").into_bytes())
    });
    if partial {
        return if calls == 2 && matches!(result, Err(Error::Unavailable)) {
            Ok(())
        } else {
            Err(Error::StateCorrupt)
        };
    }
    let staged = result?;
    staged.recheck()?;
    if staged.timestamp()? != b"timestamp"
        || staged.snapshot()? != b"snapshot"
        || staged.member(1)? != b"member-1"
        || staged.member(2)? != b"member-2"
    {
        return Err(Error::StateCorrupt);
    }
    let row =
        open(staged.members.0, &revision_name(1), true, Some(tx))?.ok_or(Error::StateCorrupt)?;
    write(&row, "Original", b"changed")?;
    if !matches!(staged.member(1), Err(Error::ScopeConflict)) {
        return Err(Error::StateCorrupt);
    }
    write(&row, "Original", b"member-1")?;
    drop(row);
    staged.recheck()?;
    staged.remove(private, tx)
}

#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_test_no_staging(private: &Key) -> Result<()> {
    if open(private.0, STAGING, false, None)?.is_some() {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_empty_and_oversized_sources_before_native_writes() {
        assert!(bounded(&[]).is_err());
        assert!(bounded(&vec![0; json::RECORD_MAX]).is_ok());
        assert!(bounded(&vec![0; json::RECORD_MAX + 1]).is_err());
    }
}
