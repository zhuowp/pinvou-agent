//! Concrete protected check-scope custody. No detached DATA can create a source.
use super::*;
use crate::check_scope::{RECORD_LIMIT, Snapshot};

const KEY: &str = "check-scope-v1";

// Query counts first: an observed extra object is corruption, whereas failed
// or incomplete enumeration remains unavailable. Enumerate exact names too.
#[allow(unsafe_code)]
fn census(key: &Key) -> Result<()> {
    let mut children = 0;
    let mut values = 0;
    let status = unsafe {
        RegQueryInfoKeyW(
            key.0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            &mut children,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut values,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(Error::Unavailable);
    }
    if children != 0 || values != 2 {
        return Err(Error::StateCorrupt);
    }
    let mut actual = names(key, true, 2)?;
    actual.sort();
    if actual != ["Genesis", "Head"] || !names(key, false, 0)?.is_empty() {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

pub(super) fn read_in(
    private: &Key,
    host: &HostRegistration,
    tx: Option<&Handle>,
) -> Result<Option<Snapshot>> {
    let key = open(private.0, KEY, false, tx)?;
    if !crate::bootstrap::has_check_scope(&host.known_owner_namespaces) {
        return if key.is_none() {
            Ok(None)
        } else {
            Err(Error::StateCorrupt)
        };
    }
    let key = key.ok_or(Error::StateCorrupt)?;
    inspect_registry(key.0, true)?;
    census(&key)?;
    let genesis = read_limited(&key, "Genesis", RECORD_LIMIT)?;
    let head = read_limited(&key, "Head", RECORD_LIMIT)?;
    crate::check_scope::check_existing(host, &genesis, &head).map(Some)
}

pub(super) fn initialize_in(
    private: &Key,
    tx: &Handle,
    host: &HostRegistration,
) -> Result<Snapshot> {
    if !crate::bootstrap::has_check_scope(&host.known_owner_namespaces) {
        return Err(Error::StateCorrupt);
    }
    // A bounded retry only handles an entropy collision, never existing state.
    let mut chosen = None;
    for _ in 0..4 {
        let id = super::super::pipe::nonce()?;
        if id != host.installation_scope_id && id != host.original_install_operation_id {
            chosen = Some(id);
            break;
        }
    }
    let snapshot = crate::check_scope::initial(host, chosen.ok_or(Error::Unavailable)?)?;
    let key = create(private.0, KEY, tx, false, true)?;
    write(&key, "Genesis", snapshot.genesis_bytes())?;
    write(&key, "Head", snapshot.head_bytes())?;
    if read_in(private, host, Some(tx))?.as_ref() != Some(&snapshot) {
        return Err(Error::StateCorrupt);
    }
    Ok(snapshot)
}

impl Store {
    /// Join the actual registration and scope under the same protected native
    /// transaction. Callers retain the resulting comparison DATA alongside the
    /// real image/SCM observation; neither the DATA nor JSON is a capability.
    #[allow(unsafe_code)]
    pub(in crate::platform::windows) fn read_with_check_scope(
        &self,
        seed: &Seed,
    ) -> Result<(HostRegistration, Option<Snapshot>)> {
        let _bootstrap = BootstrapGuard::acquire(seed, false)?;
        let guard = product_catalog::ProductGuard::acquire(seed)?;
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })?;
        let host = time::read_guarded_in(self, seed, &guard, &tx)?.ok_or(Error::SetupIncomplete)?;
        let private = self.key(false, Some(&tx))?.ok_or(Error::StateCorrupt)?;
        let scope = read_in(&private, &host, Some(&tx))?;
        Ok((host, scope))
    }
}

#[cfg(feature = "metadata-component-tests")]
pub(super) fn component_probes(store: &Store, host: &HostRegistration, expected: &Snapshot) {
    // Each probe mutates real protected native DATA in an abandoned TxR. It
    // cannot construct InstalledImages, a retained service or source authority.
    fn probe(store: &Store, host: &HostRegistration, change: impl FnOnce(&Key, &Key, &Handle)) {
        #[allow(unsafe_code)]
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let private = store.key(true, Some(&tx)).unwrap().unwrap();
        let key = open(private.0, KEY, true, Some(&tx)).unwrap().unwrap();
        change(&private, &key, &tx);
        assert_eq!(read_in(&private, host, Some(&tx)), Err(Error::StateCorrupt));
    }
    probe(store, host, |_, key, _| {
        write(key, "Extra", b"x").unwrap();
    });
    probe(store, host, |_, key, tx| {
        let _extra = create(key.0, "extra", tx, false, true).unwrap();
    });
    probe(store, host, |_, key, _| {
        write(key, "Head", &vec![b'x'; RECORD_LIMIT + 1]).unwrap();
    });
    probe(store, host, |_, key, _| {
        let mut head: serde_json::Value = json::decode(expected.head_bytes(), false).unwrap();
        head["channel"] = "beta".into();
        head["channelRevision"] = 2.into();
        write(key, "Head", &json::encode(&head, false).unwrap()).unwrap();
    });
    probe(store, host, |_, key, _| {
        let mut genesis: serde_json::Value = json::decode(expected.genesis_bytes(), false).unwrap();
        genesis["binding"]["installationScopeId"] = "0".repeat(64).into();
        write(key, "Genesis", &json::encode(&genesis, false).unwrap()).unwrap();
    });
    probe(store, host, |_, key, _| {
        #[allow(unsafe_code)]
        let status = unsafe { RegDeleteValueW(key.0, wide("Head").as_ptr()) };
        assert_eq!(status, 0);
    });
    probe(store, host, |_, key, _| {
        #[allow(unsafe_code)]
        let status = unsafe { RegDeleteValueW(key.0, wide("Head").as_ptr()) };
        assert_eq!(status, 0);
        write(key, "head", expected.head_bytes()).unwrap();
    });
    probe(store, host, |_, key, _| {
        #[allow(unsafe_code)]
        let status = unsafe {
            RegSetValueExW(
                key.0,
                wide("Head").as_ptr(),
                0,
                REG_SZ,
                [0u8, 0].as_ptr(),
                2,
            )
        };
        assert_eq!(status, 0);
    });
    // An explicitly old owner list must not adopt a newly present namespace.
    let mut legacy = host.clone();
    legacy.known_owner_namespaces.pop();
    let private = store.key(false, None).unwrap().unwrap();
    assert_eq!(read_in(&private, &legacy, None), Err(Error::StateCorrupt));
    drop(private);
    #[allow(unsafe_code)]
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let private = store.key(true, Some(&tx)).unwrap().unwrap();
    #[allow(unsafe_code)]
    let status = unsafe {
        RegDeleteKeyTransactedW(
            private.0,
            wide(KEY).as_ptr(),
            KEY_WOW64_64KEY,
            0,
            tx.raw(),
            ptr::null(),
        )
    };
    assert_eq!(status, 0);
    assert_eq!(read_in(&private, &legacy, Some(&tx)).unwrap(), None);
    assert_eq!(read_in(&private, host, Some(&tx)), Err(Error::StateCorrupt));
    // Recreate the prior complete serialized registration in this abandoned
    // native transaction. Store must retain its old owners and API usability;
    // a missing new scope owner cannot make a valid old registration corrupt.
    let legacy_raw = json::encode(&legacy, false).unwrap();
    write(&private, "Head", &legacy_raw).unwrap();
    let revision = open(
        private.0,
        &format!("history\\{}", revision_name(legacy.revision)),
        true,
        Some(&tx),
    )
    .unwrap()
    .unwrap();
    write(&revision, "Record", &legacy_raw).unwrap();
    let public = store.public_key(Some(&tx)).unwrap().unwrap();
    write(
        &public,
        "Head",
        &json::encode(&legacy.public(), false).unwrap(),
    )
    .unwrap();
    let seed = Seed::embedded().unwrap();
    let actual = store
        .read_in_checked(&seed, Some(&tx), true)
        .unwrap()
        .unwrap();
    assert_eq!(actual.digest().unwrap(), legacy.digest().unwrap());
    metadata::check_in(&private, &seed, &actual, Some(&tx)).unwrap();
    assert_eq!(read_in(&private, &actual, Some(&tx)).unwrap(), None);
    drop(public);
    drop(revision);
    legacy.known_owner_namespaces = vec!["bootstrap-v1".into()];
    assert_eq!(read_in(&private, &legacy, Some(&tx)).unwrap(), None);
    drop(private);
    drop(tx);
    assert_eq!(
        store
            .read_with_check_scope(&Seed::embedded().unwrap())
            .unwrap()
            .1
            .as_ref(),
        Some(expected)
    );
    // Native owner reads preserve identity across the existing retained-scope
    // registration lifecycle. These DATA transitions do not claim SCM removal.
    for changed in [
        host.next(crate::registration::Phase::Provisioning, "installer-claim")
            .unwrap(),
        {
            let mut tombstone = host.clone();
            tombstone.phase = crate::registration::Phase::RemovedTombstone;
            tombstone.reinstall_same_build().unwrap()
        },
    ] {
        let private = store.key(false, None).unwrap().unwrap();
        assert_eq!(
            read_in(&private, &changed, None).unwrap().as_ref(),
            Some(expected)
        );
    }
}
