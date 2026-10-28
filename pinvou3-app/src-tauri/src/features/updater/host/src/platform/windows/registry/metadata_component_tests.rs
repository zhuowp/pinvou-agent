//! Native Store component test in a separate process with an overridden HKLM.
//! This does not construct a source-installer capability or install a service.
use super::*;
use crate::{
    identity::{FileTime, LogonId},
    inventory::tests,
    registration::InstallerIdentity,
};
use std::sync::atomic::Ordering;

struct IsolatedRoot {
    root: Option<Key>,
    override_active: bool,
}
#[link(name = "ntdll")]
#[allow(unsafe_code)]
unsafe extern "system" {
    fn NtDeleteKey(key: HKEY) -> i32;
}
impl IsolatedRoot {
    #[allow(unsafe_code)]
    fn cleanup(&mut self) -> std::result::Result<(), &'static str> {
        if self.override_active {
            if unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, ptr::null_mut()) } != 0 {
                return Err("restore HKLM");
            }
            self.override_active = false;
        }
        if let Some(root) = self.root.as_ref() {
            if unsafe { RegDeleteTreeW(root.0, ptr::null()) } != 0 {
                return Err("clear retained test root");
            }
            if unsafe { NtDeleteKey(root.0) } != 0 {
                return Err("delete retained test root by handle");
            }
            drop(self.root.take());
        }
        Ok(())
    }
    fn finish(mut self) {
        self.cleanup().expect("cleanup owned registry test root");
    }
}
impl Drop for IsolatedRoot {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("best-effort test cleanup failed: {error}");
        }
    }
}

#[allow(unsafe_code)]
fn isolated_root() -> IsolatedRoot {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = wide(&format!(
        "PinvouMetadataComponent-{}-{unique}",
        std::process::id()
    ));
    let mut root = ptr::null_mut();
    let mut disposition = 0;
    let policy = NativeSecurity::registry(false).expect("native test-root policy");
    assert_eq!(
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                &policy.attributes(),
                &mut root,
                &mut disposition,
            )
        },
        0,
        "create test root"
    );
    if disposition != REG_CREATED_NEW_KEY {
        drop(Key(root));
        panic!("refuse existing test root");
    }
    let mut owned = IsolatedRoot {
        root: Some(Key(root)),
        override_active: false,
    };
    inspect_registry(root, true).expect("real protected test-root ACL");
    assert_eq!(
        unsafe { RegOverridePredefKey(HKEY_LOCAL_MACHINE, root) },
        0,
        "override HKLM"
    );
    owned.override_active = true;
    // Production checks the Software ancestor; create it with the unchanged
    // native policy. An unelevated token must fail here, never silently skip.
    let policy = NativeSecurity::registry(true).expect("native policy");
    let mut software = ptr::null_mut();
    assert_eq!(
        unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide("Software").as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                &policy.attributes(),
                &mut software,
                &mut disposition,
            )
        },
        0,
        "create protected Software: elevated administrator required"
    );
    let software = Key(software);
    assert_eq!(disposition, REG_CREATED_NEW_KEY);
    inspect_registry(software.0, true).expect("real protected registry ACL");
    drop(software);
    owned
}

pub(crate) fn run_isolated() {
    let _root = isolated_root();
    let seed = Seed::embedded().expect("signed test Seed and Root must be embedded");
    assert_eq!(seed.profile_kind, "lab");
    assert_eq!(seed.profile_id, "metadata-component-test");
    let input = tests::fixture_for_seed(&seed, vec![vec![tests::app()]]);
    let manifest = input.parse(&seed).expect("real inventory parser");
    let installer = InstallerIdentity {
        process_id: 1, creation_file_time: FileTime::from_native(0, 1),
        token_user_sid: "S-1-5-18".into(), logon_authentication_id: LogonId { high: 0, low: 1 },
        session_id: 1, source_nsis_sha256: "4".repeat(64),
        source_nsis_file_identity: serde_json::from_value(serde_json::json!({"volume":1,"indexHigh":0,"indexLow":1,"createdHigh":0,"createdLow":1})).unwrap(),
        manifest_sha256: json::sha256(&input.root), operation_id: "9".repeat(64),
    };
    let record =
        HostRegistration::initial(&seed, &manifest, "5".repeat(64), installer, None).unwrap();
    let store = Store::new(&seed);
    assert!(store.read(&seed).unwrap().is_none());
    catalog_missing_never_adopts_existing_profile(&seed, &record);
    INITIAL_COMMIT_FAULT.store(1, Ordering::SeqCst);
    assert_eq!(
        store.commit(&seed, None, &record, Some(&input)),
        Err(Error::Unavailable)
    );
    assert!(
        store.read(&seed).unwrap().is_none(),
        "abandoned TxR must publish no scope"
    );
    INITIAL_COMMIT_FAULT.store(2, Ordering::SeqCst);
    assert_eq!(
        store.commit(&seed, None, &record, Some(&input)),
        Err(Error::StateCommitUnknown)
    );
    let reopened = Store::new(&seed)
        .read(&seed)
        .unwrap()
        .expect("committed unknown must reopen");
    assert_eq!(reopened.digest().unwrap(), record.digest().unwrap());
    Store::new(&seed)
        .verify_initial_metadata(&seed, &reopened)
        .expect("recheck original initial intent");
    check_scope_uses_persisted_native_owner(&store, &seed, &reopened);
    let first_scope = store.read_with_check_scope(&seed).unwrap().1.unwrap();
    historical_genesis_uses_transacted_registry(&store, &seed, &reopened);
    metadata_finalization_pins_use_transacted_registry(&store, &seed, &reopened);
    member_metadata_genesis_uses_actual_catalog(&store, &seed, &reopened);
    if super::time::root_history::component_fixture::matches(&seed) {
        root_publication_uses_signed_nonempty_cache(&store, &seed, &reopened);
    }
    publication_staging_uses_transacted_registry(&store, &seed);
    waterlog_structure_uses_transacted_registry(&store, &seed, &reopened);
    if seed.original_root.sha256
        == "9caab397724ac6fed0a308b9be94d375ad01ce590e50ea5a4286836842977c56"
    {
        historical_legacy_uses_signed_transacted_records(&store, &seed, &reopened);
        signed_history_replays_from_transacted_objects(&store, &seed, &reopened);
    }
    root_read_set_rechecks_and_discards_mutations(&store, &seed, &reopened);
    root_snapshot_partial_write_rolls_back(&store, &seed, &reopened);
    root_evidence_codec_rolls_back(&store, &seed, &reopened);
    root_transition_requires_exact_empty_layout(&store, &seed, &reopened);
    let private = store.key(false, None).unwrap().unwrap();
    assert!(
        open(private.0, "root-snapshot-test", false, None)
            .unwrap()
            .is_none(),
        "rejected snapshot transaction must not persist partial objects"
    );
    drop(private);
    catalog_damage_refuses_profile_read(&store, &seed, &reopened);
    catalog_other_product_damage_is_isolated(&seed, &reopened);
    assert_eq!(
        store.commit(&seed, None, &record, Some(&input)),
        Err(Error::ScopeConflict),
        "must not reinitialize committed scope"
    );
    let private = store.key(true, None).unwrap().unwrap();
    let meta = open(private.0, "metadata-state-v1", true, None)
        .unwrap()
        .unwrap();
    write(&meta, "Head", b"damaged").unwrap();
    drop(meta);
    drop(private);
    assert!(
        store.verify_initial_metadata(&seed, &reopened).is_err(),
        "damaged initial state must not be claimed"
    );
    legacy_ready_is_readable(&store, &seed, &record);
    _root.finish();
    let _normal_root = isolated_root();
    let normal = Store::new(&seed);
    normal
        .commit(&seed, None, &record, Some(&input))
        .expect("normal first install commits and verifies");
    let committed = Store::new(&seed)
        .read(&seed)
        .unwrap()
        .expect("reopen normal commit");
    assert_eq!(committed.digest().unwrap(), record.digest().unwrap());
    normal
        .verify_initial_metadata(&seed, &committed)
        .expect("normal initial state remains valid");
    let second_scope = normal.read_with_check_scope(&seed).unwrap().1.unwrap();
    let first: serde_json::Value = json::decode(&first_scope.scope_json(), false).unwrap();
    let second: serde_json::Value = json::decode(&second_scope.scope_json(), false).unwrap();
    assert_ne!(
        first["installId"], second["installId"],
        "two actual fresh producers must not reuse identity"
    );
    product_lock_contention(&seed);
    missing_top_level_catalog_refuses_initialized_profile(&normal, &seed);
    _normal_root.finish();
}

fn check_scope_uses_persisted_native_owner(store: &Store, seed: &Seed, host: &HostRegistration) {
    let (actual, scope) = store.read_with_check_scope(seed).unwrap();
    assert_eq!(actual.digest().unwrap(), host.digest().unwrap());
    let scope = scope.expect("real first-install scope owner");
    let json = scope.scope_json();
    let fields: serde_json::Value = crate::json::decode(&json, false).unwrap();
    assert_eq!(fields.as_object().unwrap().len(), 7);
    assert!(crate::json::digest(fields["installId"].as_str().unwrap()));
    assert_ne!(fields["installId"], host.installation_scope_id);
    assert_ne!(fields["installId"], host.original_install_operation_id);
    assert_eq!(fields["channel"], "stable");
    assert_eq!(fields["channelRevision"], 1);
    // Exactly one bounded marker, from the actual reopened protected owner. CI
    // feeds these precise public test bytes to the existing frozen API schema.
    println!(
        "PINVOU_NATIVE_CHECK_SCOPE_JSON={}",
        String::from_utf8(json).unwrap()
    );
    store.verify_initial_metadata(seed, host).unwrap();
    assert_eq!(
        store.read_with_check_scope(seed).unwrap().1.as_ref(),
        Some(&scope)
    );
    check_scope::component_probes(store, host, &scope);
}

#[allow(unsafe_code)]
fn publication_staging_uses_transacted_registry(store: &Store, seed: &Seed) {
    let _profile = BootstrapGuard::acquire(seed, false).unwrap();
    let _product = product_catalog::ProductGuard::acquire(seed).unwrap();
    // A failed partial construction must roll back, then the next fresh
    // transaction can stage and delete the same owned namespace successfully.
    for partial in [true, false, false] {
        {
            let tx = Handle::owned(unsafe {
                CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
            })
            .unwrap();
            let private = store.key(true, Some(&tx)).unwrap().unwrap();
            metadata::publication::component_test_staging_in(&private, &tx, partial).unwrap();
        }
        let private = store.key(false, None).unwrap().unwrap();
        metadata::publication::component_test_no_staging(&private).unwrap();
    }
}

#[allow(unsafe_code)]
fn waterlog_structure_uses_transacted_registry(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    let _profile = BootstrapGuard::acquire(seed, false).unwrap();
    let _product = product_catalog::ProductGuard::acquire(seed).unwrap();
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let private = store.key(true, Some(&tx)).unwrap().unwrap();
    metadata::component_test_waterlog_structure_in(&private, seed, host, &tx).unwrap();
}

#[allow(unsafe_code)]
fn historical_legacy_uses_signed_transacted_records(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    let _profile = BootstrapGuard::acquire(seed, false).unwrap();
    let product = product_catalog::ProductGuard::acquire(seed).unwrap();
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let private = store.key(true, Some(&tx)).unwrap().unwrap();
    super::time::component_test_historical_legacy(&private, seed, host, &product, &tx).unwrap();
}

#[allow(unsafe_code)]
fn historical_genesis_uses_transacted_registry(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    let _profile = BootstrapGuard::acquire(seed, false).unwrap();
    let product = product_catalog::ProductGuard::acquire(seed).unwrap();
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let private = store.key(false, Some(&tx)).unwrap().unwrap();
    let source = super::time::current_in(&private, seed, host, &product, &tx).unwrap();
    super::time::component_test_historical_genesis(&source).unwrap();
    // Dropping the uncommitted transaction removes all damaged/extra rows.
}

/// Native pin DATA only. No finalization, service or positive clock is minted.
#[allow(unsafe_code)]
fn metadata_finalization_pins_use_transacted_registry(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    {
        let _profile = BootstrapGuard::acquire(seed, false).unwrap();
        let product = product_catalog::ProductGuard::acquire(seed).unwrap();
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let private = store.key(true, Some(&tx)).unwrap().unwrap();
        super::time::component_test_metadata_finalization_pins_in(
            &private, seed, host, &product, &tx,
        )
        .expect("native finalization pin mutations and restoration");
    }
    assert_eq!(
        store.read(seed).unwrap().unwrap().digest().unwrap(),
        host.digest().unwrap()
    );
    assert_eq!(store.time_load(seed, host).unwrap().state.revision, 1);
}

/// Signed historical DATA under the existing isolated lab registry. This does
/// not call the service-owned Root writer or manufacture its native clock proof.
#[allow(unsafe_code)]
fn root_publication_uses_signed_nonempty_cache(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    let before = || {
        let private = store.key(false, None).unwrap().unwrap();
        let metadata = open(private.0, "metadata-state-v1", false, None)
            .unwrap()
            .unwrap();
        let time = open(private.0, "trusted-time-v1", false, None)
            .unwrap()
            .unwrap();
        [
            read(&private, METADATA_BOOTSTRAP_ROOT).unwrap(),
            read(&metadata, "Head").unwrap(),
            read(&metadata, "Policy").unwrap(),
            read(&time, "Head").unwrap(),
        ]
    };
    let original = before();
    for exit_old_key in [true, false] {
        {
            let _profile = BootstrapGuard::acquire(seed, false).unwrap();
            let product = product_catalog::ProductGuard::acquire(seed).unwrap();
            let tx = Handle::owned(unsafe {
                CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
            })
            .unwrap();
            super::time::root_history::component_fixture::run(
                seed,
                host,
                &product,
                &tx,
                exit_old_key,
            )
            .expect("signed nonempty native Root staging fixture");
        }
        assert!(
            before() == original,
            "discarded transaction must preserve all committed source Heads"
        );
        let private = store.key(false, None).unwrap().unwrap();
        assert!(
            open(private.0, "root-publication-staging-v2", false, None)
                .unwrap()
                .is_none()
        );
        let time = open(private.0, "trusted-time-v1", false, None)
            .unwrap()
            .unwrap();
        assert!(
            open(time.0, "root-acquisition-v1", false, None)
                .unwrap()
                .is_none()
        );
        product_catalog::check(seed, host, None)
            .expect("discarded candidate must leave the committed product genesis unchanged");
    }
    println!("PINVOU_ROOT_PUBLICATION_DATA_TEST_PASSED");
}

/// Uses the real fixed catalog/profile source without constructing an SCM
/// context. This one-member fixture does not prove cross-member interleavings
/// or nonempty publication/restart. All deliberate mutations are rolled back.
#[allow(unsafe_code)]
fn member_metadata_genesis_uses_actual_catalog(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    let _profile = BootstrapGuard::acquire(seed, false).unwrap();
    let product = product_catalog::ProductGuard::acquire(seed).unwrap();
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let private = store.key(true, Some(&tx)).unwrap().unwrap();
    let metadata = open(private.0, "metadata-state-v1", true, Some(&tx))
        .unwrap()
        .unwrap();
    let mut members = 0;
    metadata::member_source::visit_metadata_members(seed, host, &product, &tx, None, |view| {
        members += 1;
        assert_eq!(view.member().host().digest()?, host.digest()?);
        assert_eq!(view.batches(), 0);
        let mut active = 0;
        view.visit_active(|_, _| {
            active += 1;
            Ok(())
        })?;
        assert_eq!(
            active, 0,
            "only exact authenticated genesis proves an empty cache"
        );
        for name in ["Head", "Policy"] {
            let original = read(&metadata, name)?;
            write(&metadata, name, b"changed-after-view")?;
            assert!(view.recheck().is_err());
            write(&metadata, name, &original)?;
            view.recheck()?;
        }
        // Prepare outside the product subtree, preserving the accepted Root
        // prefix while a future publisher assembles a new batch in this TxR.
        let scratch = create(private.0, "captured-metadata-test", &tx, false, true)?;
        let v1 = super::time::root_snapshot::capture_in(
            &scratch,
            "v1",
            seed,
            view.member().event(),
            host,
            &tx,
        )?;
        let v1_key = open(scratch.0, "v1", false, Some(&tx))?.ok_or(Error::StateCorrupt)?;
        assert!(
            matches!(
                super::time::root_snapshot::read_captured_in(&v1_key, &tx, &v1),
                Err(Error::SourceUnavailable)
            ),
            "legacy lineage data cannot assert an empty captured metadata set"
        );
        let v2 = super::time::root_snapshot::capture_metadata_in(
            &scratch,
            "v2",
            seed,
            view.member().event(),
            host,
            &product,
            &tx,
            None,
            view,
        )?;
        let v2_key = open(scratch.0, "v2", true, Some(&tx))?.ok_or(Error::StateCorrupt)?;
        let captured = super::time::root_snapshot::read_captured_in(&v2_key, &tx, &v2)?;
        assert_eq!(captured.metadata().genesis, read(&metadata, "Genesis")?);
        assert_eq!(captured.metadata().head, read(&metadata, "Head")?);
        assert!(captured.state().binding == *view.member().binding());
        let saved = read(&v2_key, "MetadataHead")?;
        write(&v2_key, "MetadataHead", b"substituted-head")?;
        assert!(super::time::root_snapshot::read_captured_in(&v2_key, &tx, &v2).is_err());
        write(&v2_key, "MetadataHead", &saved)?;
        super::time::root_snapshot::read_captured_in(&v2_key, &tx, &v2)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(members, 1, "fixture installs one actual protected member");
    assert_eq!(
        metadata::member_source::visit_metadata_members(seed, host, &product, &tx, None, |_| {
            Err(Error::TimeCanceled)
        }),
        Err(Error::TimeCanceled),
        "native visitor failure must survive full-source traversal"
    );
    let head = read(&metadata, "Head").unwrap();
    let mut invoked = false;
    assert!(
        metadata::member_source::visit_metadata_members(seed, host, &product, &tx, None, |_| {
            invoked = true;
            write(&metadata, "Head", b"changed-before-factory-return")
        })
        .is_err()
    );
    assert!(invoked, "mutation assertion must execute its callback");
    write(&metadata, "Head", &head).unwrap();
    metadata::member_source::visit_metadata_members(seed, host, &product, &tx, None, |_| Ok(()))
        .expect("restored source remains usable in the next traversal");
}

fn product_lock_contention(seed: &Seed) {
    let guard = product_catalog::ProductGuard::acquire(seed).expect("acquire product lock");
    std::thread::scope(|scope| {
        let contender = scope.spawn(|| {
            matches!(
                product_catalog::ProductGuard::acquire(seed),
                Err(Error::Busy)
            )
        });
        assert!(contender.join().unwrap(), "other thread must observe Busy");
    });
    drop(guard);
    let _again = product_catalog::ProductGuard::acquire(seed).expect("released lock is available");
}

/// Delete only the catalog in this test's private HKLM override, after the
/// initialized profile has been verified. The isolated root is then removed.
#[allow(unsafe_code)]
fn missing_top_level_catalog_refuses_initialized_profile(store: &Store, seed: &Seed) {
    assert!(store.read(seed).unwrap().is_some());
    let pinvou = open(HKEY_LOCAL_MACHINE, "Software\\Pinvou", true, None)
        .unwrap()
        .unwrap();
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    assert_eq!(unsafe { RegDeleteTreeW(pinvou.0, wide(leaf).as_ptr()) }, 0);
    if open(pinvou.0, leaf, false, None).unwrap().is_some() {
        assert_eq!(
            unsafe {
                windows_sys::Win32::System::Registry::RegDeleteKeyW(pinvou.0, wide(leaf).as_ptr())
            },
            0
        );
    }
    assert!(open(pinvou.0, leaf, false, None).unwrap().is_none());
    assert!(matches!(store.read(seed), Err(Error::StateCorrupt)));
}

/// Exercises actual TxR object reads and protected member snapshots with public
/// signed fixture data. This does not construct an SCM service, commit a Root
/// Head, or prove production history publication/recovery.
#[allow(unsafe_code)]
fn signed_history_replays_from_transacted_objects(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    use crate::{
        identity::ProcessSelector,
        monotonic::CounterObservation,
        trusted_time::{
            Binding, CounterEvidence, Evidence, Incarnation, ProductRootBatch, ProductRootReplay,
        },
    };
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/product-root-history.json"
    )))
    .unwrap();
    assert_eq!(
        fixture["original"].as_str().unwrap().as_bytes(),
        seed.original_root_bytes()
    );
    {
        let _profile = BootstrapGuard::acquire(seed, false).unwrap();
        let _product = product_catalog::ProductGuard::acquire(seed).unwrap();
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let private = store.key(true, Some(&tx)).unwrap().unwrap();
        let scratch = create(private.0, "signed-root-history-test", &tx, false, true).unwrap();
        let members = create(scratch.0, "members", &tx, false, true).unwrap();
        let objects = create(scratch.0, "roots", &tx, false, true).unwrap();
        let mut member_records = Vec::new();
        product_catalog::visit_members_in(seed, host, &tx, |event, actual| {
            let name = format!("{:020}", member_records.len() + 1);
            let raw =
                super::time::root_snapshot::capture_in(&members, &name, seed, event, actual, &tx)?;
            member_records.push((name, raw));
            Ok(())
        })
        .unwrap();
        assert_eq!(member_records.len(), 1, "fixture installs one real member");
        let time = open(private.0, "trusted-time-v1", false, Some(&tx))
            .unwrap()
            .unwrap();
        let policy = String::from_utf8(read(&time, "Policy").unwrap()).unwrap();
        let binding = Binding::from_host(host);
        let sent = CounterEvidence::from_data(
            CounterObservation::from_bracket(10_000_000, 9_000_000, 9_000_000, 10_000_000).unwrap(),
        );
        let received = CounterEvidence::from_data(
            CounterObservation::from_bracket(10_200_000, 9_200_000, 9_200_000, 10_200_000).unwrap(),
        );
        let incarnation = Incarnation {
            host_epoch: 1,
            instance_nonce: "c".repeat(64),
            process: ProcessSelector {
                process_id: 3,
                creation_file_time: FileTime::from_native(1, 2),
            },
        };
        let entries = fixture["batches"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let mut batches = Vec::new();
        for (batch_index, entry) in entries.iter().enumerate() {
            let roots = entry["successors"].as_array().unwrap();
            for (root_index, root) in roots.iter().enumerate() {
                let name = format!("{batch_index}-{root_index}");
                write(&objects, &name, root.as_str().unwrap().as_bytes()).unwrap();
            }
            batches.push(ProductRootBatch {
                binding: binding.clone(),
                successor_count: roots.len(),
                evidence: Evidence {
                    incarnation: incarnation.clone(),
                    request: serde_json::to_string(&entry["request"]).unwrap(),
                    response: entry["response"].as_str().unwrap().into(),
                    sent: sent.clone(),
                    received: received.clone(),
                    policy: policy.clone(),
                    floor_before: 0,
                    base_root_count: if batch_index == 0 { 0 } else { 2 },
                    denied_key_ids: Vec::new(),
                    earliest: entry["earliest"].as_u64().unwrap(),
                    latest: entry["latest"].as_u64().unwrap(),
                },
            });
        }
        let mut cursor =
            ProductRootReplay::new(&seed.product, fixture["original"].as_str().unwrap()).unwrap();
        let advance = |cursor: &mut ProductRootReplay, index: usize| {
            cursor.advance(
                &batches[index],
                |root_index| read(&objects, &format!("{index}-{root_index}")),
                |visit| {
                    for (name, raw) in &member_records {
                        let key =
                            open(members.0, name, false, Some(&tx))?.ok_or(Error::StateCorrupt)?;
                        super::time::root_snapshot::read_in(&key, &tx, raw)?.visit(visit)?;
                    }
                    Ok(())
                },
            )
        };
        advance(&mut cursor, 0).expect("first signed batch from TxR");
        let name = "1-0";
        let original = read(&objects, name).unwrap();
        write(&objects, name, b"replaced").unwrap();
        assert!(
            advance(&mut cursor, 1).is_err(),
            "replacement refuses replay"
        );
        write(&objects, name, &original).unwrap();
        assert_eq!(
            unsafe { RegDeleteValueW(objects.0, wide(name).as_ptr()) },
            0
        );
        assert!(
            advance(&mut cursor, 1).is_err(),
            "missing Root refuses replay"
        );
        write(&objects, name, &original).unwrap();
        advance(&mut cursor, 1).expect("second signed batch after failed reads");
        cursor.finish(2, 3, &json::sha256(&original)).unwrap();
        super::time::root_history::component_test_captured_prefix(
            &private,
            seed,
            host,
            &_product,
            &tx,
            &batches[0],
            |index| read(&objects, &format!("0-{index}")),
        )
        .expect("V2 captured source must come from actual signed native Root history");
    }
    let private = store.key(false, None).unwrap().unwrap();
    assert!(
        open(private.0, "signed-root-history-test", false, None)
            .unwrap()
            .is_none(),
        "all fixture data must roll back with the test transaction"
    );
    println!("PINVOU_SIGNED_ROOT_HISTORY_TEST_PASSED");
}

// The shared event chain remains intact while the other product's private
// projections are absent. This exercises isolation without forging a Seed.
#[allow(unsafe_code)]
fn catalog_other_product_damage_is_isolated(seed: &Seed, host: &HostRegistration) {
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let key = open(
        HKEY_LOCAL_MACHINE,
        "Software\\Pinvou\\UpgradeProductCatalogLabV1",
        true,
        Some(&tx),
    )
    .unwrap()
    .unwrap();
    let original = read(&key, "Head").unwrap();
    let mut foreign = crate::product_catalog::Event::parse(&original).unwrap();
    foreign.revision = 2;
    foreign.previous_sha256 = Some(json::sha256(&original));
    foreign.product = "other-product".into();
    foreign.profile_id = "other-profile".into();
    foreign.scope = "b".repeat(64);
    let raw = json::encode(&foreign, false).unwrap();
    let history = open(key.0, "history", true, Some(&tx)).unwrap().unwrap();
    let second = create(history.0, &revision_name(2), &tx, false, true).unwrap();
    write(&second, "Record", &raw).unwrap();
    write(&key, "Head", &raw).unwrap();
    product_catalog::check(seed, host, Some(&tx))
        .expect("another product's missing projections must not block this product");
    write(&key, "Head", b"damaged-shared-head").unwrap();
    product_catalog::check(seed, host, Some(&tx))
        .expect("ordinary reads use the protected product-local history");
    let mut visited = 0;
    product_catalog::visit_members_in(seed, host, &tx, |event, actual| {
        assert!(event.matches(seed, host));
        assert_eq!(actual.profile_id, host.profile_id);
        visited += 1;
        Ok(())
    })
    .expect("visit only authenticated members of this product");
    assert_eq!(visited, 1);
    assert!(matches!(
        product_catalog::visit_members_in(seed, host, &tx, |_, _| Err(Error::Unavailable)),
        Err(Error::Unavailable)
    ));

    let products = open(key.0, "products", true, Some(&tx)).unwrap().unwrap();
    let product = open(
        products.0,
        &json::sha256(seed.product.as_bytes()),
        true,
        Some(&tx),
    )
    .unwrap()
    .unwrap();
    let members = open(product.0, "members", true, Some(&tx))
        .unwrap()
        .unwrap();
    let own = open(
        members.0,
        &json::sha256(seed.profile_id.as_bytes()),
        true,
        Some(&tx),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        unsafe { RegDeleteValueW(own.0, wide("Record").as_ptr()) },
        0
    );
    assert!(
        product_catalog::check(seed, host, Some(&tx)).is_err(),
        "the current product's missing member must still be refused"
    );
    let mut called = false;
    assert!(
        product_catalog::visit_members_in(seed, host, &tx, |_, _| {
            called = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!called, "a member with missing evidence is never delivered");
}

#[allow(unsafe_code)]
fn catalog_missing_never_adopts_existing_profile(seed: &Seed, host: &HostRegistration) {
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let software = open(HKEY_LOCAL_MACHINE, "Software", true, Some(&tx))
        .unwrap()
        .unwrap();
    let pinvou = create(software.0, "Pinvou", &tx, true, false).unwrap();
    let profiles = create(pinvou.0, seed.updater_leaf(), &tx, true, false).unwrap();
    let existing = create(profiles.0, "unregistered-profile", &tx, true, true).unwrap();
    drop(existing);
    assert_eq!(
        product_catalog::stage(seed, host, &tx),
        Err(Error::SetupIncomplete)
    );
}

#[allow(unsafe_code)]
fn catalog_damage_refuses_profile_read(store: &Store, seed: &Seed, host: &HostRegistration) {
    let _guard = product_catalog::ProductGuard::acquire(seed).unwrap();
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let key = open(
        HKEY_LOCAL_MACHINE,
        "Software\\Pinvou\\UpgradeProductCatalogLabV1",
        true,
        Some(&tx),
    )
    .unwrap()
    .unwrap();
    let products = open(key.0, "products", true, Some(&tx)).unwrap().unwrap();
    let product = open(
        products.0,
        &json::sha256(seed.product.as_bytes()),
        true,
        Some(&tx),
    )
    .unwrap()
    .unwrap();
    let original = read(&product, "Head").unwrap();
    write(&product, "Head", b"damaged").unwrap();
    assert!(store.read_in(seed, Some(&tx)).is_err());
    assert_eq!(
        super::time::require_product_members_at_genesis_in(seed, host, &tx),
        Err(Error::RepairRequired)
    );
    write(&product, "Head", &original).unwrap();
    assert!(store.read_in(seed, Some(&tx)).unwrap().is_some());
    let anchors = open(key.0, "anchors", true, Some(&tx)).unwrap().unwrap();
    let anchor = open(
        anchors.0,
        &json::sha256(seed.product.as_bytes()),
        true,
        Some(&tx),
    )
    .unwrap()
    .unwrap();
    let anchor_original = read(&anchor, "Record").unwrap();
    write(&anchor, "Record", b"damaged").unwrap();
    assert!(store.read_in(seed, Some(&tx)).is_err());
    write(&anchor, "Record", &anchor_original).unwrap();
    assert!(store.read_in(seed, Some(&tx)).unwrap().is_some());
    let product_root = open(product.0, "root-state-v1", true, Some(&tx))
        .unwrap()
        .unwrap();
    let root_head = read(&product_root, "Head").unwrap();
    write(&product_root, "Head", b"changed").unwrap();
    assert!(store.read_in(seed, Some(&tx)).is_err());
    write(&product_root, "Head", &root_head).unwrap();
    let root_genesis = read(&product_root, "Genesis").unwrap();
    assert_eq!(
        unsafe { RegDeleteValueW(product_root.0, wide("Genesis").as_ptr()) },
        0
    );
    assert!(store.read_in(seed, Some(&tx)).is_err());
    write(&product_root, "Genesis", &root_genesis).unwrap();
    assert!(store.read_in(seed, Some(&tx)).unwrap().is_some());
}

/// Exercise the real transacted registry namespace without installing or
/// starting a service. Dropping this test transaction rolls back its mutations.
#[allow(unsafe_code)]
fn root_read_set_rechecks_and_discards_mutations(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    let mut wrong = host.clone();
    wrong.profile_id = "other-profile".into();
    assert!(super::time::RootReadSet::new(seed, &wrong).is_err());
    {
        let source = super::time::RootReadSet::new(seed, host).expect("read protected inputs");
        source.recheck().expect("stable protected inputs");
        source.damage_time_head_for_test().unwrap();
        assert!(source.recheck().is_err());
    }
    assert!(store.read(seed).unwrap().is_some());
    {
        let source = super::time::RootReadSet::new(seed, host).expect("read protected inputs");
        source.stage_container_for_test().unwrap();
        source
            .recheck()
            .expect("scratch container preserves product validation");
        source.change_valid_policy_for_test().unwrap();
        assert_eq!(source.recheck(), Err(Error::ScopeConflict));
    }
    {
        let source = super::time::RootReadSet::new(seed, host).expect("read protected inputs");
        source.stage_container_for_test().unwrap();
        source.damage_original_root_for_test().unwrap();
        assert!(source.recheck().is_err());
    }
    {
        let source = super::time::RootReadSet::new(seed, host).expect("read protected inputs");
        source.stage_container_for_test().unwrap();
        source.delete_policy_for_test().unwrap();
        assert!(source.recheck().is_err());
    }
    {
        let source = super::time::RootReadSet::new(seed, host).expect("read protected inputs");
        source.stage_container_for_test().unwrap();
        source.add_root_extra_for_test().unwrap();
        assert!(source.recheck().is_err());
    }
    {
        let source = super::time::RootReadSet::new(seed, host).expect("rollback retained inputs");
        source.damage_policy_for_test().unwrap();
        assert!(source.recheck().is_err());
    }
    {
        let source = super::time::RootReadSet::new(seed, host).expect("rollback retained policy");
        source.empty_policy_for_test().unwrap();
        assert!(source.recheck().is_err());
    }
    assert!(super::time::RootReadSet::new(seed, host).is_ok());
    let source = super::time::RootReadSet::new(seed, host).expect("read protected inputs");
    assert_eq!(
        source.probe_first_root_batch(),
        Err(Error::PrerequisiteUnavailable)
    );
    let leaf = if seed.profile_kind == "production" {
        "UpgradeProductCatalogV1"
    } else {
        "UpgradeProductCatalogLabV1"
    };
    let path = format!(
        "Software\\Pinvou\\{leaf}\\products\\{}\\root-state-v1",
        json::sha256(seed.product.as_bytes())
    );
    let root = open(HKEY_LOCAL_MACHINE, &path, false, None)
        .unwrap()
        .unwrap();
    assert!(open(root.0, "candidate-v2", false, None).unwrap().is_none());
    let private = store.key(false, None).unwrap().unwrap();
    assert!(
        open(private.0, "root-history-candidate-v2", false, None)
            .unwrap()
            .is_none()
    );
}

#[allow(unsafe_code)]
fn root_evidence_codec_rolls_back(store: &Store, seed: &Seed, host: &HostRegistration) {
    {
        let _guard = product_catalog::ProductGuard::acquire(seed).unwrap();
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let private = store.key(true, Some(&tx)).unwrap().unwrap();
        super::time::root_history::component_test(&private, host, &tx).unwrap();
    }
    let private = store.key(false, None).unwrap().unwrap();
    for name in ["root-evidence-test", "root-evidence-partial-test"] {
        assert!(open(private.0, name, false, None).unwrap().is_none());
    }
}

#[allow(unsafe_code)]
fn root_snapshot_partial_write_rolls_back(store: &Store, seed: &Seed, host: &HostRegistration) {
    {
        let _guard = product_catalog::ProductGuard::acquire(seed).unwrap();
        let tx = Handle::owned(unsafe {
            CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
        })
        .unwrap();
        let private = store.key(true, Some(&tx)).unwrap().unwrap();
        let snapshots = create(private.0, "root-snapshot-partial-test", &tx, false, true).unwrap();
        let result = product_catalog::visit_members_in(seed, host, &tx, |event, actual| {
            super::time::root_snapshot::FAIL_AFTER_ENROLLMENT.store(true, Ordering::SeqCst);
            let result = super::time::root_snapshot::capture_in(
                &snapshots, "partial", seed, event, actual, &tx,
            );
            assert!(matches!(result, Err(Error::Unavailable)));
            let partial =
                open(snapshots.0, "partial", false, Some(&tx))?.ok_or(Error::StateCorrupt)?;
            assert!(!read(&partial, "Enrollment")?.is_empty());
            assert!(read(&partial, "Record").is_err());
            Err(Error::Unavailable)
        });
        assert_eq!(result, Err(Error::Unavailable));
        // Drop all keys, then the uncommitted transaction, while the guard is held.
    }
    let private = store.key(false, None).unwrap().unwrap();
    assert!(
        open(private.0, "root-snapshot-partial-test", false, None)
            .unwrap()
            .is_none()
    );
}

#[allow(unsafe_code)]
fn root_transition_requires_exact_empty_layout(
    store: &Store,
    seed: &Seed,
    host: &HostRegistration,
) {
    let _guard = product_catalog::ProductGuard::acquire(seed).unwrap();
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let private = store.key(true, Some(&tx)).unwrap().unwrap();
    super::time::require_product_members_at_genesis_in(seed, host, &tx)
        .expect("complete product member census accepts intact genesis");
    let time = open(private.0, "trusted-time-v1", true, Some(&tx))
        .unwrap()
        .unwrap();
    let time_head = read(&time, "Head").unwrap();
    write(&time, "Head", b"damaged").unwrap();
    assert_eq!(
        super::time::require_product_members_at_genesis_in(seed, host, &tx),
        Err(Error::RepairRequired)
    );
    write(&time, "Head", &time_head).unwrap();
    super::time::require_product_members_at_genesis_in(seed, host, &tx).unwrap();
    super::metadata::require_empty_for_root_transition_in(&private, seed, host, &tx)
        .expect("original empty layout permits Root transition");
    let check_members = || {
        product_catalog::visit_members_in(seed, host, &tx, |event, actual| {
            super::metadata::require_member_empty_for_root_transition_in(seed, event, actual, &tx)
        })
    };
    check_members().expect("the member's own protected genesis is empty");
    let original_bootstrap = read(&private, METADATA_BOOTSTRAP).unwrap();
    write(&private, METADATA_BOOTSTRAP, b"damaged").unwrap();
    assert!(
        check_members().is_err(),
        "damaged member bootstrap must be refused"
    );
    write(&private, METADATA_BOOTSTRAP, &original_bootstrap).unwrap();
    check_members().expect("restored member bootstrap is accepted");
    let metadata = open(private.0, "metadata-state-v1", true, Some(&tx))
        .unwrap()
        .unwrap();
    let original_policy = read(&metadata, "Policy").unwrap();
    assert_eq!(
        unsafe { RegDeleteValueW(metadata.0, wide("Policy").as_ptr()) },
        0
    );
    assert_eq!(check_members(), Err(Error::StateCorrupt));
    assert_eq!(
        super::metadata::check_in(&private, seed, host, Some(&tx)),
        Err(Error::StateCorrupt)
    );
    write(&metadata, "Policy", b"{}").unwrap();
    assert_eq!(check_members(), Err(Error::StateCorrupt));
    write(&metadata, "Policy", &original_policy).unwrap();
    check_members().expect("restored explicit metadata role policy is accepted");
    let waterlog = open(metadata.0, "waterlog", true, Some(&tx))
        .unwrap()
        .unwrap();
    let water_head = read(&waterlog, "Head").unwrap();
    let water_genesis = read(&waterlog, "Genesis").unwrap();
    assert_eq!(
        unsafe { RegDeleteValueW(waterlog.0, wide("Genesis").as_ptr()) },
        0
    );
    assert_eq!(
        super::metadata::check_in(&private, seed, host, Some(&tx)),
        Err(Error::StateCorrupt)
    );
    assert!(
        read(&waterlog, "Genesis").is_err(),
        "read must not recreate missing genesis"
    );
    write(&waterlog, "Genesis", &water_genesis).unwrap();
    write(&waterlog, "Genesis", b"wrong-binding").unwrap();
    assert_eq!(check_members(), Err(Error::StateCorrupt));
    write(&waterlog, "Genesis", &water_genesis).unwrap();
    write(&waterlog, "Head", b"damaged").unwrap();
    assert_eq!(check_members(), Err(Error::StateCorrupt));
    write(&waterlog, "Head", &water_head).unwrap();
    let entries = open(waterlog.0, "entries", true, Some(&tx))
        .unwrap()
        .unwrap();
    write(&entries, "Unexpected", b"x").unwrap();
    assert!(check_members().is_err());
    assert_eq!(
        unsafe { RegDeleteValueW(entries.0, wide("Unexpected").as_ptr()) },
        0
    );
    write(&entries, "", b"unexpected-default").unwrap();
    assert_eq!(check_members(), Err(Error::StateCorrupt));
    assert_eq!(unsafe { RegDeleteValueW(entries.0, wide("").as_ptr()) }, 0);
    let extra = create(entries.0, "unexpected", &tx, false, true).unwrap();
    assert_eq!(check_members(), Err(Error::StateCorrupt));
    drop(extra);
    assert_eq!(
        unsafe {
            RegDeleteKeyTransactedW(
                entries.0,
                wide("unexpected").as_ptr(),
                KEY_WOW64_64KEY,
                0,
                tx.raw(),
                ptr::null(),
            )
        },
        0
    );
    drop(entries);
    assert_eq!(
        unsafe {
            RegDeleteKeyTransactedW(
                waterlog.0,
                wide("entries").as_ptr(),
                KEY_WOW64_64KEY,
                0,
                tx.raw(),
                ptr::null(),
            )
        },
        0
    );
    assert_eq!(
        super::metadata::check_in(&private, seed, host, Some(&tx)),
        Err(Error::StateCorrupt)
    );
    assert!(
        open(waterlog.0, "entries", false, Some(&tx))
            .unwrap()
            .is_none()
    );
    drop(waterlog);
    assert_eq!(
        unsafe {
            RegDeleteKeyTransactedW(
                metadata.0,
                wide("waterlog").as_ptr(),
                KEY_WOW64_64KEY,
                0,
                tx.raw(),
                ptr::null(),
            )
        },
        0
    );
    assert_eq!(
        super::metadata::check_in(&private, seed, host, Some(&tx)),
        Err(Error::StateCorrupt)
    );
    assert!(
        open(metadata.0, "waterlog", false, Some(&tx))
            .unwrap()
            .is_none()
    );
    let waterlog = create(metadata.0, "waterlog", &tx, false, true).unwrap();
    let entries = create(waterlog.0, "entries", &tx, false, true).unwrap();
    write(&waterlog, "Genesis", &water_genesis).unwrap();
    write(&waterlog, "Head", &water_head).unwrap();
    drop(entries);
    drop(waterlog);
    check_members().expect("restored empty waterlog is accepted");
    let original_head = read(&metadata, "Head").unwrap();
    write(&metadata, "Head", b"unknown-new-head").unwrap();
    assert_eq!(
        super::metadata::require_empty_for_root_transition_in(&private, seed, host, &tx),
        Err(Error::ScopeConflict)
    );
    assert_eq!(check_members(), Err(Error::ScopeConflict));
    write(&metadata, "Head", &original_head).unwrap();
    write(&metadata, "Unexpected", b"x").unwrap();
    assert!(
        super::metadata::require_empty_for_root_transition_in(&private, seed, host, &tx).is_err()
    );
    assert_eq!(
        unsafe { RegDeleteValueW(metadata.0, wide("Unexpected").as_ptr()) },
        0
    );
    super::metadata::require_empty_for_root_transition_in(&private, seed, host, &tx)
        .expect("restoring exact empty layout permits Root transition");
    check_members().expect("restored member genesis is accepted");
    let snapshots = create(private.0, "root-snapshot-test", &tx, false, true).unwrap();
    let mut count = 0u64;
    product_catalog::visit_members_in(seed, host, &tx, |event, actual| {
        let name = revision_name(count + 1);
        let mut wrong_host = actual.clone();
        wrong_host.profile_id = "other-profile".into();
        assert!(
            super::time::root_snapshot::capture_in(
                &snapshots,
                "wrong-host",
                seed,
                event,
                &wrong_host,
                &tx,
            )
            .is_err()
        );
        assert!(open(snapshots.0, "wrong-host", false, Some(&tx))?.is_none());
        let raw =
            super::time::root_snapshot::capture_in(&snapshots, &name, seed, event, actual, &tx)?;
        let member = open(snapshots.0, &name, true, Some(&tx))?.ok_or(Error::StateCorrupt)?;
        let denials = super::time::root_snapshot::read_in(&member, &tx, &raw)?;
        let mut lists = 0;
        denials.visit(&mut |ids| {
            assert!(ids.is_empty());
            lists += 1;
            Ok(())
        })?;
        assert_eq!(lists, 2);
        let saved_host = read(&member, "Host")?;
        write(&member, "Host", b"{}")?;
        assert!(super::time::root_snapshot::read_in(&member, &tx, &raw).is_err());
        write(&member, "Host", &saved_host)?;
        write(&member, "Policy", b"{}")?;
        assert!(super::time::root_snapshot::read_in(&member, &tx, &raw).is_err());
        count += 1;
        Ok(())
    })
    .unwrap();
    assert!(count > 0);
    let history = open(metadata.0, "history", true, Some(&tx))
        .unwrap()
        .unwrap();
    let extra = create(history.0, "0000000000000002", &tx, false, true).unwrap();
    drop(extra);
    assert!(
        super::metadata::require_empty_for_root_transition_in(&private, seed, host, &tx).is_err()
    );
    assert!(check_members().is_err());
}

// Construct the old serialized lab shape under the same test-owned protected
// root. This checks Store compatibility, not the historical installer.
#[allow(unsafe_code)]
fn legacy_ready_is_readable(store: &Store, seed: &Seed, initial: &HostRegistration) {
    use crate::registration::{Phase, StartupAttestation};
    let mut old = initial.clone();
    old.known_owner_namespaces = vec!["bootstrap-v1".into()];
    let files = old.next(Phase::FilesVerified, "verify-files").unwrap();
    let mut intent = files
        .next(Phase::FilesVerified, "service-create-intent")
        .unwrap();
    intent.service_identity.creation_operation_id =
        Some(old.installer_identity.operation_id.clone());
    let mut configured = intent
        .next(Phase::ServiceConfigured, "service-configured")
        .unwrap();
    configured.service_identity.service_sid = Some("S-1-5-80-1-2-3-4-5".into());
    let mut started = configured
        .next(Phase::ServiceConfigured, "startup-incarnation")
        .unwrap();
    started.host_epoch = 1;
    started.startup_attestation = Some(StartupAttestation {
        process_id: 2,
        creation_file_time: FileTime::from_native(0, 2),
        instance_nonce: "6".repeat(64),
        helper_image_sha256: started.helper.sha256.clone(),
        manifest_sha256: started.genesis_manifest_sha256.clone(),
        host_epoch: 1,
        observed_registration_revision: configured.revision,
    });
    let ready = started.next(Phase::Ready, "ready").unwrap();
    for entry in [&old, &files, &intent, &configured, &started, &ready] {
        entry.validate(seed).unwrap();
    }
    ready.validate(seed).unwrap();
    let private = store.key(true, None).unwrap().unwrap();
    for name in [
        METADATA_BOOTSTRAP,
        METADATA_BOOTSTRAP_ROOT,
        PREPARATION_BOOTSTRAP,
    ] {
        assert_eq!(
            unsafe { RegDeleteValueW(private.0, wide(name).as_ptr()) },
            0
        );
    }
    assert_eq!(
        unsafe { RegDeleteTreeW(private.0, wide("metadata-state-v1").as_ptr()) },
        0
    );
    // The old serialized namespace predates this owner. Remove it from this
    // test-owned fixture instead of treating a new owner as legacy migration.
    assert_eq!(
        unsafe { RegDeleteTreeW(private.0, wide("check-scope-v1").as_ptr()) },
        0
    );
    let first = open(private.0, "history\\0000000000000001", true, None)
        .unwrap()
        .unwrap();
    write(&first, "Record", &json::encode(&old, false).unwrap()).unwrap();
    drop(first);
    let tx = Handle::owned(unsafe {
        CreateTransaction(ptr::null_mut(), ptr::null_mut(), 0, 0, 0, 0, ptr::null())
    })
    .unwrap();
    let history = open(private.0, "history", true, Some(&tx))
        .unwrap()
        .unwrap();
    for entry in [&files, &intent, &configured, &started, &ready] {
        let revision = create(history.0, &revision_name(entry.revision), &tx, false, true).unwrap();
        write(&revision, "Record", &json::encode(entry, false).unwrap()).unwrap();
    }
    drop(history);
    assert_ne!(unsafe { CommitTransaction(tx.raw()) }, 0);
    drop(tx);
    write(&private, "Head", &json::encode(&ready, false).unwrap()).unwrap();
    drop(private);
    let public = store.public_key(None).unwrap().unwrap();
    write(
        &public,
        "Head",
        &json::encode(&ready.public(), false).unwrap(),
    )
    .unwrap();
    drop(public);
    let actual = store
        .read(seed)
        .unwrap()
        .expect("legacy Ready remains readable");
    assert_eq!(actual.digest().unwrap(), ready.digest().unwrap());
    assert_eq!(store.read_with_check_scope(seed).unwrap().1, None);
    assert!(matches!(
        store.original_root(seed, &actual),
        Err(Error::InitialTrustUnavailable)
    ));
    let private = store.key(false, None).unwrap().unwrap();
    assert!(
        open(private.0, "metadata-state-v1", false, None)
            .unwrap()
            .is_none(),
        "legacy read must not create metadata"
    );
}
