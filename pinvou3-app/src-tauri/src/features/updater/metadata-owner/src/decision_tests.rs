use super::decision::verify_renewal;
use super::{
    DecisionError, DecisionInputs, OwnedPriorWater, PriorWater, decide_public_metadata,
    decide_public_metadata_owned, decide_public_metadata_source,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use pinvou_upgrade_codec::decode_canonical_envelope;
use pinvou_upgrade_codec::{Document, InputKind};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, process::Command};

struct DropProbe {
    inner: OwnedPriorWater,
    live: std::rc::Rc<std::cell::Cell<usize>>,
    dropped: std::rc::Rc<std::cell::Cell<usize>>,
}
impl super::decision::PriorItem for DropProbe {
    fn record(&self) -> &Document {
        &self.inner.record
    }
    fn previous_release(&self) -> Option<(&[u8], &pinvou_upgrade_codec::RootPolicyShape)> {
        self.inner
            .previous_release
            .as_ref()
            .map(|(bytes, root)| (bytes.as_slice(), root))
    }
}
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
        self.dropped.set(self.dropped.get() + 1);
    }
}

fn document(value: &Value) -> Document {
    Document::parse(&serde_json::to_vec(value).unwrap(), InputKind::Metadata).unwrap()
}

#[test]
fn signed_release_renewal_checks_archived_trust_and_immutable_business() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(6)
        .unwrap();
    let output = Command::new("node")
        .args([
            "--input-type=module",
            "-e",
            include_str!("../../protocol/verify/tests/release-renewal-oracle.mjs"),
        ])
        .arg(root.join("specs/upgrade/v1/reference/signatures.mjs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (name, expected) in [
        ("expired-history-distinct-current-signer", true),
        ("immutable-appVersion", false),
    ] {
        let case = cases.iter().find(|c| c["name"] == name).unwrap();
        let archived = document(&case["archivedRoot"]).root_policy_shape().unwrap();
        let current = document(&case["currentRoot"]).root_policy_shape().unwrap();
        let context = document(&case["context"]);
        let time = document(&case["now"]).protocol_time_shape().unwrap();
        let old = STANDARD
            .decode(case["previousBytes"].as_str().unwrap())
            .unwrap();
        let next = STANDARD
            .decode(case["nextBytes"].as_str().unwrap())
            .unwrap();
        let old = decode_canonical_envelope(&old, InputKind::Metadata)
            .unwrap()
            .check_full_schema()
            .unwrap();
        let next = decode_canonical_envelope(&next, InputKind::Metadata)
            .unwrap()
            .check_full_schema()
            .unwrap();
        let denied: Vec<String> = serde_json::from_value(case["deniedKeyIds"].clone()).unwrap();
        let by_role = BTreeMap::new();
        let inputs = DecisionInputs {
            root: &current,
            context: &context,
            earliest: &time,
            latest: &time,
            denied: &denied,
            denied_by_role: &by_role,
        };
        assert_eq!(
            verify_renewal(&old, &next, &archived, &inputs).is_ok(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn signed_graph_requires_complete_success_and_each_protected_high_water() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(6)
        .unwrap();
    let output = Command::new("node")
        .args([
            "--input-type=module",
            "-e",
            include_str!("../../protocol/verify/tests/public-chain-oracle.mjs"),
        ])
        .arg(root.join("specs/upgrade/v1/reference/signatures.mjs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let case = cases
        .iter()
        .find(|c| c["name"] == "strong-signed-complete-positive")
        .unwrap();
    let trusted_root = document(&case["trustedRoot"]).root_policy_shape().unwrap();
    let context = document(&case["context"]);
    let time = document(&case["now"]).protocol_time_shape().unwrap();
    let timestamp = STANDARD
        .decode(case["timestamp"].as_str().unwrap())
        .unwrap();
    let snapshot = STANDARD.decode(case["snapshot"].as_str().unwrap()).unwrap();
    let members: Vec<Vec<u8>> = case["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| STANDARD.decode(v.as_str().unwrap()).unwrap())
        .collect();
    let members: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();
    let denied = BTreeMap::new();
    let inputs = || DecisionInputs {
        root: &trusted_root,
        context: &context,
        earliest: &time,
        latest: &time,
        denied: &[],
        denied_by_role: &denied,
    };
    let decision =
        decide_public_metadata(&timestamp, &snapshot, &members, inputs(), |_| Ok(None)).unwrap();
    assert_eq!(decision.updates().len(), 4); // timestamp, snapshot, target, release; not package
    let mut source_reads = 0usize;
    let source = decide_public_metadata_source(
        &timestamp,
        &snapshot,
        members.len(),
        |i| {
            source_reads += 1;
            Ok(members[i].to_vec())
        },
        inputs(),
        |_| Ok(None),
    )
    .unwrap();
    let fields = |d: &super::Decision| {
        d.updates()
            .iter()
            .map(|w| (w.context().to_vec(), w.version(), w.sha256().to_owned()))
            .collect::<Vec<_>>()
    };
    assert_eq!(fields(&decision), fields(&source));
    let later = document(&json!(case["now"].as_u64().unwrap() + 1))
        .protocol_time_shape()
        .unwrap();
    let distinct_inputs = || DecisionInputs {
        root: &trusted_root,
        context: &context,
        earliest: &time,
        latest: &later,
        denied: &[],
        denied_by_role: &denied,
    };
    let distinct_slice =
        decide_public_metadata_owned(&timestamp, &snapshot, &members, distinct_inputs(), |_| {
            Ok(None)
        })
        .unwrap();
    let distinct_source = decide_public_metadata_source(
        &timestamp,
        &snapshot,
        members.len(),
        |i| Ok(members[i].to_vec()),
        distinct_inputs(),
        |_| Ok(None),
    )
    .unwrap();
    assert_eq!(fields(&distinct_slice), fields(&distinct_source));
    let mut late_visits = 0;
    assert!(matches!(
        decide_public_metadata_source(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].to_vec()),
            inputs(),
            |ctx| {
                late_visits += 1;
                if ctx.value()["role"] == "release" {
                    Err(DecisionError::PriorUnavailable)
                } else {
                    Ok(None)
                }
            }
        ),
        Err(DecisionError::PriorUnavailable)
    ));
    assert!(
        late_visits > 1,
        "late prior failure must not return earlier updates"
    );
    let final_pass_start = source_reads - members.len();
    let mut count = 0usize;
    assert!(matches!(
        decide_public_metadata_source(
            &timestamp,
            &snapshot,
            members.len(),
            |i| {
                let current = count;
                count += 1;
                if current == final_pass_start {
                    Err(DecisionError::SourceUnavailable)
                } else {
                    Ok(members[i].to_vec())
                }
            },
            inputs(),
            |_| Ok(None)
        ),
        Err(DecisionError::SourceUnavailable)
    ));
    let mut count = 0usize;
    assert!(matches!(
        decide_public_metadata_source(
            &timestamp,
            &snapshot,
            members.len(),
            |i| {
                let current = count;
                count += 1;
                Ok(if current == final_pass_start {
                    members[(i + 1) % members.len()].to_vec()
                } else {
                    members[i].to_vec()
                })
            },
            inputs(),
            |_| Ok(None)
        ),
        Err(DecisionError::Verification)
    ));
    let mut records = BTreeMap::new();
    for update in decision.updates() {
        let scope: Value = serde_json::from_slice(update.context()).unwrap();
        records.insert(
            update.context().to_vec(),
            document(&json!({"scope":scope,
            "version":update.version(),"envelopeSha256":update.sha256()})),
        );
    }
    let compare = |map: &BTreeMap<Vec<u8>, Document>| {
        decide_public_metadata(&timestamp, &snapshot, &members, inputs(), |ctx| {
            Ok(map
                .get(&ctx.canonical_bytes().unwrap())
                .map(|record| PriorWater {
                    record,
                    previous_release: None,
                }))
        })
        .map(|d| d.updates().len())
    };
    assert_eq!(compare(&records), Ok(4));
    let compare_owned = |map: &BTreeMap<Vec<u8>, Document>| {
        decide_public_metadata_owned(&timestamp, &snapshot, &members, inputs(), |ctx| {
            Ok(map
                .get(&ctx.canonical_bytes().unwrap())
                .map(|record| OwnedPriorWater {
                    record: document(record.value()),
                    previous_release: None,
                }))
        })
        .map(|d| d.updates().len())
    };
    assert_eq!(compare_owned(&records), Ok(4));
    let compare_source = |map: &BTreeMap<Vec<u8>, Document>| {
        decide_public_metadata_source(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].to_vec()),
            inputs(),
            |ctx| {
                Ok(map
                    .get(&ctx.canonical_bytes().unwrap())
                    .map(|record| OwnedPriorWater {
                        record: document(record.value()),
                        previous_release: None,
                    }))
            },
        )
        .map(|d| d.updates().len())
    };
    assert_eq!(compare_source(&records), Ok(4));
    assert!(matches!(
        decide_public_metadata_source(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].to_vec()),
            inputs(),
            |_| Err(DecisionError::PriorUnavailable)
        ),
        Err(DecisionError::PriorUnavailable)
    ));
    let live = std::rc::Rc::new(std::cell::Cell::new(0));
    let dropped = std::rc::Rc::new(std::cell::Cell::new(0));
    let probe = super::decision::decide_inner(&timestamp, &snapshot, &members, inputs(), |ctx| {
        assert_eq!(
            live.get(),
            0,
            "previous item must be released before the next read"
        );
        let record = records.get(&ctx.canonical_bytes().unwrap()).unwrap();
        live.set(1);
        Ok(Some(DropProbe {
            inner: OwnedPriorWater {
                record: document(record.value()),
                previous_release: None,
            },
            live: live.clone(),
            dropped: dropped.clone(),
        }))
    })
    .unwrap();
    assert_eq!(live.get(), 0);
    assert_eq!(dropped.get(), 4);
    let values = |d: &super::Decision| {
        d.updates()
            .iter()
            .map(|w| (w.context().to_vec(), w.version(), w.sha256().to_owned()))
            .collect::<Vec<_>>()
    };
    assert_eq!(values(&decision), values(&probe));
    dropped.set(0);
    let source_probe = super::decision::decide_source_inner(
        &timestamp,
        &snapshot,
        members.len(),
        |i| Ok(members[i].to_vec()),
        inputs(),
        |ctx| {
            assert_eq!(
                live.get(),
                0,
                "previous source item must be released before the next read"
            );
            let record = records.get(&ctx.canonical_bytes().unwrap()).unwrap();
            live.set(1);
            Ok(Some(DropProbe {
                inner: OwnedPriorWater {
                    record: document(record.value()),
                    previous_release: None,
                },
                live: live.clone(),
                dropped: dropped.clone(),
            }))
        },
    )
    .unwrap();
    assert_eq!(live.get(), 0);
    assert_eq!(dropped.get(), 4);
    assert_eq!(values(&decision), values(&source_probe));
    let mut owned_visits = 0;
    assert!(matches!(
        decide_public_metadata_owned(&timestamp, &snapshot, &members, inputs(), |ctx| {
            owned_visits += 1;
            if ctx.value()["role"] == "release" {
                return Err(DecisionError::PriorUnavailable);
            }
            Ok(records
                .get(&ctx.canonical_bytes().unwrap())
                .map(|record| OwnedPriorWater {
                    record: document(record.value()),
                    previous_release: None,
                }))
        }),
        Err(DecisionError::PriorUnavailable)
    ));
    assert!(owned_visits > 1);
    let first = decision.updates()[0].context().to_vec();
    let scope: Value = serde_json::from_slice(&first).unwrap();
    let clone_records = || {
        records
            .iter()
            .map(|(key, value)| (key.clone(), document(value.value())))
            .collect::<BTreeMap<_, _>>()
    };
    let mut rollback = clone_records();
    rollback.insert(first.clone(), document(&json!({"scope":scope,"version":decision.updates()[0].version()+1,"envelopeSha256":"0".repeat(64)})));
    assert_eq!(compare(&rollback), Err(DecisionError::Rollback));
    assert_eq!(compare_owned(&rollback), Err(DecisionError::Rollback));
    assert_eq!(compare_source(&rollback), Err(DecisionError::Rollback));
    let mut fork = clone_records();
    fork.insert(first, document(&json!({"scope":scope,"version":decision.updates()[0].version(),"envelopeSha256":"0".repeat(64)})));
    assert_eq!(compare(&fork), Err(DecisionError::Equivocation));
    assert_eq!(compare_owned(&fork), Err(DecisionError::Equivocation));
    assert_eq!(compare_source(&fork), Err(DecisionError::Equivocation));
    for role in ["target", "release"] {
        let item = decision
            .updates()
            .iter()
            .find(|item| serde_json::from_slice::<Value>(item.context()).unwrap()["role"] == role)
            .unwrap();
        let scope: Value = serde_json::from_slice(item.context()).unwrap();
        for (version, expected) in [
            (item.version() + 1, DecisionError::Rollback),
            (item.version(), DecisionError::Equivocation),
        ] {
            let mut changed = clone_records();
            changed.insert(
                item.context().to_vec(),
                document(&json!({"scope":scope,"version":version,"envelopeSha256":"0".repeat(64)})),
            );
            assert_eq!(compare(&changed), Err(expected), "{role}");
        }
    }
    let mut wrong_scope = clone_records();
    let mut changed_scope = scope.clone();
    changed_scope["component"] = json!("another-component");
    wrong_scope.insert(decision.updates()[0].context().to_vec(), document(&json!({"scope":changed_scope,"version":decision.updates()[0].version(),"envelopeSha256":decision.updates()[0].sha256()})));
    assert_eq!(compare(&wrong_scope), Err(DecisionError::InvalidPrior));
    let mut visited = 0;
    assert!(matches!(
        decide_public_metadata(&timestamp, &snapshot, &members, inputs(), |ctx| {
            visited += 1;
            if ctx.value()["role"] == "release" {
                Err(DecisionError::PriorUnavailable)
            } else {
                Ok(None)
            }
        }),
        Err(DecisionError::PriorUnavailable)
    ));
    assert!(
        visited > 1,
        "a late failure cannot return earlier proposed updates"
    );
    assert!(matches!(
        decide_public_metadata(&timestamp, &snapshot, &members, inputs(), |_| Err(
            DecisionError::PriorUnavailable
        )),
        Err(DecisionError::PriorUnavailable)
    ));
    assert!(matches!(
        decide_public_metadata(
            &timestamp,
            &snapshot,
            &members[..members.len() - 1],
            inputs(),
            |_| Ok(None)
        ),
        Err(DecisionError::Verification)
    ));
    let mut calls = 0;
    let denied_id = serde_json::from_slice::<Value>(&timestamp).unwrap()["signatures"][0]["keyId"]
        .as_str()
        .unwrap()
        .to_owned();
    let denied_ids = [denied_id];
    let blocked = DecisionInputs {
        root: &trusted_root,
        context: &context,
        earliest: &time,
        latest: &time,
        denied: &denied_ids,
        denied_by_role: &denied,
    };
    assert!(matches!(
        decide_public_metadata(&timestamp, &snapshot, &members, blocked, |_| {
            calls += 1;
            Ok(None)
        }),
        Err(DecisionError::Verification)
    ));
    assert_eq!(
        calls, 0,
        "invalid signatures/denials cannot reach the protected water source"
    );
    let release = members
        .iter()
        .find(|raw| serde_json::from_slice::<Value>(raw).unwrap()["signed"]["role"] == "release")
        .unwrap();
    let release_id = serde_json::from_slice::<Value>(release).unwrap()["signatures"][0]["keyId"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut role_denied = BTreeMap::new();
    role_denied.insert("release".to_owned(), vec![release_id]);
    let role_inputs = DecisionInputs {
        root: &trusted_root,
        context: &context,
        earliest: &time,
        latest: &time,
        denied: &[],
        denied_by_role: &role_denied,
    };
    assert!(matches!(
        decide_public_metadata(&timestamp, &snapshot, &members, role_inputs, |_| Ok(None)),
        Err(DecisionError::Verification)
    ));
    let later = document(&json!(case["now"].as_u64().unwrap() + 1))
        .protocol_time_shape()
        .unwrap();
    let interval = |first, last| DecisionInputs {
        root: &trusted_root,
        context: &context,
        earliest: first,
        latest: last,
        denied: &[],
        denied_by_role: &denied,
    };
    assert!(
        decide_public_metadata(
            &timestamp,
            &snapshot,
            &members,
            interval(&time, &later),
            |_| Ok(None)
        )
        .is_ok()
    );
    assert!(matches!(
        decide_public_metadata(
            &timestamp,
            &snapshot,
            &members,
            interval(&later, &time),
            |_| Ok(None)
        ),
        Err(DecisionError::Verification)
    ));
    let deadline = std::iter::once(timestamp.as_slice())
        .chain(std::iter::once(snapshot.as_slice()))
        .chain(members.iter().copied())
        .filter_map(|raw| {
            serde_json::from_slice::<Value>(raw).unwrap()["signed"]["expiresAt"].as_u64()
        })
        .chain(case["trustedRoot"]["expiresAt"].as_u64())
        .min()
        .unwrap();
    let before_expiry = document(&json!(deadline - 1))
        .protocol_time_shape()
        .unwrap();
    let at_expiry = document(&json!(deadline)).protocol_time_shape().unwrap();
    assert!(
        decide_public_metadata(
            &timestamp,
            &snapshot,
            &members,
            interval(&time, &before_expiry),
            |_| Ok(None)
        )
        .is_ok()
    );
    assert!(matches!(
        decide_public_metadata(
            &timestamp,
            &snapshot,
            &members,
            interval(&time, &at_expiry),
            |_| Ok(None)
        ),
        Err(DecisionError::Verification)
    ));
    let mut duplicate = members.clone();
    duplicate[1] = members[0];
    assert!(matches!(
        decide_public_metadata(&timestamp, &snapshot, &duplicate, inputs(), |_| Ok(None)),
        Err(DecisionError::Verification)
    ));
    let mut extra = members.clone();
    extra.push(timestamp.as_slice());
    assert!(matches!(
        decide_public_metadata(&timestamp, &snapshot, &extra, inputs(), |_| Ok(None)),
        Err(DecisionError::Verification)
    ));
}

#[test]
fn full_signed_graph_requires_the_matching_archived_release_for_renewal() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(6)
        .unwrap();
    let script = r#"
      import {pathToFileURL} from 'node:url';
      const ref=pathToFileURL(process.argv[1]);
      const {createFixtureSet,NOW}=await import(new URL('./tests/fixtures.mjs',ref));
      const {envelopeReference}=await import(ref);
      const f=createFixtureSet(), pkg=f.sign(f.metadata.package);
      const old=structuredClone(f.metadata.release);
      old.targets[0].packageManifest=envelopeReference(pkg);
      const oldBytes=f.sign(old), other=structuredClone(old); other.appVersion='7.7.7';
      const otherBytes=f.sign(other), next=structuredClone(old); next.revision=2;
      const nextBytes=f.sign(next), target=structuredClone(f.metadata.target);
      target.baselineRelease=envelopeReference(nextBytes);
      const targetBytes=f.sign(target), snap=structuredClone(f.metadata.snapshot);
      snap.entries=[targetBytes,nextBytes,pkg].map(envelopeReference);
      const snapshot=f.sign(snap), timestamp=structuredClone(f.metadata.timestamp);
      timestamp.snapshot=envelopeReference(snapshot);
      const enc=x=>Buffer.from(x).toString('base64');
      console.log(JSON.stringify({root:f.metadata.root,now:NOW,context:{product:'pinvou',component:'app'},
        old:enc(oldBytes), other:enc(otherBytes), timestamp:enc(f.sign(timestamp)),
        snapshot:enc(snapshot), members:[targetBytes,nextBytes,pkg].map(enc)}));
    "#;
    let output = Command::new("node")
        .args(["--input-type=module", "-e", script])
        .arg(root.join("specs/upgrade/v1/reference/signatures.mjs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let case: Value = serde_json::from_slice(&output.stdout).unwrap();
    let trusted_root = document(&case["root"]).root_policy_shape().unwrap();
    let context = document(&case["context"]);
    let time = document(&case["now"]).protocol_time_shape().unwrap();
    let decode = |v: &Value| STANDARD.decode(v.as_str().unwrap()).unwrap();
    let old = decode(&case["old"]);
    let other = decode(&case["other"]);
    let timestamp = decode(&case["timestamp"]);
    let snapshot = decode(&case["snapshot"]);
    let members: Vec<Vec<u8>> = case["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    let members: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();
    let denied = BTreeMap::new();
    let inputs = || DecisionInputs {
        root: &trusted_root,
        context: &context,
        earliest: &time,
        latest: &time,
        denied: &[],
        denied_by_role: &denied,
    };
    let release = decode_canonical_envelope(&old, InputKind::Metadata)
        .unwrap()
        .check_full_schema()
        .unwrap();
    let value = release.envelope().signed().value();
    let scope = json!({"role":value["role"],"product":value["product"],"component":value["component"],"scope":value["scope"]});
    let record = |bytes: &[u8]| {
        document(&json!({"scope":scope,"version":1,"envelopeSha256":super::sha256(bytes)}))
    };
    let water = record(&old);
    let call = |water: &Document, previous: Option<&[u8]>| {
        decide_public_metadata(&timestamp, &snapshot, &members, inputs(), |ctx| {
            Ok((ctx.value()["role"] == "release").then_some(PriorWater {
                record: water,
                previous_release: previous.map(|p| (p, &trusted_root)),
            }))
        })
        .map(|d| d.updates().len())
    };
    assert_eq!(call(&water, Some(&old)), Ok(4));
    let owned = decide_public_metadata_owned(&timestamp, &snapshot, &members, inputs(), |ctx| {
        Ok((ctx.value()["role"] == "release").then(|| OwnedPriorWater {
            record: document(water.value()),
            previous_release: Some((
                old.clone(),
                document(&case["root"]).root_policy_shape().unwrap(),
            )),
        }))
    });
    assert!(owned.is_ok());
    let sourced = decide_public_metadata_source(
        &timestamp,
        &snapshot,
        members.len(),
        |i| Ok(members[i].to_vec()),
        inputs(),
        |ctx| {
            Ok((ctx.value()["role"] == "release").then(|| OwnedPriorWater {
                record: document(water.value()),
                previous_release: Some((
                    old.clone(),
                    document(&case["root"]).root_policy_shape().unwrap(),
                )),
            }))
        },
    );
    assert!(sourced.is_ok());
    assert_eq!(call(&water, None), Err(DecisionError::PriorUnavailable));
    assert_eq!(call(&water, Some(&other)), Err(DecisionError::InvalidPrior));
    assert_eq!(
        call(&record(&other), Some(&other)),
        Err(DecisionError::ReleaseRenewal)
    );
    let mut corrupted: Value = serde_json::from_slice(&old).unwrap();
    corrupted["signatures"][0]["signature"] =
        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0; 64]));
    let corrupted = document(&corrupted).canonical_bytes().unwrap();
    assert_eq!(
        call(&record(&corrupted), Some(&corrupted)),
        Err(DecisionError::ReleaseRenewal)
    );
    assert!(matches!(
        decide_public_metadata_source(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].to_vec()),
            inputs(),
            |ctx| {
                Ok((ctx.value()["role"] == "release").then(|| OwnedPriorWater {
                    record: record(&corrupted),
                    previous_release: Some((
                        corrupted.clone(),
                        document(&case["root"]).root_policy_shape().unwrap(),
                    )),
                }))
            }
        ),
        Err(DecisionError::ReleaseRenewal)
    ));
    let failed_owned =
        decide_public_metadata_owned(&timestamp, &snapshot, &members, inputs(), |ctx| {
            Ok((ctx.value()["role"] == "release").then(|| OwnedPriorWater {
                record: record(&corrupted),
                previous_release: Some((
                    corrupted.clone(),
                    document(&case["root"]).root_policy_shape().unwrap(),
                )),
            }))
        });
    assert!(matches!(failed_owned, Err(DecisionError::ReleaseRenewal)));
}

#[test]
fn source_and_slice_decisions_agree_for_signed_graph_oracle() {
    let root_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(6)
        .unwrap();
    let output = Command::new("node")
        .args([
            "--input-type=module",
            "-e",
            include_str!("../../protocol/verify/tests/public-chain-oracle.mjs"),
        ])
        .arg(root_dir.join("specs/upgrade/v1/reference/signatures.mjs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in &cases {
        let root = document(&case["trustedRoot"]).root_policy_shape().unwrap();
        let context = document(&case["context"]);
        let time = document(&case["now"]).protocol_time_shape().unwrap();
        let decode = |v: &Value| STANDARD.decode(v.as_str().unwrap()).unwrap();
        let timestamp = decode(&case["timestamp"]);
        let snapshot = decode(&case["snapshot"]);
        let members: Vec<Vec<u8>> = case["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode)
            .collect();
        let borrowed: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();
        let denied: Vec<String> = serde_json::from_value(case["deniedKeyIds"].clone()).unwrap();
        let roles: BTreeMap<String, Vec<String>> =
            serde_json::from_value(case["deniedKeyIdsByRole"].clone()).unwrap();
        let inputs = || DecisionInputs {
            root: &root,
            context: &context,
            earliest: &time,
            latest: &time,
            denied: &denied,
            denied_by_role: &roles,
        };
        let slice =
            decide_public_metadata_owned(&timestamp, &snapshot, &borrowed, inputs(), |_| Ok(None));
        let source = decide_public_metadata_source(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].clone()),
            inputs(),
            |_| Ok(None),
        );
        let fields = |d: &super::Decision| {
            d.updates()
                .iter()
                .map(|w| (w.context().to_vec(), w.version(), w.sha256().to_owned()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            slice.as_ref().ok().map(fields),
            source.as_ref().ok().map(fields),
            "{}",
            case["name"]
        );
    }
}
