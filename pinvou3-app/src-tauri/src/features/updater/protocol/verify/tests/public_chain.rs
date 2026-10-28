use base64::{Engine, engine::general_purpose::STANDARD};
use pinvou_upgrade_codec::{Document, InputKind};
use pinvou_upgrade_verifier::{
    PublicChainError, PublicChainInputs, VerificationInputs, verify_public_chain,
    verify_public_chain_interval, verify_public_chain_source_interval, verify_with_supplied_root,
};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, process::Command, sync::OnceLock};

fn document(value: &Value) -> Document {
    Document::parse(&serde_json::to_vec(value).unwrap(), InputKind::Metadata).unwrap()
}
fn cases() -> &'static [Value] {
    static CASES: OnceLock<Vec<Value>> = OnceLock::new();
    CASES.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(7)
            .unwrap();
        let output = Command::new("node")
            .args([
                "--input-type=module",
                "-e",
                include_str!("public-chain-oracle.mjs"),
            ])
            .arg(root.join("specs/upgrade/v1/reference/signatures.mjs"))
            .output()
            .expect("Node is required for the complete public-chain oracle");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    })
}
fn check_group(group: &str, count: usize) {
    let mut actual = 0;
    for case in cases().iter().filter(|c| c["group"] == group) {
        actual += 1;
        let root = document(&case["trustedRoot"]).root_policy_shape().unwrap();
        let context = document(&case["context"]);
        let now = document(&case["now"]).protocol_time_shape().unwrap();
        let timestamp = STANDARD
            .decode(case["timestamp"].as_str().unwrap())
            .unwrap();
        let snapshot = STANDARD.decode(case["snapshot"].as_str().unwrap()).unwrap();
        let members: Vec<_> = case["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| STANDARD.decode(m.as_str().unwrap()).unwrap())
            .collect();
        let borrowed: Vec<_> = members.iter().map(Vec::as_slice).collect();
        let denied: Vec<String> = serde_json::from_value(case["deniedKeyIds"].clone()).unwrap();
        let role_denied: BTreeMap<String, Vec<String>> =
            serde_json::from_value(case["deniedKeyIdsByRole"].clone()).unwrap();
        let mut inputs = PublicChainInputs::new(&root, &context, &now).with_denied_key_ids(&denied);
        for (role, ids) in &role_denied {
            inputs = inputs.with_role_denied_key_ids(role, ids);
        }
        match verify_public_chain(&timestamp, &snapshot, &borrowed, inputs) {
            Ok(checked) => {
                assert_eq!(
                    case["accepted"], true,
                    "unexpected chain acceptance {}",
                    case["name"]
                );
                assert!(std::ptr::eq(checked.supplied_root(), &root));
                assert_eq!(checked.supplied_time_millis(), now.as_millis());
                assert_eq!(checked.timestamp().envelope().raw_bytes(), timestamp);
                assert_eq!(checked.snapshot().envelope().raw_bytes(), snapshot);
                assert_eq!(checked.members().len(), members.len());
                for (checked, raw) in checked.members().iter().zip(&members) {
                    assert_eq!(checked.envelope().raw_bytes(), raw);
                }
            }
            Err(error) => {
                assert_eq!(
                    case["accepted"], false,
                    "unexpected chain refusal {}: {error}",
                    case["name"]
                );
                let code = case["code"].as_str().unwrap();
                let expected = match (case["name"].as_str().unwrap(), code) {
                    // Same necessary preallocation bound as the unchanged codec;
                    // an oversized actual list refuses before duplicate scanning.
                    ("duplicate-actual-member", _) => "PUBLIC_MEMBER_UNREFERENCED",
                    (_, "REFERENCE_MISMATCH") => "METADATA_REFERENCE_MISMATCH",
                    (_, "SCHEMA_INVALID") => "ENVELOPE_SCHEMA_INVALID",
                    (_, "ROLE_NOT_AUTHORIZED") => "ROLE_POLICY_NOT_DECLARED",
                    _ => code,
                };
                assert_eq!(
                    error.to_string(),
                    expected,
                    "wrong refusal {}",
                    case["name"]
                );
            }
        }
    }
    assert_eq!(actual, count, "changed public-chain group {group}");
}
#[test]
fn complete_reference_membership_and_public_reachability() {
    check_group("relationships", 34);
}
#[test]
fn global_and_role_denial_preserve_other_role_positive_controls() {
    check_group("denial", 9);
}
#[test]
fn actual_thresholds_all_extras_and_unsigned_changes() {
    check_group("signatures", 5);
}
#[test]
fn fresh_root_and_body_windows_are_required() {
    check_group("time", 3);
}

#[test]
fn interval_requires_every_instant_to_be_inside_all_fresh_windows() {
    let case = cases()
        .iter()
        .find(|case| case["name"] == "strong-signed-complete-positive")
        .unwrap();
    let root = document(&case["trustedRoot"]).root_policy_shape().unwrap();
    let context = document(&case["context"]);
    let timestamp = STANDARD
        .decode(case["timestamp"].as_str().unwrap())
        .unwrap();
    let snapshot = STANDARD.decode(case["snapshot"].as_str().unwrap()).unwrap();
    let members: Vec<_> = case["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| STANDARD.decode(item.as_str().unwrap()).unwrap())
        .collect();
    let borrowed: Vec<_> = members.iter().map(Vec::as_slice).collect();
    let mut claims = vec![case["trustedRoot"].clone()];
    claims.extend(
        [&timestamp, &snapshot]
            .into_iter()
            .chain(members.iter())
            .map(|bytes| serde_json::from_slice::<Value>(bytes).unwrap()["signed"].clone()),
    );
    let lower = claims
        .iter()
        .filter_map(|v| v["issuedAt"].as_i64())
        .max()
        .unwrap();
    let upper = claims
        .iter()
        .filter_map(|v| v["expiresAt"].as_i64())
        .min()
        .unwrap();
    assert!(lower > 0 && upper > lower);
    let time = |value| document(&Value::from(value)).protocol_time_shape().unwrap();
    let earliest = time(lower);
    let latest = time(upper - 1);
    let checked = verify_public_chain_interval(
        &timestamp,
        &snapshot,
        &borrowed,
        PublicChainInputs::new(&root, &context, &earliest),
        &latest,
    )
    .unwrap();
    assert_eq!(checked.earliest_millis(), lower as f64);
    assert_eq!(checked.latest_millis(), (upper - 1) as f64);
    assert_eq!(
        checked.chain().timestamp().envelope().raw_bytes(),
        timestamp
    );
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed,
            PublicChainInputs::new(&root, &context, &earliest),
            &earliest
        )
        .is_ok()
    );
    let too_early = time(lower - 1);
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed,
            PublicChainInputs::new(&root, &context, &too_early),
            &latest
        )
        .is_err()
    );
    let expired = time(upper);
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed,
            PublicChainInputs::new(&root, &context, &earliest),
            &expired
        )
        .is_err()
    );
    assert!(matches!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed,
            PublicChainInputs::new(&root, &context, &latest),
            &earliest
        ),
        Err(PublicChainError::InvalidInterval)
    ));
    let denied = vec![
        case["trustedRoot"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["role"] == "timestamp")
            .unwrap()["keyIds"][0]
            .as_str()
            .unwrap()
            .to_owned(),
    ];
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed,
            PublicChainInputs::new(&root, &context, &earliest).with_denied_key_ids(&denied),
            &latest
        )
        .is_err()
    );
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed,
            PublicChainInputs::new(&root, &context, &earliest)
                .with_role_denied_key_ids("timestamp", &denied),
            &latest
        )
        .is_err()
    );
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed,
            PublicChainInputs::new(&root, &context, &earliest)
                .with_role_denied_key_ids("download", &denied),
            &latest
        )
        .is_ok()
    );
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &borrowed[..borrowed.len() - 1],
            PublicChainInputs::new(&root, &context, &earliest),
            &latest
        )
        .is_err()
    );
    let mut altered = members.clone();
    altered[0].push(b' ');
    let altered_refs: Vec<_> = altered.iter().map(Vec::as_slice).collect();
    assert!(
        verify_public_chain_interval(
            &timestamp,
            &snapshot,
            &altered_refs,
            PublicChainInputs::new(&root, &context, &earliest),
            &latest
        )
        .is_err()
    );
}
#[test]
fn exact_policy_original_wire_and_production_package_rules() {
    check_group("wire_policy", 5);
}

#[test]
fn source_interval_rechecks_actual_originals_across_graph_passes() {
    let case = cases()
        .iter()
        .find(|c| c["name"] == "strong-signed-complete-positive")
        .unwrap();
    let root = document(&case["trustedRoot"]).root_policy_shape().unwrap();
    let context = document(&case["context"]);
    let now = document(&case["now"]).protocol_time_shape().unwrap();
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
    let borrowed: Vec<_> = members.iter().map(Vec::as_slice).collect();
    let inputs = || PublicChainInputs::new(&root, &context, &now);
    let mut visits = vec![0usize; members.len()];
    let checked = verify_public_chain_source_interval(
        &timestamp,
        &snapshot,
        members.len(),
        |i| {
            visits[i] += 1;
            Ok(members[i].clone())
        },
        inputs(),
        &now,
    )
    .unwrap();
    assert_eq!(checked.member_count(), members.len());
    assert_eq!(checked.earliest_millis(), now.as_millis());
    assert_eq!(checked.latest_millis(), now.as_millis());
    assert!(
        std::mem::size_of_val(&checked) <= 32,
        "the returned proof retains no member bodies"
    );
    assert!(
        visits.iter().all(|count| *count >= 3),
        "both graph passes reload actual members"
    );
    assert!(verify_public_chain_interval(&timestamp, &snapshot, &borrowed, inputs(), &now).is_ok());
    let mut calls = 0;
    let failed = verify_public_chain_source_interval(
        &timestamp,
        &snapshot,
        members.len(),
        |i| {
            calls += 1;
            if calls > members.len() && i == 0 {
                Err(PublicChainError::SourceUnavailable)
            } else {
                Ok(members[i].clone())
            }
        },
        inputs(),
        &now,
    );
    assert!(matches!(failed, Err(PublicChainError::SourceUnavailable)));
    let mut reads = vec![0usize; members.len()];
    assert!(
        verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len(),
            |i| {
                reads[i] += 1;
                Ok(if i == 0 && reads[i] > 1 {
                    members[1].clone()
                } else {
                    members[i].clone()
                })
            },
            inputs(),
            &now
        )
        .is_err(),
        "changed source cannot reuse the first reference"
    );
    assert!(
        verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len() - 1,
            |i| Ok(members[i].clone()),
            inputs(),
            &now
        )
        .is_err()
    );
    let mut duplicate_reads = 0;
    assert!(matches!(
        verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len(),
            |i| {
                duplicate_reads += 1;
                Ok(members[if i == 1 { 0 } else { i }].clone())
            },
            inputs(),
            &now
        ),
        Err(PublicChainError::Graph(
            pinvou_upgrade_codec::PublicGraphError::MemberDuplicate
        ))
    ));
    assert_eq!(
        duplicate_reads, 2,
        "duplicate references are refused before accumulating more input"
    );
    let release = members
        .iter()
        .find(|raw| serde_json::from_slice::<Value>(raw).unwrap()["signed"]["role"] == "release")
        .unwrap();
    let key = serde_json::from_slice::<Value>(release).unwrap()["signatures"][0]["keyId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].clone()),
            inputs().with_role_denied_key_ids("release", &[key]),
            &now
        )
        .is_err()
    );
    let later = document(&serde_json::json!(case["now"].as_u64().unwrap() + 1))
        .protocol_time_shape()
        .unwrap();
    assert!(matches!(
        verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].clone()),
            PublicChainInputs::new(&root, &context, &later),
            &now
        ),
        Err(PublicChainError::InvalidInterval)
    ));
    let expired = document(&serde_json::json!(9_007_199_254_740_991_u64))
        .protocol_time_shape()
        .unwrap();
    assert!(
        verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].clone()),
            inputs(),
            &expired
        )
        .is_err()
    );
}

#[test]
fn source_accepts_large_independent_signed_members_without_returning_bodies() {
    let root_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(7)
        .unwrap();
    let script = r#"
      import {pathToFileURL} from 'node:url';
      const ref=pathToFileURL(process.argv[1]);
      const {createFixtureSet,NOW}=await import(new URL('./tests/fixtures.mjs',ref));
      const {envelopeReference}=await import(ref);
      const f=createFixtureSet(), pkg=f.sign(f.metadata.package), releases=[];
      for(let i=0;i<8;i++) {
        const r=structuredClone(f.metadata.release); r.scope.releaseId=`release-${i+20}`;
        r.notes={'zh-CN':'a'.repeat(50000),en:'b'.repeat(50000),ja:'c'.repeat(50000)};
        r.targets[0].packageManifest=envelopeReference(pkg); releases.push(f.sign(r));
      }
      const target=structuredClone(f.metadata.target);
      target.baselineRelease=envelopeReference(releases[0]);
      target.ordinaryPaths=releases.slice(1).map((r,i)=>({deploymentId:`deployment-${i+20}`,
        deploymentRevision:1,approvalId:`approval-${i+20}`,approvalRevision:1,release:envelopeReference(r)}));
      const members=[f.sign(target),...releases,pkg], snap=structuredClone(f.metadata.snapshot);
      snap.entries=members.map(envelopeReference);
      const snapshot=f.sign(snap), timestamp=structuredClone(f.metadata.timestamp);
      timestamp.snapshot=envelopeReference(snapshot);
      const b64=x=>Buffer.from(x).toString('base64');
      console.log(JSON.stringify({root:f.metadata.root,context:{product:'pinvou',component:'app'},now:NOW,
        timestamp:b64(f.sign(timestamp)),snapshot:b64(snapshot),members:members.map(b64)}));
    "#;
    let output = Command::new("node")
        .args(["--input-type=module", "-e", script])
        .arg(root_dir.join("specs/upgrade/v1/reference/signatures.mjs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let case: Value = serde_json::from_slice(&output.stdout).unwrap();
    let root = document(&case["root"]).root_policy_shape().unwrap();
    let context = document(&case["context"]);
    let now = document(&case["now"]).protocol_time_shape().unwrap();
    let decode = |v: &Value| STANDARD.decode(v.as_str().unwrap()).unwrap();
    let timestamp = decode(&case["timestamp"]);
    let snapshot = decode(&case["snapshot"]);
    let members: Vec<Vec<u8>> = case["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    assert!(members.iter().map(Vec::len).sum::<usize>() > 1024 * 1024);
    assert!(members.iter().all(|item| item.len() <= 1024 * 1024));
    let mut reads = 0;
    let proof = verify_public_chain_source_interval(
        &timestamp,
        &snapshot,
        members.len(),
        |i| {
            reads += 1;
            Ok(members[i].clone())
        },
        PublicChainInputs::new(&root, &context, &now),
        &now,
    )
    .unwrap();
    assert_eq!(proof.member_count(), members.len());
    assert!(reads > members.len() * 2);
    assert!(std::mem::size_of_val(&proof) <= 32);
}

#[test]
fn source_failure_or_replacement_on_second_time_endpoint_is_not_accepted() {
    let case = cases()
        .iter()
        .find(|c| c["name"] == "strong-signed-complete-positive")
        .unwrap();
    let root = document(&case["trustedRoot"]).root_policy_shape().unwrap();
    let context = document(&case["context"]);
    let first = document(&case["now"]).protocol_time_shape().unwrap();
    let last = document(&serde_json::json!(case["now"].as_u64().unwrap() + 1))
        .protocol_time_shape()
        .unwrap();
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
    let mut order = Vec::new();
    let checked = verify_public_chain_source_interval(
        &timestamp,
        &snapshot,
        members.len(),
        |i| {
            order.push(i);
            Ok(members[i].clone())
        },
        PublicChainInputs::new(&root, &context, &first),
        &last,
    )
    .unwrap();
    assert!(checked.latest_millis() > checked.earliest_millis());
    let graph_reads = &order[members.len()..];
    assert_eq!(graph_reads.len() % 2, 0);
    let half = graph_reads.len() / 2;
    assert!(half > 0);
    assert_eq!(&graph_reads[..half], &graph_reads[half..]);
    let high_first = members.len() + half;
    let mut seen = 0;
    let failed = verify_public_chain_source_interval(
        &timestamp,
        &snapshot,
        members.len(),
        |i| {
            let current = seen;
            seen += 1;
            if current == high_first {
                Err(PublicChainError::SourceUnavailable)
            } else {
                Ok(members[i].clone())
            }
        },
        PublicChainInputs::new(&root, &context, &first),
        &last,
    );
    assert!(matches!(failed, Err(PublicChainError::SourceUnavailable)));
    let mut seen = 0;
    let replaced = verify_public_chain_source_interval(
        &timestamp,
        &snapshot,
        members.len(),
        |i| {
            let current = seen;
            seen += 1;
            Ok(if current == high_first {
                members[(i + 1) % members.len()].clone()
            } else {
                members[i].clone()
            })
        },
        PublicChainInputs::new(&root, &context, &first),
        &last,
    );
    assert!(matches!(
        replaced,
        Err(PublicChainError::Graph(
            pinvou_upgrade_codec::PublicGraphError::Reference(
                pinvou_upgrade_codec::MetadataReferenceError::Mismatch
            )
        ))
    ));
}

#[test]
fn signed_oracle_acceptance_agrees_between_slice_and_source() {
    for case in cases() {
        let root = document(&case["trustedRoot"]).root_policy_shape().unwrap();
        let context = document(&case["context"]);
        let now = document(&case["now"]).protocol_time_shape().unwrap();
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
        let borrowed: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();
        let denied: Vec<String> = serde_json::from_value(case["deniedKeyIds"].clone()).unwrap();
        let denied_by_role: BTreeMap<String, Vec<String>> =
            serde_json::from_value(case["deniedKeyIdsByRole"].clone()).unwrap();
        let input = || {
            let mut inputs =
                PublicChainInputs::new(&root, &context, &now).with_denied_key_ids(&denied);
            for (role, ids) in &denied_by_role {
                inputs = inputs.with_role_denied_key_ids(role, ids);
            }
            inputs
        };
        let slice =
            verify_public_chain_interval(&timestamp, &snapshot, &borrowed, input(), &now).is_ok();
        let source = verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].clone()),
            input(),
            &now,
        )
        .is_ok();
        assert_eq!(
            source, slice,
            "source/slice acceptance differs for {}",
            case["name"]
        );
    }
}

#[test]
fn source_checks_member_expiry_at_second_endpoint_independently() {
    let root_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(7)
        .unwrap();
    let script = r#"
      import {pathToFileURL} from 'node:url';
      const ref=pathToFileURL(process.argv[1]);
      const {createFixtureSet,NOW}=await import(new URL('./tests/fixtures.mjs',ref));
      const {envelopeReference}=await import(ref);
      const f=createFixtureSet(), pkg=f.sign(f.metadata.package);
      const release=structuredClone(f.metadata.release); release.targets[0].packageManifest=envelopeReference(pkg);
      const releaseBytes=f.sign(release), target=structuredClone(f.metadata.target);
      target.expiresAt=NOW+5; target.baselineRelease=envelopeReference(releaseBytes);
      const members=[f.sign(target),releaseBytes,pkg], snap=structuredClone(f.metadata.snapshot);
      snap.entries=members.map(envelopeReference); const snapshot=f.sign(snap);
      const timestamp=structuredClone(f.metadata.timestamp); timestamp.snapshot=envelopeReference(snapshot);
      const b64=x=>Buffer.from(x).toString('base64');
      console.log(JSON.stringify({root:f.metadata.root,context:{product:'pinvou',component:'app'},now:NOW,
        timestamp:b64(f.sign(timestamp)),snapshot:b64(snapshot),members:members.map(b64)}));
    "#;
    let output = Command::new("node")
        .args(["--input-type=module", "-e", script])
        .arg(root_dir.join("specs/upgrade/v1/reference/signatures.mjs"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let case: Value = serde_json::from_slice(&output.stdout).unwrap();
    let root = document(&case["root"]).root_policy_shape().unwrap();
    let context = document(&case["context"]);
    let now = case["now"].as_u64().unwrap();
    let first = document(&serde_json::json!(now))
        .protocol_time_shape()
        .unwrap();
    let before = document(&serde_json::json!(now + 4))
        .protocol_time_shape()
        .unwrap();
    let expiry = document(&serde_json::json!(now + 5))
        .protocol_time_shape()
        .unwrap();
    let decode = |v: &Value| STANDARD.decode(v.as_str().unwrap()).unwrap();
    let timestamp = decode(&case["timestamp"]);
    let snapshot = decode(&case["snapshot"]);
    let members: Vec<Vec<u8>> = case["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    let run = |last| {
        verify_public_chain_source_interval(
            &timestamp,
            &snapshot,
            members.len(),
            |i| Ok(members[i].clone()),
            PublicChainInputs::new(&root, &context, &first),
            last,
        )
    };
    assert!(run(&before).is_ok());
    assert!(run(&expiry).is_err());
    root.assert_supplied_current_window(&expiry).unwrap();
    for (role, raw) in [("timestamp", &timestamp), ("snapshot", &snapshot)] {
        let expected = document(
            &serde_json::json!({"role":role,"product":"pinvou","component":"app","scope":{}}),
        );
        verify_with_supplied_root(raw, VerificationInputs::new(&root, &expected, &expiry)).unwrap();
    }
}
