//! Public, independently signed test objects; no test private key is retained.
//! This verifies the streaming protocol verifier, not protected custody or TxR.
use std::borrow::Cow;

use pinvou_upgrade_codec::{Document, InputKind};
use pinvou_upgrade_verifier::{
    SuppliedTimeObservation, TimeVerificationError, verify_time_response_source,
    verify_time_root_successor,
};

#[test]
fn signed_root_batch_over_one_mib_streams_and_missing_or_replaced_objects_fail() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("large-root-history.json")).unwrap();
    let original = fixture["original"].as_str().unwrap().as_bytes();
    let roots: Vec<&[u8]> = fixture["successors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().as_bytes())
        .collect();
    assert!(roots.iter().map(|raw| raw.len()).sum::<usize>() > 1024 * 1024);
    assert!(roots.iter().all(|raw| raw.len() <= 1024 * 1024));
    let mut previous = original;
    for root in &roots {
        verify_time_root_successor(previous, root, "pinvou", &[]).unwrap();
        previous = root;
    }
    let mut altered: serde_json::Value = serde_json::from_slice(roots[0]).unwrap();
    let signature = altered["signatures"][0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let first = if signature.starts_with('A') { "B" } else { "A" };
    altered["signatures"][0]["signature"] = format!("{first}{}", &signature[1..]).into();
    let altered = Document::parse(&serde_json::to_vec(&altered).unwrap(), InputKind::Metadata)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert!(
        verify_time_root_successor(original, &altered, "pinvou", &[]).is_err(),
        "a canonical Root with a damaged signature must not become an anchor"
    );
    let request = Document::parse(
        &serde_json::to_vec(&fixture["request"]).unwrap(),
        InputKind::Credential,
    )
    .unwrap()
    .time_request_shape()
    .unwrap();
    let observation = SuppliedTimeObservation {
        sent_monotonic_millis: 10,
        received_monotonic_millis: 20,
        max_round_trip_millis: 30_000,
        max_uncertainty_millis: 1_000,
        trusted_time_floor_millis: 0,
    };
    let response = fixture["response"].as_str().unwrap().as_bytes();
    let verify = |missing: Option<usize>, replace: Option<usize>| {
        verify_time_response_source(
            response,
            original,
            roots.len(),
            |index| {
                if missing == Some(index) {
                    return Err(TimeVerificationError::InvalidObservation);
                }
                let root = if replace == Some(index) {
                    roots[(index + 1) % roots.len()]
                } else {
                    roots[index]
                };
                Ok(Cow::Borrowed(root))
            },
            &request,
            observation,
            &[],
        )
    };
    let checked = verify(None, None).unwrap();
    assert_eq!(checked.root_version(), 5);
    assert_eq!(checked.checked_root_steps(), roots.len());
    assert!(
        verify(Some(1), None).is_err(),
        "a missing object is not end of history"
    );
    assert!(
        verify(None, Some(1)).is_err(),
        "a different signed object is not accepted"
    );
}
