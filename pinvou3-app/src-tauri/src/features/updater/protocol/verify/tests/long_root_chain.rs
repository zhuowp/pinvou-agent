//! Verifier coverage only; does not exercise Windows custody or transactions.
use pinvou_upgrade_codec::{Document, InputKind};
use pinvou_upgrade_verifier::{
    SuppliedTimeObservation, TimeVerificationError, VerificationError, verify_time_response_source,
};
use std::borrow::Cow;
#[path = "support/long_root_fixture.rs"]
mod long_root_fixture;

#[test]
fn latest_only_time_can_authenticate_4097_independent_signed_roots() {
    let long_root_fixture::Fixture {
        original,
        roots,
        request,
        response,
        replacement,
    } = long_root_fixture::generate();
    let request = Document::parse(
        &serde_json::to_vec(&request).unwrap(),
        InputKind::Credential,
    )
    .unwrap()
    .time_request_shape()
    .unwrap();
    let obs = SuppliedTimeObservation {
        sent_monotonic_millis: 10,
        received_monotonic_millis: 20,
        max_round_trip_millis: 30_000,
        max_uncertainty_millis: 1_000,
        trusted_time_floor_millis: 0,
    };
    let run = |missing: Option<usize>, swapped: Option<usize>, replace_last: bool| {
        verify_time_response_source(
            &response,
            &original,
            roots.len(),
            |i| {
                if missing == Some(i) {
                    return Err(TimeVerificationError::InvalidObservation);
                }
                if replace_last && i == 4096 {
                    return Ok(Cow::Borrowed(replacement.as_slice()));
                }
                let index = if swapped == Some(i) { i + 1 } else { i };
                Ok(Cow::Borrowed(roots[index].as_slice()))
            },
            &request,
            obs,
            &[],
        )
    };
    let checked = run(None, None, false).unwrap();
    assert_eq!(checked.root_version(), 4098);
    assert_eq!(checked.checked_root_steps(), 4097);
    // Failures at the page boundary cannot be interpreted as end-of-chain.
    assert!(matches!(
        run(Some(4096), None, false),
        Err(TimeVerificationError::InvalidObservation)
    ));
    assert!(run(None, Some(4095), false).is_err());
    // A final rotation signed only by the old threshold must not be accepted.
    assert!(matches!(
        run(None, None, true),
        Err(TimeVerificationError::Verification(
            VerificationError::ThresholdUnmet
        ))
    ));
}
