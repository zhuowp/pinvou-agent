//! Test-only Root history fixture. All signing keys are generated in memory.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pinvou_upgrade_codec::{Document, InputKind};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{Value, json};

pub struct Fixture {
    pub original: Vec<u8>,
    pub roots: Vec<Vec<u8>>,
    pub request: Value,
    pub response: Vec<u8>,
    pub replacement: Vec<u8>,
}

fn key() -> (Ed25519KeyPair, Value) {
    let material = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(material.as_ref()).unwrap();
    let public = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let descriptor = pinvou_upgrade_codec::key_descriptor(&public).unwrap();
    let value = json!({"keyId":descriptor.key_id(),"algorithm":"ed25519","publicKey":public});
    (pair, value)
}

fn signed(claims: &Value, keys: &[(&Ed25519KeyPair, &Value)]) -> Vec<u8> {
    let input = Document::parse(&serde_json::to_vec(claims).unwrap(), InputKind::Metadata)
        .unwrap()
        .signing_input()
        .unwrap();
    let mut signatures: Vec<_> = keys
        .iter()
        .map(|(key, descriptor)| {
            json!({
                "keyId": descriptor["keyId"],
                "signature": URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).as_ref()),
            })
        })
        .collect();
    signatures.sort_by(|a, b| {
        a["keyId"]
            .as_str()
            .unwrap()
            .cmp(b["keyId"].as_str().unwrap())
    });
    Document::parse(
        &serde_json::to_vec(&json!({"signed":claims,"signatures":signatures})).unwrap(),
        InputKind::Metadata,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap()
}

fn sha(raw: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, raw)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn generate() -> Fixture {
    let (r1, d1) = key();
    let (r2, d2) = key();
    let (_r3, d3) = key();
    let (n1, e1) = key();
    let (n2, e2) = key();
    let (_n3, e3) = key();
    let (time, dt) = key();
    let claims = |version, new: bool| {
        let (a, b, c) = if new {
            (&e1, &e2, &e3)
        } else {
            (&d1, &d2, &d3)
        };
        json!({
            "protocolVersion":1,"role":"root","product":"pinvou","component":null,"scope":{},
            "version":version,"issuedAt":90_000,"expiresAt":200_000,
            "keys":[a,b,c,&dt],
            "roles":[
                {"role":"root","component":null,"channel":null,"targetKey":null,"threshold":2,"keyIds":[a["keyId"],b["keyId"],c["keyId"]]},
                {"role":"time","component":"app","channel":null,"targetKey":null,"threshold":1,"keyIds":[dt["keyId"]]}
            ]
        })
    };
    let signers = [(&r1, &d1), (&r2, &d2)];
    let original = signed(&claims(1, false), &signers);
    // Each Root is independent; this Vec is test storage, not a JSON array in the protocol.
    let roots: Vec<Vec<u8>> = (2..=4098)
        .map(|n| {
            if n == 4098 {
                signed(
                    &claims(n, true),
                    &[(&r1, &d1), (&r2, &d2), (&n1, &e1), (&n2, &e2)],
                )
            } else {
                signed(&claims(n, false), &signers)
            }
        })
        .collect();
    assert_eq!(roots.len(), 4097);
    assert!(roots.iter().all(|r| r.len() <= 1024 * 1024));
    let reference = json!({"version":4098,"sha256":sha(roots.last().unwrap())});
    let nonce = URL_SAFE_NO_PAD.encode([11_u8; 32]);
    let request = json!({"protocolVersion":1,"product":"pinvou","component":"app","requestNonce":nonce,"root":reference});
    let response = signed(
        &json!({"protocolVersion":1,"role":"time","product":"pinvou","component":"app","scope":{},"purpose":"trusted-time.v1","requestNonce":nonce,"root":reference,"serverTime":100_000,"uncertaintyMs":5}),
        &[(&time, &dt)],
    );
    let replacement = signed(&claims(4098, true), &signers);
    Fixture {
        original,
        roots,
        request,
        response,
        replacement,
    }
}
