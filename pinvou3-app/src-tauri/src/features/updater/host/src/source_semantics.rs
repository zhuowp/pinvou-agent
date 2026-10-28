//! Image-bound supported-semantics declarations, never actual SourceFacts.
use crate::{
    error::{Error, Result},
    json,
    profile::Seed,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_SUPPORTED_LABELS: usize = 64;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleDeclaration {
    identity: String,
    publisher: String,
}

/// Closed declaration DATA supplied by the explicit build producer. Neither
/// these labels nor their image binding certify a runtime mode or data format.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourceSemanticsDeclaration {
    source_semantics_version: u8,
    product: String,
    component: String,
    target_key: String,
    profile_kind: String,
    profile_id: String,
    build_id: String,
    layout_id: String,
    app_version: String,
    seed_sha256: String,
    application: RoleDeclaration,
    helper: RoleDeclaration,
    launcher: RoleDeclaration,
    supported_ownership_protocols: Vec<String>,
    supported_data_formats: Vec<String>,
    supported_migration_protocols: Vec<String>,
}

impl SourceSemanticsDeclaration {
    pub(crate) fn validate(&self, seed: &Seed) -> Result<()> {
        let labels = |values: &[String]| {
            values.len() <= MAX_SUPPORTED_LABELS
                && values.iter().all(|value| json::identifier(value))
                && values.iter().collect::<BTreeSet<_>>().len() == values.len()
        };
        if self.source_semantics_version != 1
            || self.product != seed.product
            || self.component != seed.component
            || self.target_key != seed.target_key
            || self.profile_kind != seed.profile_kind
            || self.profile_id != seed.profile_id
            || self.build_id != seed.build_id
            || self.layout_id != seed.layout_id
            || self.app_version != seed.app_version
            || self.seed_sha256 != seed.seed_sha256()
            || [&self.application, &self.helper, &self.launcher]
                .iter()
                .any(|role| !json::identifier(&role.identity) || !json::identifier(&role.publisher))
            || !labels(&self.supported_ownership_protocols)
            || !labels(&self.supported_data_formats)
            || !labels(&self.supported_migration_protocols)
        {
            return Err(Error::ImageRefused);
        }
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        json::encode(self, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inventory, profile::RootManifest};
    use serde_json::{Value, json};

    fn declaration(seed: &Seed) -> Value {
        // Explicit declaration-only labels. No fixture certifies actual native
        // ownership, data, time mode, SourceFacts or current qualification.
        json!({
            "sourceSemanticsVersion":1,"product":seed.product,"component":seed.component,
            "targetKey":seed.target_key,"profileKind":seed.profile_kind,"profileId":seed.profile_id,
            "buildId":seed.build_id,"layoutId":seed.layout_id,"appVersion":seed.app_version,
            "seedSha256":seed.seed_sha256(),
            "application":{"identity":"declared-app","publisher":"declared-app-author"},
            "helper":{"identity":"declared-helper","publisher":"declared-helper-author"},
            "launcher":{"identity":"declared-launcher","publisher":"declared-launcher-author"},
            "supportedOwnershipProtocols":[],"supportedDataFormats":[],"supportedMigrationProtocols":[]
        })
    }

    fn fixture() -> (Seed, Value) {
        let (seed, input) = inventory::tests::fixture(vec![vec![inventory::tests::app()]]);
        let mut manifest: Value = serde_json::from_slice(&input.root).unwrap();
        manifest["hostManifestVersion"] = 3.into();
        manifest["sourceSemantics"] = declaration(&seed);
        (seed, manifest)
    }

    fn parse(value: &Value, seed: &Seed) -> Result<RootManifest> {
        RootManifest::parse(&json::encode(value, false).unwrap(), seed)
    }

    #[test]
    fn explicit_versions_preserve_v2_and_require_v3_declaration() {
        let (seed, original) = inventory::tests::fixture(vec![vec![inventory::tests::app()]]);
        let v2 = RootManifest::parse(&original.root, &seed).unwrap();
        assert_eq!(json::encode(&v2, false).unwrap(), original.root);
        assert_eq!(v2.source_semantics_json(), Err(Error::SourceUnavailable));
        let (_, mut wire) = fixture();
        let v3 = parse(&wire, &seed).unwrap();
        assert_eq!(
            v3.source_semantics_json().unwrap(),
            json::encode(&declaration(&seed), false).unwrap()
        );
        wire["hostManifestVersion"] = 2.into();
        assert!(parse(&wire, &seed).is_err());
        wire["hostManifestVersion"] = 3.into();
        wire.as_object_mut().unwrap().remove("sourceSemantics");
        assert!(parse(&wire, &seed).is_err());
        wire["hostManifestVersion"] = 4.into();
        assert!(parse(&wire, &seed).is_err());
        wire["hostManifestVersion"] = 2.into();
        wire["sourceSemantics"] = Value::Null;
        assert!(parse(&wire, &seed).is_err());
    }

    #[test]
    fn declaration_is_closed_and_bound_to_every_seed_context_field() {
        let (seed, wire) = fixture();
        for field in [
            "product",
            "component",
            "targetKey",
            "profileKind",
            "profileId",
            "buildId",
            "layoutId",
            "appVersion",
            "seedSha256",
        ] {
            let mut changed = wire.clone();
            changed["sourceSemantics"][field] = "other-context".into();
            assert!(parse(&changed, &seed).is_err(), "{field}");
        }
        for field in [
            "sourceSemanticsVersion",
            "application",
            "supportedDataFormats",
        ] {
            let mut changed = wire.clone();
            changed["sourceSemantics"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(parse(&changed, &seed).is_err(), "{field}");
        }
        for pointer in ["", "/helper"] {
            let mut changed = wire.clone();
            changed["sourceSemantics"].pointer_mut(pointer).unwrap()["trusted"] = true.into();
            assert!(parse(&changed, &seed).is_err());
        }
        let mut changed = wire;
        changed["sourceSemantics"]["sourceSemanticsVersion"] = 2.into();
        assert!(parse(&changed, &seed).is_err());
    }

    #[test]
    fn labels_are_explicit_bounded_unique_and_do_not_require_a_certificate() {
        let (seed, wire) = fixture();
        for role in ["application", "helper", "launcher"] {
            for field in ["identity", "publisher"] {
                for bad in [
                    String::new(),
                    "space label".into(),
                    "a".repeat(129),
                    "../path".into(),
                ] {
                    let mut changed = wire.clone();
                    changed["sourceSemantics"][role][field] = bad.into();
                    assert!(parse(&changed, &seed).is_err());
                }
            }
        }
        for field in [
            "supportedOwnershipProtocols",
            "supportedDataFormats",
            "supportedMigrationProtocols",
        ] {
            let mut changed = wire.clone();
            changed["sourceSemantics"][field] = json!(["protocol-B", "protocol-A"]);
            parse(&changed, &seed).unwrap();
            for bad in [
                json!(["same", "same"]),
                json!([""]),
                json!(["bad label"]),
                json!((0..65).map(|i| format!("label-{i}")).collect::<Vec<_>>()),
            ] {
                changed["sourceSemantics"][field] = bad;
                assert!(parse(&changed, &seed).is_err());
            }
        }
    }

    #[test]
    #[ignore = "compile with the immutable metadata-component-fixture Seed/Root inputs"]
    fn actual_js_manifest_and_inventory_bind_the_same_declaration_bytes() {
        // Same frozen JS buildInstallationManifest output checked by the Node
        // packaging test. Ordinary payload DATA is deliberately not executable.
        const SEED: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/metadata-component-fixture/seed.json"
        ));
        const ROOT: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/metadata-component-fixture/root.json"
        ));
        const MANIFEST: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/source-semantics-fixture/manifest.json"
        ));
        const SHARD: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/source-semantics-fixture/inventory-0.json"
        ));
        let seed = Seed::embedded().unwrap();
        // This is an opt-in compiled-profile test, never a fallback Seed or a
        // passing empty-profile test that silently skips its real assertions.
        assert_eq!(seed.seed_sha256(), json::sha256(SEED));
        assert_eq!(seed.original_root_bytes(), ROOT);
        let input = inventory::InventoryBytes {
            root: MANIFEST.to_vec(),
            shards: vec![SHARD.to_vec()],
        };
        let accepted = input.parse(&seed).unwrap();
        assert_eq!(accepted.host_manifest_version, 3);
        assert_eq!(accepted.app_files.len(), 1);
        let payload = b"Public declaration fixture DATA; not an executable.\n";
        assert_eq!(accepted.app.size, payload.len() as u64);
        assert_eq!(accepted.app.sha256, json::sha256(payload));
        assert_eq!(accepted.app_files[0].sha256, accepted.app.sha256);
        let declaration: Value =
            serde_json::from_slice(&accepted.source_semantics_json().unwrap()).unwrap();
        assert_eq!(declaration, self::declaration(&seed));
        for field in [
            "supportedOwnershipProtocols",
            "supportedDataFormats",
            "supportedMigrationProtocols",
        ] {
            assert!(declaration[field].as_array().unwrap().is_empty());
        }
        let mut altered: Value = serde_json::from_slice(MANIFEST).unwrap();
        altered["sourceSemantics"]["buildId"] = "c".repeat(64).into();
        let bad = inventory::InventoryBytes {
            root: json::encode(&altered, false).unwrap(),
            shards: vec![SHARD.to_vec()],
        };
        assert!(bad.parse(&seed).is_err());
        altered = serde_json::from_slice(MANIFEST).unwrap();
        altered["appInventory"]["shards"][0]["sha256"] = "d".repeat(64).into();
        let bad = inventory::InventoryBytes {
            root: json::encode(&altered, false).unwrap(),
            shards: vec![SHARD.to_vec()],
        };
        assert!(bad.parse(&seed).is_err());
        altered = serde_json::from_slice(MANIFEST).unwrap();
        altered["app"]["sha256"] = "e".repeat(64).into();
        let bad = inventory::InventoryBytes {
            root: json::encode(&altered, false).unwrap(),
            shards: vec![SHARD.to_vec()],
        };
        assert!(bad.parse(&seed).is_err());
    }
}
