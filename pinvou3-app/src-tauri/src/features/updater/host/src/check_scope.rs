//! Bounded check-scope DATA. Only the native first-install owner produces it.
//! These records and their JSON projection confer no current source authority.
use crate::{
    error::{Error, Result},
    json,
    registration::HostRegistration,
};
use serde::{Deserialize, Serialize};

pub(crate) const NAMESPACE: &str = "native-check-scope-v1";
pub(crate) const RECORD_LIMIT: usize = 4096;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    product: String,
    component: String,
    target_key: String,
    profile_kind: String,
    profile_id: String,
    seed_sha256: String,
    installation_scope_id: String,
    genesis_manifest_sha256: String,
    original_install_operation_id: String,
}
impl Binding {
    fn from_host(host: &HostRegistration) -> Self {
        Self {
            product: host.product.clone(),
            component: host.component.clone(),
            target_key: host.target_key.clone(),
            profile_kind: host.profile_kind.clone(),
            profile_id: host.profile_id.clone(),
            seed_sha256: host.genesis_seed_sha256.clone(),
            installation_scope_id: host.installation_scope_id.clone(),
            genesis_manifest_sha256: host.genesis_manifest_sha256.clone(),
            original_install_operation_id: host.original_install_operation_id.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Genesis {
    check_scope_genesis_version: u8,
    binding: Binding,
    install_id: String,
    initial_channel: String,
    initial_channel_revision: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Head {
    check_scope_head_version: u8,
    genesis_sha256: String,
    channel: String,
    channel_revision: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Scope<'a> {
    product: &'a str,
    component: &'a str,
    install_id: &'a str,
    installation_scope_id: &'a str,
    channel: &'a str,
    channel_revision: u64,
    target_key: &'a str,
}
/// Private comparison DATA, never constructible from a public diagnostic DTO.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    genesis: Vec<u8>,
    head: Vec<u8>,
    scope: Vec<u8>,
}
impl Snapshot {
    pub(crate) fn scope_json(&self) -> Vec<u8> {
        self.scope.clone()
    }
    pub(crate) fn genesis_bytes(&self) -> &[u8] {
        &self.genesis
    }
    pub(crate) fn head_bytes(&self) -> &[u8] {
        &self.head
    }
}

pub(crate) fn initial(host: &HostRegistration, install_id: String) -> Result<Snapshot> {
    let genesis = Genesis {
        check_scope_genesis_version: 1,
        binding: Binding::from_host(host),
        install_id,
        initial_channel: "stable".into(),
        initial_channel_revision: 1,
    };
    let raw = json::encode(&genesis, false)?;
    let head = Head {
        check_scope_head_version: 1,
        genesis_sha256: json::sha256(&raw),
        channel: "stable".into(),
        channel_revision: 1,
    };
    check_existing(host, &raw, &json::encode(&head, false)?)
}

pub(crate) fn check_existing(
    host: &HostRegistration,
    genesis: &[u8],
    head: &[u8],
) -> Result<Snapshot> {
    if genesis.len() > RECORD_LIMIT || head.len() > RECORD_LIMIT {
        return Err(Error::StateCorrupt);
    }
    let g: Genesis = json::decode(genesis, false)?;
    let h: Head = json::decode(head, false)?;
    // Version one has exactly one real producer: first-install Stable/1. Merely
    // decoding a later channel/revision cannot certify a channel transition.
    if json::encode(&g, false)? != genesis
        || json::encode(&h, false)? != head
        || g.check_scope_genesis_version != 1
        || h.check_scope_head_version != 1
        || g.binding != Binding::from_host(host)
        || !json::digest(&g.install_id)
        || g.install_id == host.installation_scope_id
        || g.install_id == host.original_install_operation_id
        || g.initial_channel != "stable"
        || g.initial_channel_revision != 1
        || h.genesis_sha256 != json::sha256(genesis)
        || h.channel != g.initial_channel
        || h.channel_revision != g.initial_channel_revision
    {
        return Err(Error::StateCorrupt);
    }
    let scope = Scope {
        product: &g.binding.product,
        component: &g.binding.component,
        install_id: &g.install_id,
        installation_scope_id: &g.binding.installation_scope_id,
        channel: &h.channel,
        channel_revision: h.channel_revision,
        target_key: &g.binding.target_key,
    };
    Ok(Snapshot {
        genesis: genesis.to_vec(),
        head: head.to_vec(),
        scope: json::encode(&scope, false)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{FileTime, LogonId},
        inventory,
        profile::Seed,
        registration::InstallerIdentity,
    };

    fn fixture() -> HostRegistration {
        // Immutable public DATA; this constructs no source/service capability.
        let seed: Seed = serde_json::from_str(include_str!(
            "../tests/metadata-component-fixture/seed.json"
        ))
        .unwrap();
        let input = inventory::tests::fixture_for_seed(&seed, vec![vec![inventory::tests::app()]]);
        let manifest = input.parse(&seed).unwrap();
        let installer = InstallerIdentity {
            process_id: 1, creation_file_time: FileTime::from_native(0, 1),
            token_user_sid: "S-1-5-18".into(), logon_authentication_id: LogonId { high: 0, low: 1 },
            session_id: 1, source_nsis_sha256: "4".repeat(64),
            source_nsis_file_identity: serde_json::from_value(serde_json::json!({"volume":1,"indexHigh":0,"indexLow":1,"createdHigh":0,"createdLow":1})).unwrap(),
            manifest_sha256: json::sha256(&input.root), operation_id: "9".repeat(64),
        };
        HostRegistration::initial(&seed, &manifest, "5".repeat(64), installer, None).unwrap()
    }

    #[test]
    fn check_scope_exact_projection_and_identity_binding() {
        let host = fixture();
        let data = initial(&host, "6".repeat(64)).unwrap();
        let scope: serde_json::Value = json::decode(&data.scope_json(), false).unwrap();
        assert_eq!(scope.as_object().unwrap().len(), 7);
        assert_eq!(scope["installId"], "6".repeat(64));
        assert_eq!(scope["installationScopeId"], host.installation_scope_id);
        assert_eq!(scope["channel"], "stable");
        assert_eq!(scope["channelRevision"], 1);
        assert!(initial(&host, host.installation_scope_id.clone()).is_err());
        assert!(initial(&host, host.original_install_operation_id.clone()).is_err());
        for key in [
            "product",
            "component",
            "targetKey",
            "profileKind",
            "profileId",
            "seedSha256",
            "installationScopeId",
            "genesisManifestSha256",
            "originalInstallOperationId",
        ] {
            let mut g: serde_json::Value = json::decode(&data.genesis, false).unwrap();
            g["binding"][key] = "different".into();
            let raw = json::encode(&g, false).unwrap();
            let mut h: serde_json::Value = json::decode(&data.head, false).unwrap();
            h["genesisSha256"] = json::sha256(&raw).into();
            assert_eq!(
                check_existing(&host, &raw, &json::encode(&h, false).unwrap()),
                Err(Error::StateCorrupt),
                "{key}"
            );
        }
    }

    #[test]
    fn check_scope_rejects_unproduced_heads_and_noncanonical_or_open_records() {
        let host = fixture();
        let data = initial(&host, "6".repeat(64)).unwrap();
        for (field, value) in [
            ("channel", serde_json::json!("beta")),
            ("channel", serde_json::json!("internal")),
            ("channelRevision", serde_json::json!(0)),
            ("channelRevision", serde_json::json!(2)),
            ("channelRevision", serde_json::json!(9007199254740991u64)),
            ("channelRevision", serde_json::json!(9007199254740992u64)),
            ("channelRevision", serde_json::json!(1.5)),
            ("checkScopeHeadVersion", serde_json::json!(2)),
            ("genesisSha256", serde_json::json!("0".repeat(64))),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut h: serde_json::Value = json::decode(&data.head, false).unwrap();
            h[field] = value;
            assert!(
                check_existing(&host, &data.genesis, &serde_json::to_vec(&h).unwrap()).is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("checkScopeGenesisVersion", serde_json::json!(2)),
            ("initialChannel", serde_json::json!("beta")),
            ("initialChannelRevision", serde_json::json!(2)),
            ("unknown", serde_json::json!(true)),
            ("installId", serde_json::json!("not-generated")),
        ] {
            let mut g: serde_json::Value = json::decode(&data.genesis, false).unwrap();
            g[field] = value;
            assert!(check_existing(&host, &serde_json::to_vec(&g).unwrap(), &data.head).is_err());
        }
        assert!(check_existing(&host, &vec![b' '; RECORD_LIMIT + 1], &data.head).is_err());
        assert!(
            check_existing(
                &host,
                &data.genesis,
                br#"{"channelRevision":1,"channelRevision":1}"#
            )
            .is_err()
        );
        let mut extra_space = data.genesis.clone();
        extra_space.push(b' ');
        assert!(check_existing(&host, &extra_space, &data.head).is_err());
    }
}
