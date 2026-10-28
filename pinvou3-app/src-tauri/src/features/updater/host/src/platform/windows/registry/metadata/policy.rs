//! Protected per-profile metadata-role deny policy; no fallback for absent data.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Policy {
    version: u8,
    binding: Binding,
    timestamp: Vec<String>,
    snapshot: Vec<String>,
    target: Vec<String>,
    release: Vec<String>,
    package: Vec<String>,
}

impl Policy {
    fn initial(binding: &Binding) -> Result<Self> {
        binding.validate()?;
        Ok(Self {
            version: 1,
            binding: binding.clone(),
            timestamp: Vec::new(),
            snapshot: Vec::new(),
            target: Vec::new(),
            release: Vec::new(),
            package: Vec::new(),
        })
    }
    pub(super) fn parse(raw: &[u8], binding: &Binding) -> Result<Self> {
        let policy: Self = json::decode(raw, false)?;
        if policy.version != 1 || policy.binding != *binding || json::encode(&policy, false)? != raw
        {
            return Err(Error::StateCorrupt);
        }
        policy.binding.validate()?;
        for ids in [
            &policy.timestamp,
            &policy.snapshot,
            &policy.target,
            &policy.release,
            &policy.package,
        ] {
            if ids.len() > 4096
                || ids.iter().any(|id| !json::digest(id))
                || ids.windows(2).any(|p| p[0] >= p[1])
            {
                return Err(Error::StateCorrupt);
            }
        }
        Ok(policy)
    }
    /// Detached data; the owner must re-read the exact policy and global deny
    /// within its held transaction before committing any metadata decision.
    pub(super) fn by_role(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        [
            ("timestamp", &self.timestamp),
            ("snapshot", &self.snapshot),
            ("target", &self.target),
            ("release", &self.release),
            ("package", &self.package),
        ]
        .into_iter()
        .map(|(role, ids)| (role.to_owned(), ids.clone()))
        .collect()
    }
}

pub(super) fn initialize_in(key: &Key, binding: &Binding) -> Result<()> {
    let raw = json::encode(&Policy::initial(binding)?, false)?;
    write(key, "Policy", &raw)?;
    Ok(())
}

pub(super) fn read_in(key: &Key, binding: &Binding) -> Result<(Policy, Vec<u8>)> {
    let raw = read(key, "Policy")?;
    Ok((Policy::parse(&raw, binding)?, raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            installation_scope_id: "scope".into(),
            product: "pinvou".into(),
            component: "app".into(),
            target_key: "windows-x86_64-exe-perMachine".into(),
            profile_kind: "production".into(),
            profile_id: "profile".into(),
            genesis_seed_sha256: "1".repeat(64),
            genesis_manifest_sha256: "2".repeat(64),
            original_install_operation_id: "operation".into(),
        }
    }
    #[test]
    fn explicit_roles_are_bound_canonical_and_never_default_on_damage() {
        let binding = binding();
        let policy = Policy::initial(&binding).unwrap();
        let raw = json::encode(&policy, false).unwrap();
        assert_eq!(Policy::parse(&raw, &binding).unwrap().by_role().len(), 5);
        let mut other = binding.clone();
        other.profile_id = "other".into();
        assert!(Policy::parse(&raw, &other).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value.as_object_mut().unwrap().remove("release");
        assert!(Policy::parse(&json::encode(&value, false).unwrap(), &binding).is_err());
        value["release"] = serde_json::json!(["bad"]);
        assert!(Policy::parse(&json::encode(&value, false).unwrap(), &binding).is_err());
        value["release"] = serde_json::json!(["a".repeat(64), "a".repeat(64)]);
        assert!(Policy::parse(&json::encode(&value, false).unwrap(), &binding).is_err());
        value["release"] = serde_json::json!(["a".repeat(64)]);
        assert_eq!(
            Policy::parse(&json::encode(&value, false).unwrap(), &binding)
                .unwrap()
                .by_role()["release"],
            vec!["a".repeat(64)]
        );
    }
}
