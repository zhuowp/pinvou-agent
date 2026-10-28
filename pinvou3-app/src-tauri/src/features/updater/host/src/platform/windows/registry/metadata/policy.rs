//! Protected per-profile metadata-role deny policy; no fallback for absent data.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const ROLES: [&str; 5] = ["timestamp", "snapshot", "target", "release", "package"];

fn validate_ids(ids: &[String]) -> Result<()> {
    if ids.len() > 4096
        || ids.iter().any(|id| !json::digest(id))
        || ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(Error::StateCorrupt);
    }
    Ok(())
}

/// An empty previous map means no admitted batch. Every snapshot otherwise has
/// all five explicit roles; neither unknown roles nor sparse resets are valid.
pub(super) fn require_retained_denials(
    current: &BTreeMap<String, Vec<String>>,
    previous: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    let validate = |map: &BTreeMap<String, Vec<String>>| -> Result<()> {
        if map.len() != ROLES.len() || ROLES.iter().any(|role| !map.contains_key(*role)) {
            return Err(Error::StateCorrupt);
        }
        for ids in map.values() {
            validate_ids(ids)?;
        }
        Ok(())
    };
    validate(current)?;
    if !previous.is_empty() {
        validate(previous)?;
    }
    for (role, ids) in previous {
        let retained = current.get(role).ok_or(Error::StateCorrupt)?;
        if ids.iter().any(|id| retained.binary_search(id).is_err()) {
            return Err(Error::StateCorrupt);
        }
    }
    Ok(())
}

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
            validate_ids(ids)?;
        }
        Ok(policy)
    }
    /// Check current native policy against historical DATA without changing it
    /// or applying later denials retroactively to historical graph decisions.
    pub(super) fn require_retains(&self, previous: &BTreeMap<String, Vec<String>>) -> Result<()> {
        require_retained_denials(&self.by_role(), previous)
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

    fn snapshot(entries: &[(&str, Vec<String>)]) -> Policy {
        let binding = binding();
        let mut value = serde_json::to_value(Policy::initial(&binding).unwrap()).unwrap();
        for (role, ids) in entries {
            value[*role] = serde_json::json!(ids);
        }
        Policy::parse(&json::encode(&value, false).unwrap(), &binding).unwrap()
    }

    #[test]
    fn canonical_snapshots_allow_additions_but_never_remove_or_move_denials() {
        let initial = snapshot(&[]);
        assert_eq!(initial.require_retains(&BTreeMap::new()), Ok(()));
        for role in ROLES {
            let first = snapshot(&[(role, vec!["a".repeat(64)])]);
            let added = snapshot(&[(role, vec!["a".repeat(64), "b".repeat(64)])]);
            assert_eq!(first.require_retains(&initial.by_role()), Ok(()));
            assert_eq!(first.require_retains(&first.by_role()), Ok(()));
            assert_eq!(added.require_retains(&first.by_role()), Ok(()));
            assert_eq!(
                first.require_retains(&added.by_role()),
                Err(Error::StateCorrupt)
            );
            assert_eq!(
                initial.require_retains(&first.by_role()),
                Err(Error::StateCorrupt)
            );
            let other_role = ROLES.into_iter().find(|other| *other != role).unwrap();
            let moved = snapshot(&[(other_role, vec!["a".repeat(64)])]);
            assert_eq!(
                moved.require_retains(&first.by_role()),
                Err(Error::StateCorrupt)
            );
        }
    }

    #[test]
    fn retention_rejects_unknown_sparse_or_malformed_role_maps() {
        let current = snapshot(&[("release", vec!["a".repeat(64)])]).by_role();
        let mut unknown = current.clone();
        unknown.insert("root".into(), Vec::new());
        let mut sparse = current.clone();
        sparse.remove("package");
        let mut replaced = sparse.clone();
        replaced.insert("root".into(), Vec::new());
        let mut malformed = current.clone();
        malformed.insert("release".into(), vec!["bad".into()]);
        let mut duplicate = current.clone();
        duplicate.insert("release".into(), vec!["a".repeat(64); 2]);
        let mut unsorted = current.clone();
        unsorted.insert("release".into(), vec!["b".repeat(64), "a".repeat(64)]);
        for invalid in [unknown, sparse, replaced, malformed, duplicate, unsorted] {
            assert_eq!(
                require_retained_denials(&invalid, &current),
                Err(Error::StateCorrupt)
            );
            assert_eq!(
                require_retained_denials(&current, &invalid),
                Err(Error::StateCorrupt)
            );
        }
        assert_eq!(
            require_retained_denials(&BTreeMap::new(), &BTreeMap::new()),
            Err(Error::StateCorrupt)
        );
    }

    #[test]
    fn cumulative_role_knowledge_keeps_the_existing_per_role_cardinality_bound() {
        let ids: Vec<String> = (0..4096).map(|i| format!("{i:064x}")).collect();
        for role in ROLES {
            // Each role reaches its limit separately; the canonical record's
            // independent total byte bound remains intact as well.
            let full = snapshot(&[(role, ids.clone())]);
            let retained = full.by_role();
            assert_eq!(retained.len(), 5);
            assert_eq!(retained[role].len(), 4096);
            assert!(retained.values().all(|ids| ids.len() <= 4096));
            assert_eq!(full.require_retains(&retained), Ok(()));
            let mut excessive = retained.clone();
            excessive
                .get_mut(role)
                .unwrap()
                .push(format!("{:064x}", 4096));
            assert_eq!(
                require_retained_denials(&excessive, &retained),
                Err(Error::StateCorrupt)
            );
            assert_eq!(full.require_retains(&excessive), Err(Error::StateCorrupt));
            let mut value = serde_json::to_value(&full).unwrap();
            value[role] = serde_json::json!(excessive[role]);
            assert!(Policy::parse(&serde_json::to_vec(&value).unwrap(), &binding()).is_err());
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
