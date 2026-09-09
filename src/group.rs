//! Group chat model and helpers.
//!
//! Groups are local address-book entries: a stable ID (`NL-GRP-<16 hex>`), a
//! display name and the NL-IDs of the members. There is no server and no
//! invitation protocol in v2.1.0 — members join by ID and every peer keeps
//! its own member list. A group message is fanned out by the sender as one
//! individually encrypted (per-session ChaCha20-Poly1305) message per member,
//! so the existing end-to-end security properties are unchanged.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::types::Config;

/// Maximum number of members per group.
pub const MAX_MEMBERS: usize = 50;

/// A group chat definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub creator: String,
    pub members: HashSet<String>,
    /// Unix timestamp (seconds) of creation.
    pub created_at: u64,
}

impl Group {
    /// Create a fresh group with a random `NL-GRP-<16 hex>` ID. The creator
    /// is automatically the first member.
    pub fn new(name: &str, creator: &str) -> Result<Self> {
        validate_group_name(name)?;
        Ok(Self::with_id(generate_group_id(), name, creator))
    }

    /// Build a group with a known ID (used when joining by ID).
    pub fn with_id(id: String, name: &str, creator: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
            creator: creator.to_string(),
            members: HashSet::from([creator.to_string()]),
            created_at: unix_now(),
        }
    }

    /// Name shown in prompts and message prefixes; falls back to the ID when
    /// the group was joined without a name.
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.id
        } else {
            &self.name
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Random `NL-GRP-<16 hex chars>` identifier (8 random bytes, hex encoded).
pub fn generate_group_id() -> String {
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().gen();
    format!("NL-GRP-{}", hex::encode(bytes).to_uppercase())
}

/// Group names: 1-64 chars after trimming (letters, numbers, spaces,
/// hyphens, underscores).
pub fn validate_group_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Group name cannot be empty"));
    }
    if trimmed.len() > 64 {
        return Err(anyhow!("Group name too long (max 64 characters)"));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "Group name may only contain letters, numbers, spaces, hyphens and underscores"
        ));
    }
    Ok(())
}

/// Group IDs: `NL-GRP-` followed by exactly 16 hex characters.
pub fn validate_group_id(id: &str) -> Result<()> {
    let rest = id
        .strip_prefix("NL-GRP-")
        .ok_or_else(|| anyhow!("Invalid group ID format. Must start with 'NL-GRP-'"))?;
    if rest.len() != 16 || hex::decode(rest).map(|b| b.len()) != Ok(8) {
        return Err(anyhow!(
            "Invalid group ID format. Expected NL-GRP-<16 hex characters>"
        ));
    }
    Ok(())
}

// ============================ config operations ============================

/// Create a group owned by `creator` and store it in the config.
pub fn create(config: &mut Config, name: &str, creator: &str) -> Result<Group> {
    let group = Group::new(name, creator)?;
    config.groups.insert(group.id.clone(), group.clone());
    Ok(group)
}

/// Join a group by ID. If the group already exists locally this only (re-)
/// adds ourselves; otherwise a local entry is created — pass `name` when the
/// inviter told you the display name, it stays empty otherwise and messages
/// then show the raw group ID.
pub fn join(
    config: &mut Config,
    group_id: &str,
    name: Option<&str>,
    self_id: &str,
) -> Result<String> {
    validate_group_id(group_id)?;
    let display = match config.groups.get_mut(group_id) {
        Some(group) => {
            ensure_member_slot(group, self_id)?;
            group.members.insert(self_id.to_string());
            group.display_name().to_string()
        }
        None => {
            if let Some(n) = name {
                validate_group_name(n)?;
            }
            let group = Group::with_id(group_id.to_string(), name.unwrap_or(""), self_id);
            let display = group.display_name().to_string();
            config.groups.insert(group_id.to_string(), group);
            display
        }
    };
    Ok(display)
}

/// Leave a group. Returns `true` when this was the last member and the group
/// entry was removed entirely.
pub fn leave(config: &mut Config, group_id: &str, self_id: &str) -> Result<bool> {
    let group = config
        .groups
        .get_mut(group_id)
        .ok_or_else(|| anyhow!("Group {} not found", group_id))?;
    group.members.remove(self_id);
    let removed = group.members.is_empty();
    if removed {
        config.groups.remove(group_id);
    }
    Ok(removed)
}

/// Add a contact (by NL-ID) to a local group so the sender knows whom to fan
/// messages out to.
pub fn add_member(config: &mut Config, group_id: &str, member: &str) -> Result<()> {
    let group = config
        .groups
        .get_mut(group_id)
        .ok_or_else(|| anyhow!("Group {} not found", group_id))?;
    ensure_member_slot(group, member)?;
    if !group.members.insert(member.to_string()) {
        return Err(anyhow!(
            "{} is already a member of {}",
            member,
            group.display_name()
        ));
    }
    Ok(())
}

fn ensure_member_slot(group: &Group, member: &str) -> Result<()> {
    if !group.members.contains(member) && group.members.len() >= MAX_MEMBERS {
        return Err(anyhow!(
            "Group {} is full (max {} members)",
            group.display_name(),
            MAX_MEMBERS
        ));
    }
    Ok(())
}

// ============================ message framing ============================

/// Wrap a chat message for group delivery: `[GRP:<id>] <text>`.
pub fn frame_message(group_id: &str, text: &str) -> String {
    format!("[GRP:{}] {}", group_id, text)
}

/// Parse a group-framed message into `(group_id, content)`. Group IDs are
/// pure hex, so the first `]` reliably terminates the ID.
pub fn parse_frame(text: &str) -> Option<(String, &str)> {
    let rest = text.strip_prefix("[GRP:")?;
    let end = rest.find(']')?;
    let group_id = &rest[..end];
    if group_id.is_empty() {
        return None;
    }
    let content = rest[end + 1..].trim_start_matches(' ');
    Some((group_id.to_string(), content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SELF: &str = "NL-AAAA-BBBB-CCCC-DDDD";
    const PEER: &str = "NL-1111-2222-3333-4444";

    fn fresh_config() -> Config {
        Config {
            nl_id: SELF.to_string(),
            display_name: "tester".to_string(),
            private_key_encrypted: Vec::new(),
            public_key: Vec::new(),
            tor_address: None,
            contacts: HashMap::new(),
            theme: crate::theme::Theme::default(),
            groups: HashMap::new(),
        }
    }

    #[test]
    fn group_id_format_is_prefix_plus_16_hex() {
        let id = generate_group_id();
        assert!(id.starts_with("NL-GRP-"));
        let rest = &id["NL-GRP-".len()..];
        assert_eq!(rest.len(), 16);
        assert!(hex::decode(rest).is_ok());
        assert!(validate_group_id(&id).is_ok());
    }

    #[test]
    fn rejects_malformed_group_ids() {
        assert!(validate_group_id("NL-GRP-123").is_err());
        assert!(validate_group_id("NL-GRP-ZZZZAAAA12345678").is_err());
        assert!(validate_group_id("GRP-AAAA1234567890AB").is_err());
        assert!(validate_group_id("NL-GRP-AAAA1234567890ABX").is_err());
    }

    #[test]
    fn validates_group_names() {
        assert!(validate_group_name("My Group").is_ok());
        assert!(validate_group_name(&"g".repeat(64)).is_ok());
        assert!(validate_group_name("   ").is_err());
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name(&"g".repeat(65)).is_err());
        assert!(validate_group_name("bad!name").is_err());
    }

    #[test]
    fn create_adds_creator_as_first_member() {
        let mut config = fresh_config();
        let group = create(&mut config, "Test Group", SELF).unwrap();
        assert!(group.members.contains(SELF));
        assert_eq!(group.creator, SELF);
        assert!(config.groups.contains_key(&group.id));
    }

    #[test]
    fn join_existing_group_keeps_entry_and_adds_self() {
        let mut config = fresh_config();
        let group = create(&mut config, "Test Group", SELF).unwrap();
        let name_before = group.name.clone();
        join(&mut config, &group.id, Some("Other Name"), PEER).unwrap();
        let joined = config.groups.get(&group.id).unwrap();
        assert_eq!(joined.name, name_before, "joining must not rename the group");
        assert!(joined.members.contains(PEER));
    }

    #[test]
    fn join_unknown_group_creates_local_entry() {
        let mut config = fresh_config();
        let id = "NL-GRP-AAAA1234567890AB";
        join(&mut config, id, None, SELF).unwrap();
        let group = config.groups.get(id).unwrap();
        assert_eq!(group.display_name(), id, "unnamed groups fall back to the ID");
        assert!(group.members.contains(SELF));
    }

    #[test]
    fn leave_removes_group_when_last_member() {
        let mut config = fresh_config();
        let group = create(&mut config, "Solo", SELF).unwrap();
        let removed = leave(&mut config, &group.id, SELF).unwrap();
        assert!(removed, "last member leaving removes the group");
        assert!(!config.groups.contains_key(&group.id));
    }

    #[test]
    fn leave_keeps_group_while_members_remain() {
        let mut config = fresh_config();
        let group = create(&mut config, "Duo", SELF).unwrap();
        add_member(&mut config, &group.id, PEER).unwrap();
        let removed = leave(&mut config, &group.id, SELF).unwrap();
        assert!(!removed);
        assert!(config.groups.get(&group.id).unwrap().members.contains(PEER));
    }

    #[test]
    fn leave_unknown_group_errors() {
        let mut config = fresh_config();
        assert!(leave(&mut config, "NL-GRP-AAAA1234567890AB", SELF).is_err());
    }

    #[test]
    fn add_member_enforces_dupes_and_cap() {
        let mut config = fresh_config();
        let group = create(&mut config, "Cap", SELF).unwrap();
        assert!(add_member(&mut config, &group.id, PEER).is_ok());
        assert!(add_member(&mut config, &group.id, PEER).is_err(), "duplicate member");
        // Fill up to the cap.
        for i in 0..(MAX_MEMBERS - 2) {
            let id = format!("NL-FILL-{:04}", i);
            add_member(&mut config, &group.id, &id).unwrap();
        }
        assert_eq!(config.groups.get(&group.id).unwrap().members.len(), MAX_MEMBERS);
        assert!(add_member(&mut config, &group.id, "NL-OVER-9999").is_err(), "cap enforced");
        assert!(
            add_member(&mut config, "NL-GRP-AAAA1234567890AB", PEER).is_err(),
            "unknown group"
        );
    }

    #[test]
    fn frame_round_trip() {
        let id = "NL-GRP-AAAA1234567890AB";
        let framed = frame_message(id, "hello everyone, how are you?");
        let (gid, content) = parse_frame(&framed).unwrap();
        assert_eq!(gid, id);
        assert_eq!(content, "hello everyone, how are you?");
        // Content that itself looks like a group frame still round-trips.
        let nested = frame_message(id, "[GRP:XX] not really");
        let (gid2, content2) = parse_frame(&nested).unwrap();
        assert_eq!(gid2, id);
        assert_eq!(content2, "[GRP:XX] not really");
        assert!(parse_frame("not a group frame").is_none());
        assert!(parse_frame("[GRP:] empty id").is_none());
    }
}