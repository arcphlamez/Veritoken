#![no_std]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

#[cfg(test)]
mod test;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Env, String, Vec,
};

// ── Result / decision types ───────────────────────────────────────────────────

/// The reason a transfer was denied by the compliance engine.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DenyReason {
    CompliancePaused,
    FromBlocklisted,
    ToBlocklisted,
    FromKycMissing,
    ToKycMissing,
    FromKycExpired,
    ToKycExpired,
    FromKycRevoked,
    ToKycRevoked,
    FromKycRejected,
    ToKycRejected,
    FromKycPending,
    ToKycPending,
    FromJurisdictionBlocked,
    ToJurisdictionBlocked,
    SameJurisdictionRequired,
    AmountExceeded,
    HoldingPeriodNotMet,
    MaxHoldersReached,
    RecipientHoldingPeriodExceeded,
    TierPolicyBlocked,
    TierFromBelowMin,
    TierToBelowMin,
    TierAmountExceeded,
    RiskScoreTooHigh,
    FromNotAllowlisted,
    ToNotAllowlisted,
}

/// The outcome of a compliance transfer evaluation.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum TransferDecision {
    Allow,
    Deny(DenyReason),
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ComplianceError {
    AlreadyInitialized = 1,
    MinHoldingPeriodExceeds365Days = 2,
    NegativeMaxTransferAmount = 3,
    MaxHoldersBelowCurrentCount = 4,
    NoRulesPending = 5,
    TooEarlyToActivate = 6,
    InvalidRiskScore = 7,
    InvalidRiskConfig = 8,
    AlreadyAtSchemaVersion = 9,
    MigrationVersionNotSequential = 10,
    /// Returned when an address that is already on the blocklist is submitted
    /// for allowlist addition.  Storing a blocklisted address on the allowlist
    /// creates a contradictory enforcement state and is rejected eagerly.
    BlocklistedAddressOnAllowlist = 11,
    /// Returned when `set_tier_policy` receives a `TierPolicy` whose
    /// `max_transfer_amount` is negative.  A negative cap is nonsensical and
    /// would silently bypass the amount check inside `evaluate_transfer_inner`.
    NegativeTierTransferAmount = 12,
    /// Returned when `propose_rules` is called with an empty description
    /// string.  Every governance proposal must carry a human-readable reason
    /// so the policy audit trail remains meaningful.
    EmptyDescription = 13,
}

// ── Tier policy types ─────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct TierPolicyKey {
    pub from_tier: u32,
    pub to_tier: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct TierPolicy {
    pub blocked: bool,
    pub max_transfer_amount: i128,
    pub min_from_tier: u32,
    pub min_to_tier: u32,
}

// ── Risk scoring types ────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct RiskConfig {
    pub max_score: u32,
    pub default_score: u32,
}

// ── Compliance rules ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ComplianceRules {
    pub max_transfer_amount: i128,
    pub min_holding_period: u64,
    pub max_holders: u32,
    pub require_same_jurisdiction: bool,
    pub paused: bool,
    pub allowlist_mode: bool,
    pub max_holding_period: u64,
}

/// A point-in-time view of an address's holding-period ("lockup") status.
///
/// All `u64` timestamp/duration fields use `0` to mean "not applicable" —
/// mirroring the `ComplianceRules` convention where `0` means a rule is
/// disabled — so callers never have to unwrap an `Option`.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct LockupStatus {
    /// Whether the address is a currently registered holder (has a balance).
    pub is_holder: bool,
    /// Unix timestamp the address became a holder, or `0` if not a holder.
    pub holder_since: u64,
    /// The active `min_holding_period` rule, in seconds (`0` = disabled).
    pub min_holding_period: u64,
    /// The active `max_holding_period` rule, in seconds (`0` = disabled).
    pub max_holding_period: u64,
    /// Unix timestamp the address may transfer out, or `0` if not locked by a
    /// minimum holding period.
    pub min_release_at: u64,
    /// Unix timestamp by which the address must transfer out, or `0` if no
    /// maximum holding period applies.
    pub max_release_at: u64,
    /// `true` if the address is currently blocked from transferring out by
    /// `min_holding_period`.
    pub locked: bool,
    /// Seconds remaining until `min_release_at`, or `0` if not locked.
    pub seconds_until_unlock: u64,
}

// ── Versioned policy history types ───────────────────────────────────────────

/// The kind of state change that produced a policy version entry.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum PolicyChangeKind {
    ImmediateRuleUpdate,
    DelayedRuleActivation,
    Pause,
    Unpause,
    BlocklistAdd,
    BlocklistRemove,
    AllowlistAdd,
    AllowlistRemove,
}

/// An immutable, versioned snapshot of the compliance policy at one point in time.
///
/// Every call that changes the active ruleset or enforcement state writes one of
/// these records.  Replaying them in ascending `version` order deterministically
/// reconstructs every historical policy state.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyRecord {
    pub version: u32,
    pub activation_timestamp: u64,
    pub rules: ComplianceRules,
    pub change_kind: PolicyChangeKind,
    pub description: String,
}

/// On-chain record of a single admin-initiated schema migration.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ComplianceMigrationRecord {
    pub from_version: u32,
    pub to_version: u32,
    pub timestamp: u64,
    pub description: String,
}

/// A pending rules proposal: the proposed rules plus the earliest activation time.
#[contracttype]
#[derive(Clone)]
pub struct PendingRulesProposal {
    pub rules: ComplianceRules,
    pub activate_at: u64,
    pub description: String,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    PendingAdmin,
    KycRegistry,
    Rules,
    PendingProposal,
    RuleChangeDelay,
    // Legacy vec-based blocklist (instance storage, schema v1 only)
    Blocklist,
    BlocklistCount,
    // Per-entry persistent blocklist (schema v2+)
    BlocklistEntry(Address),
    BlocklistSize,
    BlocklistMember(u32),
    BlockedJurisdictions,
    HolderCount,
    HolderSince(Address),
    // Legacy vec-based allowlist (instance storage, schema v1 only)
    Allowlist,
    // Per-entry persistent allowlist (schema v2+)
    AllowlistEntry(Address),
    AllowlistSize,
    AllowlistMember(u32),
    TierPolicy(TierPolicyKey),
    TierPolicyCount,
    JurisdictionRisk(String),
    RiskConfig,
    PolicyVersionCount,
    PolicyVersion(u32),
    StorageVersion,
    MigrationCount,
    Migration(u32),
}

// 86400 s/day ÷ 5 s/ledger = 17280
const DAY_IN_LEDGERS: u32 = 17280;
const BUMP: u32 = 30 * DAY_IN_LEDGERS;
const THRESHOLD: u32 = BUMP - DAY_IN_LEDGERS;
const MAX_HOLDING_PERIOD_DAYS: u64 = 365;

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ComplianceEngine;

#[contractimpl]
impl ComplianceEngine {
    pub fn initialize(env: Env, admin: Address, kyc_registry: Address, rule_change_delay: u64) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(env, ComplianceError::AlreadyInitialized);
        }
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::KycRegistry, &kyc_registry);
        env.storage()
            .instance()
            .set(&DataKey::RuleChangeDelay, &rule_change_delay);
        let default_rules = ComplianceRules {
            max_transfer_amount: 0,
            min_holding_period: 0,
            max_holders: 0,
            require_same_jurisdiction: false,
            paused: false,
            allowlist_mode: false,
            max_holding_period: 0,
        };
        env.storage()
            .instance()
            .set(&DataKey::Rules, &default_rules);
        env.storage().instance().set(&DataKey::HolderCount, &0u32);
        env.storage()
            .instance()
            .set(&DataKey::PolicyVersionCount, &0u32);
        env.storage()
            .instance()
            .set(&DataKey::StorageVersion, &1u32);
        env.storage()
            .instance()
            .set(&DataKey::MigrationCount, &0u32);
        // Record version 0 — the initial policy.
        Self::append_policy_record(
            &env,
            default_rules,
            PolicyChangeKind::ImmediateRuleUpdate,
            String::from_str(&env, "initial"),
        );
    }

    pub fn propose_admin(env: Env, new_admin: Address) {
        Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        env.events()
            .publish((symbol_short!("proposed"),), new_admin);
    }

    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .expect("no pending admin");
        pending.require_auth();
        let old_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("admin must be set");
        env.storage().instance().set(&DataKey::Admin, &pending);
        env.storage().instance().remove(&DataKey::PendingAdmin);
        env.events()
            .publish((symbol_short!("admin_set"),), (old_admin, pending));
    }

    // ── Rule management ───────────────────────────────────────────────────────

    /// Propose new compliance rules with a time-lock delay.
    /// Rules do not take effect until `activate_rules` is called after
    /// `rule_change_delay` seconds have elapsed.
    pub fn propose_rules(env: Env, new_rules: ComplianceRules, description: String) {
        Self::require_admin(&env);
        // Every governance proposal must carry a non-empty description so that
        // the on-chain policy audit trail remains meaningful.  An empty string
        // would produce a `PolicyRecord` with no human-readable context, making
        // it impossible to understand why a rule change was made after the fact.
        if description.len() == 0 {
            panic_with_error!(env, ComplianceError::EmptyDescription);
        }
        Self::validate_rules(&env, &new_rules);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let delay: u64 = env
            .storage()
            .instance()
            .get(&DataKey::RuleChangeDelay)
            .unwrap_or(0);
        let activate_at = env.ledger().timestamp() + delay;
        let proposal = PendingRulesProposal {
            rules: new_rules,
            activate_at,
            description,
        };
        env.storage()
            .instance()
            .set(&DataKey::PendingProposal, &proposal);
        env.events()
            .publish((symbol_short!("rules_prp"),), activate_at);
    }

    /// Activate previously proposed rules after the time-lock has passed.
    /// Permissionless once the delay has elapsed.
    pub fn activate_rules(env: Env) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let proposal: PendingRulesProposal = env
            .storage()
            .instance()
            .get(&DataKey::PendingProposal)
            .unwrap_or_else(|| panic_with_error!(env, ComplianceError::NoRulesPending));
        let now = env.ledger().timestamp();
        if now < proposal.activate_at {
            panic_with_error!(env, ComplianceError::TooEarlyToActivate);
        }
        env.storage()
            .instance()
            .set(&DataKey::Rules, &proposal.rules);
        env.storage().instance().remove(&DataKey::PendingProposal);
        Self::append_policy_record(
            &env,
            proposal.rules,
            PolicyChangeKind::DelayedRuleActivation,
            proposal.description,
        );
        env.events().publish((symbol_short!("rules_act"),), ());
    }

    /// Emergency immediate rule update (bypasses the time-lock).  Admin-only.
    pub fn set_rules(env: Env, rules: ComplianceRules) {
        Self::require_admin(&env);
        Self::validate_rules(&env, &rules);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage().instance().set(&DataKey::Rules, &rules);
        Self::append_policy_record(
            &env,
            rules,
            PolicyChangeKind::ImmediateRuleUpdate,
            String::from_str(&env, ""),
        );
        env.events().publish((symbol_short!("rules_wrn"),), ());
        env.events().publish((symbol_short!("rules_set"),), ());
    }

    pub fn get_rules(env: Env) -> ComplianceRules {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::Rules)
            .expect("rules must be set")
    }

    pub fn get_pending_proposal(env: Env) -> Option<PendingRulesProposal> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage().instance().get(&DataKey::PendingProposal)
    }

    // ── Pause / unpause ───────────────────────────────────────────────────────

    pub fn pause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let mut rules: ComplianceRules = env
            .storage()
            .instance()
            .get(&DataKey::Rules)
            .expect("rules must be set");
        rules.paused = true;
        env.storage().instance().set(&DataKey::Rules, &rules);
        Self::append_policy_record(
            &env,
            rules,
            PolicyChangeKind::Pause,
            String::from_str(&env, ""),
        );
        env.events().publish((symbol_short!("paused"),), ());
    }

    pub fn unpause(env: Env) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let mut rules: ComplianceRules = env
            .storage()
            .instance()
            .get(&DataKey::Rules)
            .expect("rules must be set");
        rules.paused = false;
        env.storage().instance().set(&DataKey::Rules, &rules);
        Self::append_policy_record(
            &env,
            rules,
            PolicyChangeKind::Unpause,
            String::from_str(&env, ""),
        );
        env.events().publish((symbol_short!("unpaused"),), ());
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    pub fn add_to_blocklist(env: Env, addr: Address) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let entry_key = DataKey::BlocklistEntry(addr.clone());
        if !env.storage().persistent().has(&entry_key) {
            env.storage().persistent().set(&entry_key, &true);
            env.storage()
                .persistent()
                .extend_ttl(&entry_key, THRESHOLD, BUMP);
            let size: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::BlocklistSize)
                .unwrap_or(0);
            let member_key = DataKey::BlocklistMember(size);
            env.storage().persistent().set(&member_key, &addr);
            env.storage()
                .persistent()
                .extend_ttl(&member_key, THRESHOLD, BUMP);
            env.storage()
                .persistent()
                .set(&DataKey::BlocklistSize, &(size + 1));
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::BlocklistSize, THRESHOLD, BUMP);
            let rules: ComplianceRules = env
                .storage()
                .instance()
                .get(&DataKey::Rules)
                .expect("rules must be set");
            Self::append_policy_record(
                &env,
                rules,
                PolicyChangeKind::BlocklistAdd,
                String::from_str(&env, ""),
            );
        }
        env.events().publish((symbol_short!("blocked"),), addr);
    }

    pub fn remove_from_blocklist(env: Env, addr: Address) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let entry_key = DataKey::BlocklistEntry(addr.clone());
        if !env.storage().persistent().has(&entry_key) {
            return;
        }
        env.storage().persistent().remove(&entry_key);
        let size: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::BlocklistSize)
            .unwrap_or(0);
        // Scan member list to find position, then swap-with-last to compact.
        let mut pos = u32::MAX;
        for i in 0..size {
            let member: Address = env
                .storage()
                .persistent()
                .get(&DataKey::BlocklistMember(i))
                .expect("blocklist member at index must exist");
            if member == addr {
                pos = i;
                break;
            }
        }
        let new_size = size.saturating_sub(1);
        if pos <= new_size {
            if pos < new_size {
                let last: Address = env
                    .storage()
                    .persistent()
                    .get(&DataKey::BlocklistMember(new_size))
                    .expect("last blocklist member must exist");
                let slot = DataKey::BlocklistMember(pos);
                env.storage().persistent().set(&slot, &last);
                env.storage()
                    .persistent()
                    .extend_ttl(&slot, THRESHOLD, BUMP);
            }
            env.storage()
                .persistent()
                .remove(&DataKey::BlocklistMember(new_size));
            env.storage()
                .persistent()
                .set(&DataKey::BlocklistSize, &new_size);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::BlocklistSize, THRESHOLD, BUMP);
        }
        let rules: ComplianceRules = env
            .storage()
            .instance()
            .get(&DataKey::Rules)
            .expect("rules must be set");
        Self::append_policy_record(
            &env,
            rules,
            PolicyChangeKind::BlocklistRemove,
            String::from_str(&env, ""),
        );
    }

    pub fn is_blocklisted(env: Env, addr: Address) -> bool {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .persistent()
            .has(&DataKey::BlocklistEntry(addr))
    }

    pub fn blocklist_count(env: Env) -> u32 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .persistent()
            .get(&DataKey::BlocklistSize)
            .unwrap_or(0)
    }

    /// Returns paginated blocklist entries. `page` is 0-based; returns up to
    /// `page_size` addresses starting at index `page * page_size`.
    pub fn get_blocklist(env: Env, page: u32, page_size: u32) -> Vec<Address> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let size: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::BlocklistSize)
            .unwrap_or(0);
        let start = page * page_size;
        let end = (start + page_size).min(size);
        let mut result: Vec<Address> = Vec::new(&env);
        for i in start..end {
            if let Some(a) = env
                .storage()
                .persistent()
                .get::<DataKey, Address>(&DataKey::BlocklistMember(i))
            {
                result.push_back(a);
            }
        }
        result
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    pub fn add_to_allowlist(env: Env, addr: Address) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        // Reject the addition when the address is already on the blocklist.
        // Storing a blocklisted address on the allowlist would create a
        // contradictory enforcement state: the blocklist check in
        // `evaluate_transfer_inner` always wins, so the allowlist entry would
        // never have effect but would silently consume storage and mislead
        // auditors reading the policy history.
        if env
            .storage()
            .persistent()
            .has(&DataKey::BlocklistEntry(addr.clone()))
        {
            panic_with_error!(env, ComplianceError::BlocklistedAddressOnAllowlist);
        }
        let entry_key = DataKey::AllowlistEntry(addr.clone());
        if !env.storage().persistent().has(&entry_key) {
            env.storage().persistent().set(&entry_key, &true);
            env.storage()
                .persistent()
                .extend_ttl(&entry_key, THRESHOLD, BUMP);
            let size: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::AllowlistSize)
                .unwrap_or(0);
            let member_key = DataKey::AllowlistMember(size);
            env.storage().persistent().set(&member_key, &addr);
            env.storage()
                .persistent()
                .extend_ttl(&member_key, THRESHOLD, BUMP);
            env.storage()
                .persistent()
                .set(&DataKey::AllowlistSize, &(size + 1));
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::AllowlistSize, THRESHOLD, BUMP);
            let rules: ComplianceRules = env
                .storage()
                .instance()
                .get(&DataKey::Rules)
                .expect("rules must be set");
            Self::append_policy_record(
                &env,
                rules,
                PolicyChangeKind::AllowlistAdd,
                String::from_str(&env, ""),
            );
        }
        env.events().publish((symbol_short!("al_add"),), addr);
    }

    pub fn remove_from_allowlist(env: Env, addr: Address) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let entry_key = DataKey::AllowlistEntry(addr.clone());
        if !env.storage().persistent().has(&entry_key) {
            env.events().publish((symbol_short!("al_rem"),), addr);
            return;
        }
        env.storage().persistent().remove(&entry_key);
        let size: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::AllowlistSize)
            .unwrap_or(0);
        let mut pos = u32::MAX;
        for i in 0..size {
            let member: Address = env
                .storage()
                .persistent()
                .get(&DataKey::AllowlistMember(i))
                .expect("allowlist member at index must exist");
            if member == addr {
                pos = i;
                break;
            }
        }
        let new_size = size.saturating_sub(1);
        if pos <= new_size {
            if pos < new_size {
                let last: Address = env
                    .storage()
                    .persistent()
                    .get(&DataKey::AllowlistMember(new_size))
                    .expect("last allowlist member must exist");
                let slot = DataKey::AllowlistMember(pos);
                env.storage().persistent().set(&slot, &last);
                env.storage()
                    .persistent()
                    .extend_ttl(&slot, THRESHOLD, BUMP);
            }
            env.storage()
                .persistent()
                .remove(&DataKey::AllowlistMember(new_size));
            env.storage()
                .persistent()
                .set(&DataKey::AllowlistSize, &new_size);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::AllowlistSize, THRESHOLD, BUMP);
        }
        let rules: ComplianceRules = env
            .storage()
            .instance()
            .get(&DataKey::Rules)
            .expect("rules must be set");
        Self::append_policy_record(
            &env,
            rules,
            PolicyChangeKind::AllowlistRemove,
            String::from_str(&env, ""),
        );
        env.events().publish((symbol_short!("al_rem"),), addr);
    }

    pub fn is_allowlisted(env: Env, addr: Address) -> bool {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .persistent()
            .has(&DataKey::AllowlistEntry(addr))
    }

    pub fn allowlist_count(env: Env) -> u32 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .persistent()
            .get(&DataKey::AllowlistSize)
            .unwrap_or(0)
    }

    /// Returns paginated allowlist entries. `page` is 0-based; returns up to
    /// `page_size` addresses starting at index `page * page_size`.
    pub fn get_allowlist(env: Env, page: u32, page_size: u32) -> Vec<Address> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let size: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::AllowlistSize)
            .unwrap_or(0);
        let start = page * page_size;
        let end = (start + page_size).min(size);
        let mut result: Vec<Address> = Vec::new(&env);
        for i in start..end {
            if let Some(a) = env
                .storage()
                .persistent()
                .get::<DataKey, Address>(&DataKey::AllowlistMember(i))
            {
                result.push_back(a);
            }
        }
        result
    }

    // ── Jurisdiction blocklist ────────────────────────────────────────────────

    pub fn add_blocked_jurisdiction(env: Env, jurisdiction: String) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let mut list = Self::get_blocked_jurisdictions(env.clone());
        if !list.contains(&jurisdiction) {
            list.push_back(jurisdiction.clone());
        }
        env.storage()
            .instance()
            .set(&DataKey::BlockedJurisdictions, &list);
        env.events()
            .publish((symbol_short!("jur_add"),), jurisdiction);
    }

    pub fn remove_blocked_jurisdiction(env: Env, jurisdiction: String) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let list = Self::get_blocked_jurisdictions(env.clone());
        let mut new_list: Vec<String> = Vec::new(&env);
        for j in list.iter() {
            if j != jurisdiction {
                new_list.push_back(j);
            }
        }
        env.storage()
            .instance()
            .set(&DataKey::BlockedJurisdictions, &new_list);
        env.events()
            .publish((symbol_short!("jur_rem"),), jurisdiction);
    }

    pub fn get_blocked_jurisdictions(env: Env) -> Vec<String> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::BlockedJurisdictions)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Transfer validation ───────────────────────────────────────────────────

    /// Returns `true` when the compliance rules permit a transfer.
    /// Does NOT validate KYC state (backward-compatible).
    pub fn can_transfer(env: Env, from: Address, to: Address, amount: i128) -> bool {
        matches!(
            Self::evaluate_transfer_inner(&env, &from, &to, amount, false),
            TransferDecision::Allow
        )
    }

    /// Evaluates a transfer against KYC state and all compliance rules,
    /// returning the first failing rule as a `DenyReason`.
    pub fn evaluate_transfer(
        env: Env,
        from: Address,
        to: Address,
        amount: i128,
    ) -> TransferDecision {
        Self::evaluate_transfer_inner(&env, &from, &to, amount, true)
    }

    /// Deterministic evaluation core.
    ///
    /// Reads the active ruleset **once** as an immutable snapshot so every
    /// sub-check in a single call sees the same policy state.  This makes
    /// transfer evaluations replayable from the stored `PolicyRecord`.
    fn evaluate_transfer_inner(
        env: &Env,
        from: &Address,
        to: &Address,
        amount: i128,
        check_kyc: bool,
    ) -> TransferDecision {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let rules: ComplianceRules = env
            .storage()
            .instance()
            .get(&DataKey::Rules)
            .expect("rules must be set");

        if rules.paused {
            return TransferDecision::Deny(DenyReason::CompliancePaused);
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::BlocklistEntry(from.clone()))
        {
            return TransferDecision::Deny(DenyReason::FromBlocklisted);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::BlocklistEntry(to.clone()))
        {
            return TransferDecision::Deny(DenyReason::ToBlocklisted);
        }

        if rules.allowlist_mode {
            if !env
                .storage()
                .persistent()
                .has(&DataKey::AllowlistEntry(from.clone()))
            {
                return TransferDecision::Deny(DenyReason::FromNotAllowlisted);
            }
            if !env
                .storage()
                .persistent()
                .has(&DataKey::AllowlistEntry(to.clone()))
            {
                return TransferDecision::Deny(DenyReason::ToNotAllowlisted);
            }
        }

        if check_kyc {
            let kyc_addr: Address = env
                .storage()
                .instance()
                .get(&DataKey::KycRegistry)
                .expect("kyc registry must be set");
            let kyc = kyc_iface::KycRegistryClient::new(env, &kyc_addr);
            match kyc.get_kyc_state(from) {
                kyc_iface::KycState::Missing => {
                    return TransferDecision::Deny(DenyReason::FromKycMissing)
                }
                kyc_iface::KycState::Expired => {
                    return TransferDecision::Deny(DenyReason::FromKycExpired)
                }
                kyc_iface::KycState::Revoked => {
                    return TransferDecision::Deny(DenyReason::FromKycRevoked)
                }
                kyc_iface::KycState::Rejected => {
                    return TransferDecision::Deny(DenyReason::FromKycRejected)
                }
                kyc_iface::KycState::Pending => {
                    return TransferDecision::Deny(DenyReason::FromKycPending)
                }
                kyc_iface::KycState::Approved => {}
            }
            match kyc.get_kyc_state(to) {
                kyc_iface::KycState::Missing => {
                    return TransferDecision::Deny(DenyReason::ToKycMissing)
                }
                kyc_iface::KycState::Expired => {
                    return TransferDecision::Deny(DenyReason::ToKycExpired)
                }
                kyc_iface::KycState::Revoked => {
                    return TransferDecision::Deny(DenyReason::ToKycRevoked)
                }
                kyc_iface::KycState::Rejected => {
                    return TransferDecision::Deny(DenyReason::ToKycRejected)
                }
                kyc_iface::KycState::Pending => {
                    return TransferDecision::Deny(DenyReason::ToKycPending)
                }
                kyc_iface::KycState::Approved => {}
            }
        }

        let blocked_jurs = Self::get_blocked_jurisdictions(env.clone());
        if !blocked_jurs.is_empty() {
            let kyc_addr: Address = env
                .storage()
                .instance()
                .get(&DataKey::KycRegistry)
                .expect("kyc registry must be set");
            let kyc = kyc_iface::KycRegistryClient::new(env, &kyc_addr);
            match kyc.get_record_opt(from) {
                Some(r) if blocked_jurs.contains(&r.jurisdiction) => {
                    return TransferDecision::Deny(DenyReason::FromJurisdictionBlocked)
                }
                None => return TransferDecision::Deny(DenyReason::FromJurisdictionBlocked),
                _ => {}
            }
            match kyc.get_record_opt(to) {
                Some(r) if blocked_jurs.contains(&r.jurisdiction) => {
                    return TransferDecision::Deny(DenyReason::ToJurisdictionBlocked)
                }
                None => return TransferDecision::Deny(DenyReason::ToJurisdictionBlocked),
                _ => {}
            }
        }

        if rules.require_same_jurisdiction {
            let kyc_addr: Address = env
                .storage()
                .instance()
                .get(&DataKey::KycRegistry)
                .expect("kyc registry must be set");
            let kyc = kyc_iface::KycRegistryClient::new(env, &kyc_addr);
            match (kyc.get_record_opt(from), kyc.get_record_opt(to)) {
                (Some(fr), Some(tr)) if fr.jurisdiction != tr.jurisdiction => {
                    return TransferDecision::Deny(DenyReason::SameJurisdictionRequired)
                }
                (None, _) | (_, None) => {
                    return TransferDecision::Deny(DenyReason::SameJurisdictionRequired)
                }
                _ => {}
            }
        }

        if rules.max_transfer_amount > 0 && amount > rules.max_transfer_amount {
            return TransferDecision::Deny(DenyReason::AmountExceeded);
        }

        if rules.min_holding_period > 0 {
            if let Some(since) = env
                .storage()
                .persistent()
                .get::<DataKey, u64>(&DataKey::HolderSince(from.clone()))
            {
                if env.ledger().timestamp().saturating_sub(since) < rules.min_holding_period {
                    return TransferDecision::Deny(DenyReason::HoldingPeriodNotMet);
                }
            }
        }

        if rules.max_holding_period > 0 {
            if let Some(since) = env
                .storage()
                .persistent()
                .get::<DataKey, u64>(&DataKey::HolderSince(to.clone()))
            {
                if env.ledger().timestamp().saturating_sub(since) >= rules.max_holding_period {
                    return TransferDecision::Deny(DenyReason::RecipientHoldingPeriodExceeded);
                }
            }
        }

        if rules.max_holders > 0
            && !env
                .storage()
                .persistent()
                .has(&DataKey::HolderSince(to.clone()))
            && Self::holder_count(env.clone()) >= rules.max_holders
        {
            return TransferDecision::Deny(DenyReason::MaxHoldersReached);
        }

        let policy_count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::TierPolicyCount)
            .unwrap_or(0);
        if policy_count > 0 {
            let kyc_addr: Address = env
                .storage()
                .instance()
                .get(&DataKey::KycRegistry)
                .expect("kyc registry must be set");
            let kyc = kyc_iface::KycRegistryClient::new(env, &kyc_addr);
            let from_tier = kyc.get_tier(from);
            let to_tier = kyc.get_tier(to);
            let w: u32 = u32::MAX;
            let pol: Option<TierPolicy> = env
                .storage()
                .instance()
                .get(&DataKey::TierPolicy(TierPolicyKey { from_tier, to_tier }))
                .or_else(|| {
                    env.storage()
                        .instance()
                        .get(&DataKey::TierPolicy(TierPolicyKey {
                            from_tier: w,
                            to_tier,
                        }))
                })
                .or_else(|| {
                    env.storage()
                        .instance()
                        .get(&DataKey::TierPolicy(TierPolicyKey {
                            from_tier,
                            to_tier: w,
                        }))
                })
                .or_else(|| {
                    env.storage()
                        .instance()
                        .get(&DataKey::TierPolicy(TierPolicyKey {
                            from_tier: w,
                            to_tier: w,
                        }))
                });
            if let Some(p) = pol {
                if p.blocked {
                    return TransferDecision::Deny(DenyReason::TierPolicyBlocked);
                }
                if from_tier < p.min_from_tier {
                    return TransferDecision::Deny(DenyReason::TierFromBelowMin);
                }
                if to_tier < p.min_to_tier {
                    return TransferDecision::Deny(DenyReason::TierToBelowMin);
                }
                if p.max_transfer_amount > 0 {
                    let cap = if rules.max_transfer_amount > 0 {
                        p.max_transfer_amount.min(rules.max_transfer_amount)
                    } else {
                        p.max_transfer_amount
                    };
                    if amount > cap {
                        return TransferDecision::Deny(DenyReason::TierAmountExceeded);
                    }
                }
            }
        }

        if let Some(risk) = env
            .storage()
            .instance()
            .get::<DataKey, RiskConfig>(&DataKey::RiskConfig)
        {
            if risk.max_score > 0 {
                let kyc_addr: Address = env
                    .storage()
                    .instance()
                    .get(&DataKey::KycRegistry)
                    .expect("kyc registry must be set");
                let kyc = kyc_iface::KycRegistryClient::new(env, &kyc_addr);
                let fj = kyc
                    .get_record_opt(from)
                    .map(|r| r.jurisdiction)
                    .unwrap_or_else(|| String::from_str(env, ""));
                let tj = kyc
                    .get_record_opt(to)
                    .map(|r| r.jurisdiction)
                    .unwrap_or_else(|| String::from_str(env, ""));
                let fs: u32 = env
                    .storage()
                    .instance()
                    .get(&DataKey::JurisdictionRisk(fj))
                    .unwrap_or(risk.default_score);
                let ts: u32 = env
                    .storage()
                    .instance()
                    .get(&DataKey::JurisdictionRisk(tj))
                    .unwrap_or(risk.default_score);
                if fs > risk.max_score || ts > risk.max_score {
                    return TransferDecision::Deny(DenyReason::RiskScoreTooHigh);
                }
            }
        }

        TransferDecision::Allow
    }

    // ── Holder management ─────────────────────────────────────────────────────

    pub fn register_holder(env: Env, addr: Address) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let key = DataKey::HolderSince(addr.clone());
        let is_new = !env.storage().persistent().has(&key);
        env.storage()
            .persistent()
            .set(&key, &env.ledger().timestamp());
        env.storage().persistent().extend_ttl(&key, THRESHOLD, BUMP);
        if is_new {
            let c: u32 = env
                .storage()
                .instance()
                .get(&DataKey::HolderCount)
                .unwrap_or(0);
            env.storage()
                .instance()
                .set(&DataKey::HolderCount, &(c + 1));
        }
    }

    pub fn unregister_holder(env: Env, addr: Address) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let key = DataKey::HolderSince(addr.clone());
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
            let c: u32 = env
                .storage()
                .instance()
                .get(&DataKey::HolderCount)
                .unwrap_or(0);
            env.storage()
                .instance()
                .set(&DataKey::HolderCount, &c.saturating_sub(1));
        }
    }

    pub fn holder_count(env: Env) -> u32 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::HolderCount)
            .unwrap_or(0)
    }

    /// Read the holding-period ("lockup") status for `addr`: whether it is
    /// currently locked by `min_holding_period`, when it unlocks, and (if
    /// `max_holding_period` is set) the deadline by which it must transfer
    /// out. See [`LockupStatus`] for field semantics.
    pub fn lockup_status(env: Env, addr: Address) -> LockupStatus {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let key = DataKey::HolderSince(addr);
        let is_holder = env.storage().persistent().has(&key);
        let since: u64 = if is_holder {
            env.storage().persistent().get(&key).unwrap_or(0)
        } else {
            0
        };
        let rules: ComplianceRules = env
            .storage()
            .instance()
            .get(&DataKey::Rules)
            .expect("rules must be set");
        let now = env.ledger().timestamp();

        let min_release_at = if is_holder && rules.min_holding_period > 0 {
            since.saturating_add(rules.min_holding_period)
        } else {
            0
        };
        let max_release_at = if is_holder && rules.max_holding_period > 0 {
            since.saturating_add(rules.max_holding_period)
        } else {
            0
        };
        let locked = min_release_at > 0 && now < min_release_at;
        let seconds_until_unlock = if locked { min_release_at - now } else { 0 };

        LockupStatus {
            is_holder,
            holder_since: since,
            min_holding_period: rules.min_holding_period,
            max_holding_period: rules.max_holding_period,
            min_release_at,
            max_release_at,
            locked,
            seconds_until_unlock,
        }
    }

    // ── Policy history query surface ──────────────────────────────────────────

    /// Total number of policy versions recorded (indices are 0-based).
    pub fn policy_version_count(env: Env) -> u32 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::PolicyVersionCount)
            .unwrap_or(0)
    }

    /// The `PolicyRecord` at 0-based `index`.  Panics if out of range.
    pub fn get_policy_version(env: Env, index: u32) -> PolicyRecord {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::PolicyVersion(index))
            .expect("policy version not found")
    }

    /// The most-recently written `PolicyRecord` (currently active version).
    pub fn get_current_policy_version(env: Env) -> PolicyRecord {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::PolicyVersionCount)
            .unwrap_or(0);
        env.storage()
            .instance()
            .get(&DataKey::PolicyVersion(count.saturating_sub(1)))
            .expect("no policy versions recorded")
    }

    /// Paged policy history. `start` is 0-based; `limit` is capped at 20.
    pub fn get_policy_history(env: Env, start: u32, limit: u32) -> Vec<PolicyRecord> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::PolicyVersionCount)
            .unwrap_or(0);
        let cap = if limit > 20 { 20 } else { limit };
        let end = (start + cap).min(count);
        let mut out: Vec<PolicyRecord> = Vec::new(&env);
        for i in start..end {
            if let Some(r) = env
                .storage()
                .instance()
                .get::<DataKey, PolicyRecord>(&DataKey::PolicyVersion(i))
            {
                out.push_back(r);
            }
        }
        out
    }

    // ── Tier-based policy ─────────────────────────────────────────────────────

    pub fn set_tier_policy(env: Env, from_tier: u32, to_tier: u32, policy: TierPolicy) {
        Self::require_admin(&env);
        // A negative max_transfer_amount is nonsensical: the amount check in
        // `evaluate_transfer_inner` uses `> 0` as the "enabled" sentinel, so a
        // negative value would be stored silently but never trigger a denial,
        // effectively disabling the cap in a misleading way.
        if policy.max_transfer_amount < 0 {
            panic_with_error!(env, ComplianceError::NegativeTierTransferAmount);
        }
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let key = DataKey::TierPolicy(TierPolicyKey { from_tier, to_tier });
        let is_new = !env.storage().instance().has(&key);
        env.storage().instance().set(&key, &policy);
        if is_new {
            let c: u32 = env
                .storage()
                .instance()
                .get(&DataKey::TierPolicyCount)
                .unwrap_or(0);
            env.storage()
                .instance()
                .set(&DataKey::TierPolicyCount, &(c + 1));
        }
        env.events()
            .publish((symbol_short!("tier_pol"),), (from_tier, to_tier));
    }

    pub fn get_tier_policy(env: Env, from_tier: u32, to_tier: u32) -> Option<TierPolicy> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::TierPolicy(TierPolicyKey { from_tier, to_tier }))
    }

    pub fn clear_tier_policy(env: Env, from_tier: u32, to_tier: u32) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        let key = DataKey::TierPolicy(TierPolicyKey { from_tier, to_tier });
        if env.storage().instance().has(&key) {
            env.storage().instance().remove(&key);
            let c: u32 = env
                .storage()
                .instance()
                .get(&DataKey::TierPolicyCount)
                .unwrap_or(0);
            env.storage()
                .instance()
                .set(&DataKey::TierPolicyCount, &c.saturating_sub(1));
        }
        env.events()
            .publish((symbol_short!("tier_clr"),), (from_tier, to_tier));
    }

    pub fn tier_policy_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::TierPolicyCount)
            .unwrap_or(0)
    }

    // ── Jurisdiction risk scoring ─────────────────────────────────────────────

    pub fn set_risk_config(env: Env, config: RiskConfig) {
        Self::require_admin(&env);
        if config.max_score > 100 {
            panic_with_error!(env, ComplianceError::InvalidRiskConfig);
        }
        if config.default_score > 100 {
            panic_with_error!(env, ComplianceError::InvalidRiskConfig);
        }
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage().instance().set(&DataKey::RiskConfig, &config);
        env.events().publish(
            (symbol_short!("risk_cfg"),),
            (config.max_score, config.default_score),
        );
    }

    pub fn get_risk_config(env: Env) -> Option<RiskConfig> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage().instance().get(&DataKey::RiskConfig)
    }

    pub fn set_jurisdiction_risk_score(env: Env, jurisdiction: String, score: u32) {
        Self::require_admin(&env);
        if score > 100 {
            panic_with_error!(env, ComplianceError::InvalidRiskScore);
        }
        if jurisdiction.len() != 2 {
            panic_with_error!(env, ComplianceError::InvalidRiskScore);
        }
        let mut b = [0u8; 2];
        jurisdiction.copy_into_slice(&mut b);
        if b[0] < b'A' || b[0] > b'Z' || b[1] < b'A' || b[1] > b'Z' {
            panic_with_error!(env, ComplianceError::InvalidRiskScore);
        }
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .set(&DataKey::JurisdictionRisk(jurisdiction.clone()), &score);
        env.events()
            .publish((symbol_short!("risk_jur"),), (jurisdiction, score));
    }

    pub fn get_jurisdiction_risk_score(env: Env, jurisdiction: String) -> Option<u32> {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::JurisdictionRisk(jurisdiction))
    }

    pub fn clear_jurisdiction_risk_score(env: Env, jurisdiction: String) {
        Self::require_admin(&env);
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .remove(&DataKey::JurisdictionRisk(jurisdiction.clone()));
        env.events()
            .publish((symbol_short!("risk_clr"),), jurisdiction);
    }

    pub fn evaluate_transfer_risk(env: Env, from_j: String, to_j: String) -> (u32, u32, bool) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        match env
            .storage()
            .instance()
            .get::<DataKey, RiskConfig>(&DataKey::RiskConfig)
        {
            None => (0, 0, false),
            Some(c) if c.max_score == 0 => (0, 0, false),
            Some(c) => {
                let fs: u32 = env
                    .storage()
                    .instance()
                    .get(&DataKey::JurisdictionRisk(from_j))
                    .unwrap_or(c.default_score);
                let ts: u32 = env
                    .storage()
                    .instance()
                    .get(&DataKey::JurisdictionRisk(to_j))
                    .unwrap_or(c.default_score);
                (fs, ts, fs > c.max_score || ts > c.max_score)
            }
        }
    }

    pub fn version(env: Env) -> String {
        String::from_str(&env, env!("CARGO_PKG_VERSION"))
    }

    // ── Storage versioning / migration ────────────────────────────────────────

    pub fn schema_version(env: Env) -> u32 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::StorageVersion)
            .unwrap_or(0)
    }

    pub fn migration_count(env: Env) -> u32 {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::MigrationCount)
            .unwrap_or(0)
    }

    pub fn get_migration_record(env: Env, index: u32) -> ComplianceMigrationRecord {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        env.storage()
            .instance()
            .get(&DataKey::Migration(index))
            .expect("migration record not found")
    }

    pub fn migrate_schema(env: Env, to_version: u32, description: String) {
        env.storage().instance().extend_ttl(THRESHOLD, BUMP);
        Self::require_admin(&env);
        let current: u32 = env
            .storage()
            .instance()
            .get(&DataKey::StorageVersion)
            .unwrap_or(0);
        if to_version == current {
            panic_with_error!(env, ComplianceError::AlreadyAtSchemaVersion);
        }
        if to_version != current + 1 {
            panic_with_error!(env, ComplianceError::MigrationVersionNotSequential);
        }
        if to_version == 2 {
            Self::apply_v2_migration(&env);
        }
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::MigrationCount)
            .unwrap_or(0);
        let rec = ComplianceMigrationRecord {
            from_version: current,
            to_version,
            timestamp: env.ledger().timestamp(),
            description,
        };
        env.storage()
            .instance()
            .set(&DataKey::Migration(count), &rec);
        env.storage()
            .instance()
            .set(&DataKey::MigrationCount, &(count + 1));
        env.storage()
            .instance()
            .set(&DataKey::StorageVersion, &to_version);
        env.events()
            .publish((symbol_short!("migrated"),), (current, to_version));
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("admin must be set");
        admin.require_auth();
    }

    fn validate_rules(env: &Env, rules: &ComplianceRules) {
        if rules.min_holding_period > MAX_HOLDING_PERIOD_DAYS * 86_400 {
            panic_with_error!(env, ComplianceError::MinHoldingPeriodExceeds365Days);
        }
        if rules.max_transfer_amount < 0 {
            panic_with_error!(env, ComplianceError::NegativeMaxTransferAmount);
        }
        if rules.max_holders > 0 {
            let count: u32 = env
                .storage()
                .instance()
                .get(&DataKey::HolderCount)
                .unwrap_or(0);
            // Reject any cap that would be immediately violated by the live
            // holder count.  The boundary condition `max_holders == count` is
            // intentionally allowed: it prevents *new* holders from joining
            // while leaving existing holders unaffected.  Only strictly less
            // than is an impossible state.
            if rules.max_holders < count {
                panic_with_error!(env, ComplianceError::MaxHoldersBelowCurrentCount);
            }
        }
    }

    /// Schema v1 → v2: migrate blocklist and allowlist from instance Vec storage
    /// to per-entry persistent storage.  Safe to call when no old Vec data
    /// exists (reads an absent key as empty) and idempotent per-address (skips
    /// entries already present in persistent storage).
    fn apply_v2_migration(env: &Env) {
        if let Some(old_list) = env
            .storage()
            .instance()
            .get::<DataKey, Vec<Address>>(&DataKey::Blocklist)
        {
            let mut size: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::BlocklistSize)
                .unwrap_or(0);
            for addr in old_list.iter() {
                let entry_key = DataKey::BlocklistEntry(addr.clone());
                if !env.storage().persistent().has(&entry_key) {
                    env.storage().persistent().set(&entry_key, &true);
                    env.storage()
                        .persistent()
                        .extend_ttl(&entry_key, THRESHOLD, BUMP);
                    let member_key = DataKey::BlocklistMember(size);
                    env.storage().persistent().set(&member_key, &addr);
                    env.storage()
                        .persistent()
                        .extend_ttl(&member_key, THRESHOLD, BUMP);
                    size += 1;
                }
            }
            env.storage()
                .persistent()
                .set(&DataKey::BlocklistSize, &size);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::BlocklistSize, THRESHOLD, BUMP);
            env.storage().instance().remove(&DataKey::Blocklist);
        }

        if let Some(old_list) = env
            .storage()
            .instance()
            .get::<DataKey, Vec<Address>>(&DataKey::Allowlist)
        {
            let mut size: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::AllowlistSize)
                .unwrap_or(0);
            for addr in old_list.iter() {
                let entry_key = DataKey::AllowlistEntry(addr.clone());
                if !env.storage().persistent().has(&entry_key) {
                    env.storage().persistent().set(&entry_key, &true);
                    env.storage()
                        .persistent()
                        .extend_ttl(&entry_key, THRESHOLD, BUMP);
                    let member_key = DataKey::AllowlistMember(size);
                    env.storage().persistent().set(&member_key, &addr);
                    env.storage()
                        .persistent()
                        .extend_ttl(&member_key, THRESHOLD, BUMP);
                    size += 1;
                }
            }
            env.storage()
                .persistent()
                .set(&DataKey::AllowlistSize, &size);
            env.storage()
                .persistent()
                .extend_ttl(&DataKey::AllowlistSize, THRESHOLD, BUMP);
            env.storage().instance().remove(&DataKey::Allowlist);
        }
    }

    /// Single write path for policy history.  Every ruleset mutation calls this.
    fn append_policy_record(
        env: &Env,
        rules: ComplianceRules,
        change_kind: PolicyChangeKind,
        description: String,
    ) {
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::PolicyVersionCount)
            .unwrap_or(0);
        let rec = PolicyRecord {
            version: count,
            activation_timestamp: env.ledger().timestamp(),
            rules,
            change_kind,
            description,
        };
        env.storage()
            .instance()
            .set(&DataKey::PolicyVersion(count), &rec);
        env.storage()
            .instance()
            .set(&DataKey::PolicyVersionCount, &(count + 1));
    }
}

// ── KYC registry cross-contract interface ────────────────────────────────────

mod kyc_iface {
    use soroban_sdk::{contractclient, contracttype, Address, String};

    #[contracttype]
    #[derive(Clone, Debug, PartialEq)]
    pub enum KycState {
        Missing,
        Approved,
        Expired,
        Revoked,
        Rejected,
        Pending,
    }

    #[contracttype]
    #[derive(Clone)]
    pub struct KycRecord {
        pub status: KycStatus,
        pub verifier: Address,
        pub tier: u32,
        pub expiry: u64,
        pub jurisdiction: String,
    }

    #[contracttype]
    #[derive(Clone)]
    pub enum KycStatus {
        Pending,
        Approved,
        Rejected,
        Revoked,
    }

    #[contractclient(name = "KycRegistryClient")]
    #[allow(dead_code)]
    pub trait KycRegistry {
        fn get_kyc_state(env: soroban_sdk::Env, addr: Address) -> KycState;
        fn get_record_opt(env: soroban_sdk::Env, addr: Address) -> Option<KycRecord>;
        fn get_tier(env: soroban_sdk::Env, addr: Address) -> u32;
    }
}
