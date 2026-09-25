#![cfg(test)]

use crate::{
    ComplianceEngine, ComplianceEngineClient, ComplianceError, ComplianceRules, PolicyChangeKind,
    TierPolicy,
};
use kyc_registry::{KycRegistry, KycRegistryClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env, Error, String,
};

// ── Shared setup helpers ──────────────────────────────────────────────────────

fn setup() -> (Env, ComplianceEngineClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = env.register(KycRegistry, ());
    KycRegistryClient::new(&env, &kyc_id).initialize(&admin);
    let ce_id = env.register(ComplianceEngine, ());
    let ce = ComplianceEngineClient::new(&env, &ce_id);
    ce.initialize(&admin, &kyc_id, &0u64);
    (env, ce, admin)
}

fn setup_with_kyc() -> (
    Env,
    ComplianceEngineClient<'static>,
    KycRegistryClient<'static>,
    Address, // verifier
    Address, // admin
) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = env.register(KycRegistry, ());
    let kyc = KycRegistryClient::new(&env, &kyc_id);
    kyc.initialize(&admin);
    let verifier = Address::generate(&env);
    kyc.add_verifier(&admin, &verifier);
    let ce_id = env.register(ComplianceEngine, ());
    let ce = ComplianceEngineClient::new(&env, &ce_id);
    ce.initialize(&admin, &kyc_id, &0u64);
    (env, ce, kyc, verifier, admin)
}

fn rules(max: i128, min_hold: u64, max_hold_cnt: u32, paused: bool) -> ComplianceRules {
    ComplianceRules {
        max_transfer_amount: max,
        min_holding_period: min_hold,
        max_holders: max_hold_cnt,
        require_same_jurisdiction: false,
        paused,
        allowlist_mode: false,
        max_holding_period: 0,
    }
}

// ── Basic transfer / pause / blocklist (preserved from original suite) ─────────

#[test]
fn test_default_rules_allow_transfer() {
    let (env, ce, _) = setup();
    assert!(ce.can_transfer(&Address::generate(&env), &Address::generate(&env), &1_000));
}

#[test]
fn test_pause_blocks_all_transfers() {
    let (env, ce, _) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    ce.pause();
    assert!(!ce.can_transfer(&from, &to, &1));
    ce.unpause();
    assert!(ce.can_transfer(&from, &to, &1));
}

#[test]
fn test_blocklist() {
    let (env, ce, _) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    assert!(!ce.is_blocklisted(&from));
    ce.add_to_blocklist(&from);
    assert!(ce.is_blocklisted(&from));
    assert!(!ce.can_transfer(&from, &to, &1));
    assert!(!ce.can_transfer(&to, &from, &1));
    ce.remove_from_blocklist(&from);
    assert!(!ce.is_blocklisted(&from));
    assert!(ce.can_transfer(&from, &to, &1));
}

#[test]
fn test_max_transfer_amount() {
    let (env, ce, _) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    ce.set_rules(&rules(100, 0, 0, false));
    assert!(ce.can_transfer(&from, &to, &100));
    assert!(!ce.can_transfer(&from, &to, &101));
}

#[test]
fn test_min_holding_period() {
    let (env, ce, _) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    ce.set_rules(&rules(0, 1_000, 0, false));
    env.ledger().set_timestamp(5_000);
    ce.register_holder(&from);
    env.ledger().set_timestamp(5_500);
    assert!(!ce.can_transfer(&from, &to, &1));
    env.ledger().set_timestamp(6_001);
    assert!(ce.can_transfer(&from, &to, &1));
}

#[test]
fn test_max_holders_blocks_new_but_allows_existing() {
    let (env, ce, _) = setup();
    let h1 = Address::generate(&env);
    let h2 = Address::generate(&env);
    let new = Address::generate(&env);
    ce.set_rules(&rules(0, 0, 2, false));
    ce.register_holder(&h1);
    ce.register_holder(&h2);
    assert!(!ce.can_transfer(&h1, &new, &1));
    assert!(ce.can_transfer(&h1, &h2, &1));
}

// ── Validation errors ─────────────────────────────────────────────────────────

#[test]
fn test_set_rules_rejects_min_holding_exceeds_365_days() {
    let (_, ce, _) = setup();
    assert_eq!(
        ce.try_set_rules(&rules(0, 31_536_001, 0, false)),
        Err(Ok(Error::from(
            ComplianceError::MinHoldingPeriodExceeds365Days
        )))
    );
}

#[test]
fn test_propose_rules_max_holding_period() {
    let (env, ce, _) = setup();
    ce.propose_rules(
        &rules(0, 365 * 86_400, 0, false),
        &String::from_str(&env, "365-day holding period"),
    );
}

#[test]
fn test_propose_rules_rejects_holding_period_over_365_days() {
    let (env, ce, _) = setup();
    assert_eq!(
        ce.try_propose_rules(
            &rules(0, 366 * 86_400, 0, false),
            &String::from_str(&env, "366-day holding period"),
        ),
        Err(Ok(Error::from(
            ComplianceError::MinHoldingPeriodExceeds365Days
        )))
    );
}

#[test]
fn test_set_rules_rejects_negative_max_transfer() {
    let (_, ce, _) = setup();
    assert_eq!(
        ce.try_set_rules(&rules(-1, 0, 0, false)),
        Err(Ok(Error::from(ComplianceError::NegativeMaxTransferAmount)))
    );
}

#[test]
fn test_set_rules_rejects_max_holders_below_current_count() {
    let (env, ce, _) = setup();
    ce.register_holder(&Address::generate(&env));
    ce.register_holder(&Address::generate(&env));
    assert_eq!(
        ce.try_set_rules(&rules(0, 0, 1, false)),
        Err(Ok(Error::from(
            ComplianceError::MaxHoldersBelowCurrentCount
        )))
    );
}

// ── Delayed rule activation ───────────────────────────────────────────────────

#[test]
fn test_propose_then_activate_after_delay() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = env.register(KycRegistry, ());
    KycRegistryClient::new(&env, &kyc_id).initialize(&admin);
    let ce_id = env.register(ComplianceEngine, ());
    let ce = ComplianceEngineClient::new(&env, &ce_id);
    // 100-second delay
    ce.initialize(&admin, &kyc_id, &100u64);

    env.ledger().set_timestamp(1_000);
    let proposed = ComplianceRules {
        max_transfer_amount: 500,
        min_holding_period: 0,
        max_holders: 0,
        require_same_jurisdiction: false,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    };
    ce.propose_rules(&proposed, &String::from_str(&env, "cap 500"));

    // Before delay: activation must fail.
    env.ledger().set_timestamp(1_050);
    assert_eq!(
        ce.try_activate_rules(),
        Err(Ok(Error::from(ComplianceError::TooEarlyToActivate)))
    );

    // After delay: activation must succeed.
    env.ledger().set_timestamp(1_100);
    ce.activate_rules();

    let r = ce.get_rules();
    assert_eq!(r.max_transfer_amount, 500);
}

#[test]
fn test_activate_rules_fails_when_no_proposal_pending() {
    let (_, ce, _) = setup();
    assert_eq!(
        ce.try_activate_rules(),
        Err(Ok(Error::from(ComplianceError::NoRulesPending)))
    );
}

#[test]
fn test_propose_zero_delay_activates_immediately() {
    let (env, ce, _) = setup(); // delay=0 by default in setup()
    let r = ComplianceRules {
        max_transfer_amount: 999,
        min_holding_period: 0,
        max_holders: 0,
        require_same_jurisdiction: false,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    };
    ce.propose_rules(&r, &String::from_str(&env, "imm"));
    ce.activate_rules(); // should not fail
    assert_eq!(ce.get_rules().max_transfer_amount, 999);
}

#[test]
fn test_get_pending_proposal_returns_some_after_propose() {
    let (env, ce, _) = setup();
    assert!(ce.get_pending_proposal().is_none());
    ce.propose_rules(&rules(0, 0, 0, false), &String::from_str(&env, "p"));
    let p = ce
        .get_pending_proposal()
        .expect("should have pending proposal");
    assert_eq!(p.description, String::from_str(&env, "p"));
}

#[test]
fn test_get_pending_proposal_cleared_after_activate() {
    let (env, ce, _) = setup();
    ce.propose_rules(&rules(0, 0, 0, false), &String::from_str(&env, "x"));
    ce.activate_rules();
    assert!(ce.get_pending_proposal().is_none());
}

// ── Policy version / history ──────────────────────────────────────────────────

#[test]
fn test_initialize_creates_version_zero() {
    let (_, ce, _) = setup();
    assert_eq!(ce.policy_version_count(), 1);
    let v = ce.get_policy_version(&0);
    assert_eq!(v.version, 0);
    assert_eq!(v.change_kind, PolicyChangeKind::ImmediateRuleUpdate);
    assert!(!v.rules.paused);
}

#[test]
fn test_set_rules_increments_policy_version() {
    let (_, ce, _) = setup();
    ce.set_rules(&rules(100, 0, 0, false));
    assert_eq!(ce.policy_version_count(), 2);
    let v = ce.get_policy_version(&1);
    assert_eq!(v.change_kind, PolicyChangeKind::ImmediateRuleUpdate);
    assert_eq!(v.rules.max_transfer_amount, 100);
}

#[test]
fn test_delayed_activation_creates_delayed_version_kind() {
    let (env, ce, _) = setup();
    ce.propose_rules(&rules(777, 0, 0, false), &String::from_str(&env, "desc"));
    ce.activate_rules();
    let v = ce.get_current_policy_version();
    assert_eq!(v.change_kind, PolicyChangeKind::DelayedRuleActivation);
    assert_eq!(v.rules.max_transfer_amount, 777);
    assert_eq!(v.description, String::from_str(&env, "desc"));
}

#[test]
fn test_pause_creates_pause_version() {
    let (_, ce, _) = setup();
    ce.pause();
    let v = ce.get_current_policy_version();
    assert_eq!(v.change_kind, PolicyChangeKind::Pause);
    assert!(v.rules.paused);
}

#[test]
fn test_unpause_creates_unpause_version() {
    let (_, ce, _) = setup();
    ce.pause();
    ce.unpause();
    let v = ce.get_current_policy_version();
    assert_eq!(v.change_kind, PolicyChangeKind::Unpause);
    assert!(!v.rules.paused);
}

#[test]
fn test_blocklist_add_creates_blocklist_add_version() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    ce.add_to_blocklist(&addr);
    let v = ce.get_current_policy_version();
    assert_eq!(v.change_kind, PolicyChangeKind::BlocklistAdd);
}

#[test]
fn test_blocklist_remove_creates_blocklist_remove_version() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    ce.add_to_blocklist(&addr);
    let before = ce.policy_version_count();
    ce.remove_from_blocklist(&addr);
    assert_eq!(ce.policy_version_count(), before + 1);
    assert_eq!(
        ce.get_current_policy_version().change_kind,
        PolicyChangeKind::BlocklistRemove
    );
}

#[test]
fn test_duplicate_blocklist_add_does_not_create_version() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    ce.add_to_blocklist(&addr);
    let count = ce.policy_version_count();
    ce.add_to_blocklist(&addr); // already in list — no new version
    assert_eq!(ce.policy_version_count(), count);
}

#[test]
fn test_allowlist_add_creates_allowlist_add_version() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    ce.add_to_allowlist(&addr);
    assert_eq!(
        ce.get_current_policy_version().change_kind,
        PolicyChangeKind::AllowlistAdd
    );
}

#[test]
fn test_policy_history_pagination() {
    let (_, ce, _) = setup();
    // init(1) + pause(1) + unpause(1) = 3 versions
    ce.pause();
    ce.unpause();
    let all = ce.get_policy_history(&0, &20);
    assert_eq!(all.len(), 3);
    let page1 = ce.get_policy_history(&0, &2);
    assert_eq!(page1.len(), 2);
    let page2 = ce.get_policy_history(&2, &2);
    assert_eq!(page2.len(), 1);
    let empty = ce.get_policy_history(&100, &10);
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_policy_history_limit_capped_at_20() {
    let (_, ce, _) = setup();
    let page = ce.get_policy_history(&0, &999);
    assert!(page.len() <= 20);
}

#[test]
fn test_policy_version_ordering_is_ascending() {
    let (_, ce, _) = setup();
    ce.pause();
    ce.unpause();
    let history = ce.get_policy_history(&0, &20);
    for i in 0..history.len() {
        assert_eq!(history.get(i).unwrap().version, i);
    }
}

#[test]
fn test_get_current_policy_version_matches_latest() {
    let (_, ce, _) = setup();
    ce.pause();
    ce.unpause();
    let count = ce.policy_version_count();
    let current = ce.get_current_policy_version();
    let last = ce.get_policy_version(&(count - 1));
    assert_eq!(current, last);
}

#[test]
fn test_policy_record_snapshot_matches_active_rules() {
    let (_, ce, _) = setup();
    ce.set_rules(&rules(1234, 0, 0, false));
    let snap = ce.get_current_policy_version();
    let live = ce.get_rules();
    assert_eq!(snap.rules.max_transfer_amount, live.max_transfer_amount);
    assert_eq!(snap.rules.paused, live.paused);
}

#[test]
fn test_activation_timestamp_recorded_correctly() {
    let (env, ce, _) = setup();
    env.ledger().set_timestamp(42_000);
    ce.set_rules(&rules(0, 0, 0, false));
    let v = ce.get_current_policy_version();
    assert_eq!(v.activation_timestamp, 42_000);
}

// ── State transition hardening ────────────────────────────────────────────────

#[test]
fn test_pause_then_set_rules_keeps_pause_flag() {
    let (_, ce, _) = setup();
    ce.pause();
    // Updating rules while paused — the new ruleset should still be paused.
    let mut r = rules(500, 0, 0, false);
    r.paused = true; // mirror current state so validate_rules passes
    ce.set_rules(&r);
    assert!(ce.get_rules().paused);
}

#[test]
fn test_unpause_then_blocklist_change_preserved() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    ce.pause();
    ce.unpause();
    ce.add_to_blocklist(&addr);
    assert!(!ce.can_transfer(&addr, &to, &1));
    assert!(ce.can_transfer(&from, &to, &1));
}

#[test]
fn test_blocklist_then_pause_then_blocklist_remove() {
    let (env, ce, _) = setup();
    let blocked = Address::generate(&env);
    let other = Address::generate(&env);
    ce.add_to_blocklist(&blocked);
    ce.pause();
    // While paused, ALL transfers are blocked (pause takes precedence over blocklist).
    assert!(!ce.can_transfer(&other, &blocked, &1));
    ce.unpause();
    // After unpause, blocklist is still in effect.
    assert!(!ce.can_transfer(&other, &blocked, &1));
    ce.remove_from_blocklist(&blocked);
    assert!(ce.can_transfer(&other, &blocked, &1));
    // History should record: init, BlocklistAdd, Pause, Unpause, BlocklistRemove
    assert_eq!(ce.policy_version_count(), 5);
}

#[test]
fn test_multiple_sequential_rule_updates_have_correct_versions() {
    let (_, ce, _) = setup();
    ce.set_rules(&rules(100, 0, 0, false));
    ce.set_rules(&rules(200, 0, 0, false));
    ce.set_rules(&rules(300, 0, 0, false));
    assert_eq!(ce.policy_version_count(), 4); // init + 3 updates
    assert_eq!(ce.get_policy_version(&1).rules.max_transfer_amount, 100);
    assert_eq!(ce.get_policy_version(&2).rules.max_transfer_amount, 200);
    assert_eq!(ce.get_policy_version(&3).rules.max_transfer_amount, 300);
}

#[test]
fn test_activation_before_delay_fails_and_leaves_state_unchanged() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = env.register(KycRegistry, ());
    KycRegistryClient::new(&env, &kyc_id).initialize(&admin);
    let ce_id = env.register(ComplianceEngine, ());
    let ce = ComplianceEngineClient::new(&env, &ce_id);
    ce.initialize(&admin, &kyc_id, &500u64);

    env.ledger().set_timestamp(1_000);
    let proposed = ComplianceRules {
        max_transfer_amount: 9999,
        min_holding_period: 0,
        max_holders: 0,
        require_same_jurisdiction: false,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    };
    ce.propose_rules(&proposed, &String::from_str(&env, "too early"));

    env.ledger().set_timestamp(1_499);
    assert!(ce.try_activate_rules().is_err());

    // Active rules must still be the defaults.
    assert_eq!(ce.get_rules().max_transfer_amount, 0);
    // Proposal should still be pending.
    assert!(ce.get_pending_proposal().is_some());
    // Policy version count must not have grown.
    assert_eq!(ce.policy_version_count(), 1); // only the init record
}

#[test]
fn test_propose_overwrites_previous_pending_proposal() {
    let (env, ce, _) = setup();
    ce.propose_rules(&rules(100, 0, 0, false), &String::from_str(&env, "first"));
    ce.propose_rules(&rules(200, 0, 0, false), &String::from_str(&env, "second"));
    let p = ce.get_pending_proposal().unwrap();
    assert_eq!(p.rules.max_transfer_amount, 200);
    ce.activate_rules();
    assert_eq!(ce.get_rules().max_transfer_amount, 200);
}

// ── Activation boundary ───────────────────────────────────────────────────────

#[test]
fn test_activate_rules_at_boundary() {
    // delay = 0 → activate_at == proposal timestamp; activation at exactly
    // that moment (no time advance) must succeed.
    let (env, ce, _) = setup();
    env.ledger().set_timestamp(500);
    ce.propose_rules(
        &rules(100, 0, 0, false),
        &String::from_str(&env, "boundary"),
    );
    // current_time (500) == activate_at (500): must be accepted.
    assert_eq!(ce.try_activate_rules(), Ok(Ok(())));
    assert_eq!(ce.get_rules().max_transfer_amount, 100);
}

#[test]
fn test_activate_rules_one_second_before_boundary_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let kyc_id = env.register(KycRegistry, ());
    KycRegistryClient::new(&env, &kyc_id).initialize(&admin);
    let ce_id = env.register(ComplianceEngine, ());
    let ce = ComplianceEngineClient::new(&env, &ce_id);
    // 1-second delay: activate_at = timestamp + 1.
    ce.initialize(&admin, &kyc_id, &1u64);
    env.ledger().set_timestamp(500);
    ce.propose_rules(
        &rules(100, 0, 0, false),
        &String::from_str(&env, "one-before"),
    );
    // current_time (500) < activate_at (501): must be rejected.
    assert_eq!(
        ce.try_activate_rules(),
        Err(Ok(Error::from(ComplianceError::TooEarlyToActivate)))
    );
}

// ── evaluate_transfer / KYC integration (preserved + extended) ────────────────

#[test]
fn test_evaluate_transfer_approved_kyc_allow() {
    use crate::TransferDecision;
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &100),
        TransferDecision::Allow
    );
}

#[test]
fn test_evaluate_transfer_missing_kyc_from_denied() {
    use crate::{DenyReason, TransferDecision};
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &100),
        TransferDecision::Deny(DenyReason::FromKycMissing)
    );
}

#[test]
fn test_evaluate_transfer_missing_kyc_to_denied() {
    use crate::{DenyReason, TransferDecision};
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "US"));
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &100),
        TransferDecision::Deny(DenyReason::ToKycMissing)
    );
}

#[test]
fn test_evaluate_transfer_expired_kyc_denied() {
    use crate::{DenyReason, TransferDecision};
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &1, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    env.ledger().set_timestamp(100);
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &100),
        TransferDecision::Deny(DenyReason::FromKycExpired)
    );
}

#[test]
fn test_evaluate_transfer_revoked_kyc_denied() {
    use crate::{DenyReason, TransferDecision};
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    kyc.revoke(&verifier, &alice);
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &100),
        TransferDecision::Deny(DenyReason::FromKycRevoked)
    );
}

#[test]
fn test_evaluate_transfer_paused_returns_compliance_paused() {
    use crate::{DenyReason, TransferDecision};
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    ce.pause();
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &100),
        TransferDecision::Deny(DenyReason::CompliancePaused)
    );
}

#[test]
fn test_evaluate_transfer_blocklisted_from_denied() {
    use crate::{DenyReason, TransferDecision};
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    ce.add_to_blocklist(&alice);
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &100),
        TransferDecision::Deny(DenyReason::FromBlocklisted)
    );
}

#[test]
fn test_can_transfer_ignores_kyc_for_backward_compat() {
    let (env, ce, _, _, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    // Neither has KYC — can_transfer must still return true.
    assert!(ce.can_transfer(&alice, &bob, &100));
}

#[test]
fn test_evaluate_transfer_amount_exceeded() {
    use crate::{DenyReason, TransferDecision};
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    ce.set_rules(&ComplianceRules {
        max_transfer_amount: 500,
        min_holding_period: 0,
        max_holders: 0,
        require_same_jurisdiction: false,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    });
    assert_eq!(
        ce.evaluate_transfer(&alice, &bob, &501),
        TransferDecision::Deny(DenyReason::AmountExceeded)
    );
}

// ── Jurisdiction tests (preserved) ────────────────────────────────────────────

#[test]
fn test_same_jurisdiction_blocks_cross_border() {
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &1, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &1, &0, &String::from_str(&env, "GB"));
    ce.set_rules(&ComplianceRules {
        max_transfer_amount: 0,
        min_holding_period: 0,
        max_holders: 0,
        require_same_jurisdiction: true,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    });
    assert!(!ce.can_transfer(&alice, &bob, &100));
}

#[test]
fn test_same_jurisdiction_allows_matching() {
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &1, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &1, &0, &String::from_str(&env, "US"));
    ce.set_rules(&ComplianceRules {
        max_transfer_amount: 0,
        min_holding_period: 0,
        max_holders: 0,
        require_same_jurisdiction: true,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 0,
    });
    assert!(ce.can_transfer(&alice, &bob, &100));
}

// ── Max holding period (preserved) ───────────────────────────────────────────

#[test]
fn test_max_holding_period_blocks_over_held_receiver() {
    let (env, ce, _) = setup();
    let sender = Address::generate(&env);
    let over_held = Address::generate(&env);
    let fresh = Address::generate(&env);
    ce.set_rules(&ComplianceRules {
        max_transfer_amount: 0,
        min_holding_period: 0,
        max_holders: 0,
        require_same_jurisdiction: false,
        paused: false,
        allowlist_mode: false,
        max_holding_period: 1_000,
    });
    env.ledger().set_timestamp(1_000);
    ce.register_holder(&over_held);
    env.ledger().set_timestamp(2_001);
    assert!(ce.can_transfer(&over_held, &fresh, &1));
    assert!(!ce.can_transfer(&sender, &over_held, &1));
}

#[test]
fn test_max_holding_period_zero_means_unlimited() {
    let (env, ce, _) = setup();
    let sender = Address::generate(&env);
    let long_holder = Address::generate(&env);
    ce.set_rules(&rules(0, 0, 0, false));
    env.ledger().set_timestamp(0);
    ce.register_holder(&long_holder);
    env.ledger().set_timestamp(u64::MAX / 2);
    assert!(ce.can_transfer(&sender, &long_holder, &1));
}

// ── Tier policy tests (preserved) ─────────────────────────────────────────────

#[test]
fn test_tier_policy_blocked_pair() {
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &2, &0, &String::from_str(&env, "US"));
    ce.set_tier_policy(
        &0u32,
        &2u32,
        &TierPolicy {
            blocked: true,
            max_transfer_amount: 0,
            min_from_tier: 0,
            min_to_tier: 0,
        },
    );
    assert!(!ce.can_transfer(&alice, &bob, &100));
    assert!(ce.can_transfer(&bob, &alice, &100));
}

#[test]
fn test_tier_policy_exact_match_overrides_wildcard() {
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &1, &0, &String::from_str(&env, "US"));
    kyc.approve(&verifier, &bob, &1, &0, &String::from_str(&env, "US"));
    ce.set_tier_policy(
        &u32::MAX,
        &u32::MAX,
        &TierPolicy {
            blocked: true,
            max_transfer_amount: 0,
            min_from_tier: 0,
            min_to_tier: 0,
        },
    );
    ce.set_tier_policy(
        &1u32,
        &1u32,
        &TierPolicy {
            blocked: false,
            max_transfer_amount: 0,
            min_from_tier: 0,
            min_to_tier: 0,
        },
    );
    assert!(ce.can_transfer(&alice, &bob, &100));
}

// ── Risk scoring tests (preserved) ───────────────────────────────────────────

#[test]
fn test_risk_scoring_inactive_by_default() {
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "KP"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    assert!(ce.can_transfer(&alice, &bob, &100));
    assert!(ce.get_risk_config().is_none());
}

#[test]
fn test_high_risk_jurisdiction_blocks_sender() {
    use crate::RiskConfig;
    let (env, ce, kyc, verifier, _) = setup_with_kyc();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    kyc.approve(&verifier, &alice, &0, &0, &String::from_str(&env, "KP"));
    kyc.approve(&verifier, &bob, &0, &0, &String::from_str(&env, "US"));
    ce.set_risk_config(&RiskConfig {
        max_score: 49,
        default_score: 0,
    });
    ce.set_jurisdiction_risk_score(&String::from_str(&env, "KP"), &100u32);
    ce.set_jurisdiction_risk_score(&String::from_str(&env, "US"), &10u32);
    assert!(!ce.can_transfer(&alice, &bob, &100));
}

// ── Schema migration tests (preserved) ───────────────────────────────────────

#[test]
fn test_schema_version_initialized_to_one() {
    let (_, ce, _) = setup();
    assert_eq!(ce.schema_version(), 1u32);
}

#[test]
fn test_migration_count_starts_at_zero() {
    let (_, ce, _) = setup();
    assert_eq!(ce.migration_count(), 0u32);
}

#[test]
fn test_migrate_schema_success_v1_to_v2() {
    let (env, ce, _) = setup();
    ce.migrate_schema(&2, &String::from_str(&env, "v1->v2"));
    assert_eq!(ce.schema_version(), 2);
    assert_eq!(ce.migration_count(), 1);
}

#[test]
fn test_migrate_schema_already_at_version_rejected() {
    let (env, ce, _) = setup();
    assert_eq!(
        ce.try_migrate_schema(&1, &String::from_str(&env, "dup")),
        Err(Ok(Error::from(ComplianceError::AlreadyAtSchemaVersion)))
    );
}

#[test]
fn test_migrate_schema_version_skip_rejected() {
    let (env, ce, _) = setup();
    assert_eq!(
        ce.try_migrate_schema(&3, &String::from_str(&env, "skip")),
        Err(Ok(Error::from(
            ComplianceError::MigrationVersionNotSequential
        )))
    );
}

#[test]
fn test_migrate_schema_state_continuity() {
    let (env, ce, _) = setup();
    ce.set_rules(&rules(1_000_000, 0, 100, false));
    ce.migrate_schema(&2, &String::from_str(&env, "v1->v2"));
    let r = ce.get_rules();
    assert_eq!(r.max_transfer_amount, 1_000_000);
    assert_eq!(r.max_holders, 100);
}

// ── Property-style consistency tests ─────────────────────────────────────────
//
// These tests mutate policy through multiple operations then verify that
// can_transfer evaluations are always consistent with the stored snapshot.

#[test]
fn test_policy_snapshot_consistent_with_active_rules_after_mutations() {
    // Apply a series of mutations and after each one check that
    // get_current_policy_version().rules matches get_rules().
    let (env, ce, _) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Mutation 1: set a transfer cap
    ce.set_rules(&rules(100, 0, 0, false));
    let snap = ce.get_current_policy_version();
    assert_eq!(
        snap.rules.max_transfer_amount,
        ce.get_rules().max_transfer_amount
    );
    assert_eq!(snap.rules.paused, ce.get_rules().paused);
    assert_eq!(ce.can_transfer(&from, &to, &1), !snap.rules.paused);

    // Mutation 2: pause
    ce.pause();
    let snap = ce.get_current_policy_version();
    assert_eq!(snap.rules.paused, ce.get_rules().paused);
    assert_eq!(ce.can_transfer(&from, &to, &1), !snap.rules.paused);

    // Mutation 3: unpause
    ce.unpause();
    let snap = ce.get_current_policy_version();
    assert_eq!(snap.rules.paused, ce.get_rules().paused);
    assert_eq!(ce.can_transfer(&from, &to, &1), !snap.rules.paused);

    // Mutation 4: remove the cap
    ce.set_rules(&rules(0, 0, 0, false));
    let snap = ce.get_current_policy_version();
    assert_eq!(
        snap.rules.max_transfer_amount,
        ce.get_rules().max_transfer_amount
    );
    assert_eq!(snap.rules.paused, ce.get_rules().paused);
    assert_eq!(ce.can_transfer(&from, &to, &1), !snap.rules.paused);
}

#[test]
fn test_evaluation_consistent_with_historical_snapshot_replay() {
    // Record rules at version N, then change them, then verify that a manual
    // evaluation against the version-N rules snapshot produces the same answer
    // as can_transfer produced at that time.
    let (env, ce, _) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);

    // Version 1: cap = 50
    ce.set_rules(&rules(50, 0, 0, false));
    let snap_v1 = ce.get_current_policy_version();
    // With cap=50, amount=30 should be allowed.
    assert!(ce.can_transfer(&from, &to, &30));
    // With cap=50, amount=51 should be blocked.
    assert!(!ce.can_transfer(&from, &to, &51));

    // Version 2: cap = 1000
    ce.set_rules(&rules(1000, 0, 0, false));
    // Now amount=51 is allowed.
    assert!(ce.can_transfer(&from, &to, &51));

    // Verify the stored snapshot for version 1 (0=init, 1=first set_rules).
    let v1 = ce.get_policy_version(&1u32);
    assert_eq!(
        v1.rules.max_transfer_amount,
        snap_v1.rules.max_transfer_amount
    );
    assert_eq!(v1.rules.max_transfer_amount, 50);
}

#[test]
fn test_blocklist_changes_reflected_in_policy_history() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);

    // init: 1 version
    ce.add_to_blocklist(&addr); // +1 = 2
    ce.remove_from_blocklist(&addr); // +1 = 3
    ce.add_to_blocklist(&addr); // +1 = 4

    let history = ce.get_policy_history(&0, &20);
    assert_eq!(history.len(), 4);
    assert_eq!(
        history.get(1).unwrap().change_kind,
        PolicyChangeKind::BlocklistAdd
    );
    assert_eq!(
        history.get(2).unwrap().change_kind,
        PolicyChangeKind::BlocklistRemove
    );
    assert_eq!(
        history.get(3).unwrap().change_kind,
        PolicyChangeKind::BlocklistAdd
    );
}

#[test]
fn test_register_holder_is_idempotent() {
    let (env, ce, _) = setup();
    let h = Address::generate(&env);
    ce.register_holder(&h);
    ce.register_holder(&h);
    assert_eq!(ce.holder_count(), 1);
}

#[test]
fn test_unregister_holder_decrements_count() {
    let (env, ce, _) = setup();
    let h = Address::generate(&env);
    ce.register_holder(&h);
    assert_eq!(ce.holder_count(), 1);
    ce.unregister_holder(&h);
    assert_eq!(ce.holder_count(), 0);
}

#[test]
fn test_blocklist_count_accuracy() {
    let (env, ce, _) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    assert_eq!(ce.blocklist_count(), 0);
    ce.add_to_blocklist(&a);
    assert_eq!(ce.blocklist_count(), 1);
    ce.add_to_blocklist(&b);
    assert_eq!(ce.blocklist_count(), 2);
    ce.add_to_blocklist(&a); // duplicate
    assert_eq!(ce.blocklist_count(), 2);
    ce.remove_from_blocklist(&a);
    assert_eq!(ce.blocklist_count(), 1);
    ce.remove_from_blocklist(&a); // already removed
    assert_eq!(ce.blocklist_count(), 1);
}

#[test]
fn test_version_returns_nonempty() {
    let (_, ce, _) = setup();
    assert!(!ce.version().is_empty());
}

// ── Persistent blocklist / allowlist (schema v2) ──────────────────────────────

#[test]
fn test_is_blocklisted_single_persistent_lookup() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    assert!(!ce.is_blocklisted(&addr));
    ce.add_to_blocklist(&addr);
    assert!(ce.is_blocklisted(&addr));
    ce.remove_from_blocklist(&addr);
    assert!(!ce.is_blocklisted(&addr));
}

#[test]
fn test_blocklist_get_paginated_25_addresses() {
    let (env, ce, _) = setup();
    // Add 25 distinct addresses
    for _ in 0..25 {
        ce.add_to_blocklist(&Address::generate(&env));
    }
    assert_eq!(ce.blocklist_count(), 25);

    let page0 = ce.get_blocklist(&0, &10);
    assert_eq!(page0.len(), 10);

    let page1 = ce.get_blocklist(&1, &10);
    assert_eq!(page1.len(), 10);

    let page2 = ce.get_blocklist(&2, &10);
    assert_eq!(page2.len(), 5);

    // page beyond end is empty
    let page3 = ce.get_blocklist(&3, &10);
    assert_eq!(page3.len(), 0);
}

#[test]
fn test_blocklist_remove_compaction_preserves_integrity() {
    let (env, ce, _) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);
    ce.add_to_blocklist(&a);
    ce.add_to_blocklist(&b);
    ce.add_to_blocklist(&c);
    assert_eq!(ce.blocklist_count(), 3);

    // Remove the first element — compaction should swap c into position 0
    ce.remove_from_blocklist(&a);
    assert_eq!(ce.blocklist_count(), 2);
    assert!(!ce.is_blocklisted(&a));
    assert!(ce.is_blocklisted(&b));
    assert!(ce.is_blocklisted(&c));

    // Full page must have exactly 2 distinct members
    let page = ce.get_blocklist(&0, &10);
    assert_eq!(page.len(), 2);
    assert!(!page.contains(&a));
    assert!(page.contains(&b));
    assert!(page.contains(&c));
}

#[test]
fn test_blocklist_remove_last_element() {
    let (env, ce, _) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    ce.add_to_blocklist(&a);
    ce.add_to_blocklist(&b);
    // Remove the last inserted element
    ce.remove_from_blocklist(&b);
    assert_eq!(ce.blocklist_count(), 1);
    assert!(ce.is_blocklisted(&a));
    assert!(!ce.is_blocklisted(&b));
    let page = ce.get_blocklist(&0, &10);
    assert_eq!(page.len(), 1);
}

#[test]
fn test_allowlist_crud() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    assert!(!ce.is_allowlisted(&addr));
    ce.add_to_allowlist(&addr);
    assert!(ce.is_allowlisted(&addr));
    ce.remove_from_allowlist(&addr);
    assert!(!ce.is_allowlisted(&addr));
}

#[test]
fn test_allowlist_count_and_get_paginated() {
    let (env, ce, _) = setup();
    for _ in 0..15 {
        ce.add_to_allowlist(&Address::generate(&env));
    }
    assert_eq!(ce.allowlist_count(), 15);
    let page0 = ce.get_allowlist(&0, &10);
    assert_eq!(page0.len(), 10);
    let page1 = ce.get_allowlist(&1, &10);
    assert_eq!(page1.len(), 5);
}

#[test]
fn test_allowlist_remove_compaction() {
    let (env, ce, _) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);
    ce.add_to_allowlist(&a);
    ce.add_to_allowlist(&b);
    ce.add_to_allowlist(&c);
    ce.remove_from_allowlist(&a);
    assert_eq!(ce.allowlist_count(), 2);
    assert!(!ce.is_allowlisted(&a));
    assert!(ce.is_allowlisted(&b));
    assert!(ce.is_allowlisted(&c));
    let page = ce.get_allowlist(&0, &10);
    assert_eq!(page.len(), 2);
    assert!(!page.contains(&a));
}

#[test]
fn test_duplicate_blocklist_add_idempotent() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    ce.add_to_blocklist(&addr);
    ce.add_to_blocklist(&addr); // duplicate — must not double-insert
    assert_eq!(ce.blocklist_count(), 1);
    assert_eq!(ce.get_blocklist(&0, &10).len(), 1);
}

#[test]
fn test_duplicate_allowlist_add_idempotent() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    ce.add_to_allowlist(&addr);
    ce.add_to_allowlist(&addr);
    assert_eq!(ce.allowlist_count(), 1);
    assert_eq!(ce.get_allowlist(&0, &10).len(), 1);
}

#[test]
fn test_remove_absent_blocklist_entry_is_noop() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    // Remove from empty list — must not panic and count stays 0
    ce.remove_from_blocklist(&addr);
    assert_eq!(ce.blocklist_count(), 0);
}

#[test]
fn test_evaluate_transfer_uses_persistent_blocklist() {
    let (env, ce, _) = setup();
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    ce.add_to_blocklist(&from);
    // Single persistent lookup blocks the transfer, no vec iteration
    assert!(!ce.can_transfer(&from, &to, &1));
    assert!(!ce.can_transfer(&to, &from, &1));
    ce.remove_from_blocklist(&from);
    assert!(ce.can_transfer(&from, &to, &1));
}

// ── Schema v2 migration ───────────────────────────────────────────────────────

#[test]
fn test_migration_v2_on_fresh_persistent_data() {
    let (env, ce, _) = setup();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    // Add addresses using new persistent code (no old Vec in instance)
    ce.add_to_blocklist(&a);
    ce.add_to_blocklist(&b);
    // Migrate v1 → v2: old instance Vec absent, persistent data untouched
    ce.migrate_schema(&2, &String::from_str(&env, "v1->v2"));
    assert_eq!(ce.schema_version(), 2);
    // Existing persistent data survives migration
    assert!(ce.is_blocklisted(&a));
    assert!(ce.is_blocklisted(&b));
    assert_eq!(ce.blocklist_count(), 2);
}

#[test]
fn test_migration_v2_twice_fails_safely() {
    let (env, ce, _) = setup();
    ce.migrate_schema(&2, &String::from_str(&env, "v1->v2"));
    assert_eq!(
        ce.try_migrate_schema(&2, &String::from_str(&env, "dup")),
        Err(Ok(Error::from(ComplianceError::AlreadyAtSchemaVersion)))
    );
    // Data intact after rejected second call
    assert_eq!(ce.schema_version(), 2);
}

#[test]
fn test_migration_v2_records_migration_audit_entry() {
    let (env, ce, _) = setup();
    ce.migrate_schema(&2, &String::from_str(&env, "blocklist-persistent"));
    assert_eq!(ce.migration_count(), 1);
    let rec = ce.get_migration_record(&0);
    assert_eq!(rec.from_version, 1);
    assert_eq!(rec.to_version, 2);
}

#[test]
fn test_blocklist_and_allowlist_independent() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);
    ce.add_to_blocklist(&addr);
    ce.add_to_allowlist(&addr);
    // Same address can be in both lists simultaneously
    assert!(ce.is_blocklisted(&addr));
    assert!(ce.is_allowlisted(&addr));
    ce.remove_from_blocklist(&addr);
    assert!(!ce.is_blocklisted(&addr));
    assert!(ce.is_allowlisted(&addr));
}

// ── Regression tests for targeted validation fixes ────────────────────────────

// Fix 1 — add_to_allowlist: reject blocklisted address
// Before the fix, an address already on the blocklist could also be added to
// the allowlist.  The blocklist check in evaluate_transfer_inner always runs
// first, so the allowlist entry would never have any effect — but it would
// still consume persistent storage and write a misleading AllowlistAdd policy
// record.  The fix panics with BlocklistedAddressOnAllowlist before touching
// storage, keeping both lists mutually exclusive.
#[test]
fn test_add_to_allowlist_rejects_blocklisted_address() {
    let (env, ce, _) = setup();
    let addr = Address::generate(&env);

    // Put the address on the blocklist first.
    ce.add_to_blocklist(&addr);
    assert!(ce.is_blocklisted(&addr));

    // Attempting to allowlist the same address must be rejected.
    assert_eq!(
        ce.try_add_to_allowlist(&addr),
        Err(Ok(Error::from(
            ComplianceError::BlocklistedAddressOnAllowlist
        )))
    );

    // Storage must be untouched: no allowlist entry written, count stays 0.
    assert!(!ce.is_allowlisted(&addr));
    assert_eq!(ce.allowlist_count(), 0);

    // Normal path still works: a non-blocklisted address can be allowlisted.
    let other = Address::generate(&env);
    ce.add_to_allowlist(&other);
    assert!(ce.is_allowlisted(&other));
    assert_eq!(ce.allowlist_count(), 1);
}

// Fix 2 — set_tier_policy: reject negative max_transfer_amount
// Before the fix, a TierPolicy with a negative max_transfer_amount could be
// stored.  The enforcement check in evaluate_transfer_inner uses `> 0` as the
// "cap is enabled" sentinel, so a negative value would be stored silently but
// never trip the denial branch — effectively disabling the cap while looking
// like it was set.  The fix panics with NegativeTierTransferAmount before any
// state is written.
#[test]
fn test_set_tier_policy_rejects_negative_max_transfer_amount() {
    let (_, ce, _) = setup();

    // Negative cap must be rejected before storage is touched.
    assert_eq!(
        ce.try_set_tier_policy(
            &0u32,
            &1u32,
            &TierPolicy {
                blocked: false,
                max_transfer_amount: -1,
                min_from_tier: 0,
                min_to_tier: 0,
            }
        ),
        Err(Ok(Error::from(ComplianceError::NegativeTierTransferAmount)))
    );

    // No policy must have been written.
    assert!(ce.get_tier_policy(&0u32, &1u32).is_none());
    assert_eq!(ce.tier_policy_count(), 0);

    // Normal path: zero and positive amounts are both accepted.
    ce.set_tier_policy(
        &0u32,
        &1u32,
        &TierPolicy {
            blocked: false,
            max_transfer_amount: 0,
            min_from_tier: 0,
            min_to_tier: 0,
        },
    );
    assert!(ce.get_tier_policy(&0u32, &1u32).is_some());

    ce.set_tier_policy(
        &0u32,
        &2u32,
        &TierPolicy {
            blocked: false,
            max_transfer_amount: 1_000,
            min_from_tier: 0,
            min_to_tier: 0,
        },
    );
    assert!(ce.get_tier_policy(&0u32, &2u32).is_some());
}

// Fix 3 — validate_rules: max_holders boundary
// The guard rejects max_holders strictly less than the live holder count.
// The exact-equal boundary (max_holders == holder_count) must be accepted:
// it prevents new holders from joining but does not break existing ones.
// This test makes both the rejected and the accepted boundary explicit.
#[test]
fn test_validate_rules_max_holders_boundary() {
    let (env, ce, _) = setup();

    // Register exactly 2 holders.
    ce.register_holder(&Address::generate(&env));
    ce.register_holder(&Address::generate(&env));
    assert_eq!(ce.holder_count(), 2);

    // max_holders < holder_count (1 < 2) → must be rejected.
    assert_eq!(
        ce.try_set_rules(&rules(0, 0, 1, false)),
        Err(Ok(Error::from(
            ComplianceError::MaxHoldersBelowCurrentCount
        )))
    );

    // max_holders == holder_count (2 == 2) → must be accepted (freeze at current).
    ce.set_rules(&rules(0, 0, 2, false));
    assert_eq!(ce.get_rules().max_holders, 2);

    // max_holders > holder_count (3 > 2) → must be accepted.
    ce.set_rules(&rules(0, 0, 3, false));
    assert_eq!(ce.get_rules().max_holders, 3);
}

// Fix 4 — propose_rules: reject empty description
// Before the fix, propose_rules accepted an empty description string and
// stored it into PendingRulesProposal and eventually into a PolicyRecord,
// leaving the governance audit trail with meaningless blank entries.
// The fix panics with EmptyDescription before any state is written.
#[test]
fn test_propose_rules_rejects_empty_description() {
    let (env, ce, _) = setup();
    let empty = String::from_str(&env, "");

    // Empty string must be rejected — no proposal stored.
    assert_eq!(
        ce.try_propose_rules(&rules(0, 0, 0, false), &empty),
        Err(Ok(Error::from(ComplianceError::EmptyDescription)))
    );
    assert!(ce.get_pending_proposal().is_none());

    // Normal path: non-empty description must still be accepted.
    let desc = String::from_str(&env, "raise transfer cap for Q4");
    ce.propose_rules(&rules(0, 0, 0, false), &desc);
    let proposal = ce.get_pending_proposal().expect("proposal must be stored");
    assert_eq!(proposal.description, desc);
}
