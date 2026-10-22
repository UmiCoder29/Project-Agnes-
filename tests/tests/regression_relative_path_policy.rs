use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::tempdir;

use agnes_common::{
    ActionPayload, ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult,
};
use agnes_policy::{Policy, PolicyRule};
use agnes_tests::SecurityTestHarness;

static CWD_MUTEX: Mutex<()> = Mutex::new(());

fn acquire_cwd_lock() -> std::sync::MutexGuard<'static, ()> {
    match CWD_MUTEX.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            CWD_MUTEX.clear_poison();
            poisoned.into_inner()
        }
    }
}

struct CwdGuard {
    original_cwd: PathBuf,
}

impl CwdGuard {
    fn change_to(new_dir: &Path) -> Self {
        let original_cwd = env::current_dir().expect("Failed to get current working directory");
        env::set_current_dir(new_dir).expect("Failed to set working directory");
        Self { original_cwd }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.original_cwd);
    }
}

/// Helper to configure a basic test environment.
struct TestSetup {
    _temp: tempfile::TempDir,
    root: PathBuf,
    sub: PathBuf,
    outside: PathBuf,
    root_file: PathBuf,
    sub_file: PathBuf,
    harness: SecurityTestHarness,
}

impl TestSetup {
    fn new() -> Self {
        let temp = tempdir().expect("Failed to create tempdir");
        let root = temp.path().join("sandbox_root");
        let sub = root.join("sub");
        let outside = temp.path().join("outside_dir");

        fs::create_dir_all(&sub).expect("create sub dir");
        fs::create_dir_all(&outside).expect("create outside dir");

        let canonical_root = root.canonicalize().expect("canonicalize root");
        let canonical_sub = sub.canonicalize().expect("canonicalize sub");
        let canonical_outside = outside.canonicalize().expect("canonicalize outside");

        let root_file = canonical_root.join("file.txt");
        let sub_file = canonical_sub.join("sub_file.txt");

        fs::write(&root_file, "ROOT_FILE_CONTENT").expect("write root file");
        fs::write(&sub_file, "SUB_FILE_CONTENT").expect("write sub file");

        let harness = SecurityTestHarness::new();
        harness.fs_enforcer.register_sandbox_root(&canonical_root);

        Self {
            _temp: temp,
            root: canonical_root,
            sub: canonical_sub,
            outside: canonical_outside,
            root_file,
            sub_file,
            harness,
        }
    }
}

/// 3(a, b, c): A relative request path is denied with "fail-closed-relative-path",
/// with the process working directory set to:
/// (a) outside the root
/// (b) the sandbox root
/// (c) a subdirectory of the root
#[test]
fn test_relative_request_path_denied_under_different_cwds() {
    let _lock = acquire_cwd_lock();
    let setup = TestSetup::new();

    // Allow everything under sandbox root
    let policy = Policy::new("p-allow-root", "Allow root", 1).with_rule(PolicyRule {
        id: "r-allow-root".to_string(),
        description: "Allow all in root".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", setup.root.display()),
        priority: 10,
    });
    setup.harness.policy_engine.add_policy(policy).unwrap();

    let cwd_targets = vec![
        ("outside", &setup.outside),
        ("sandbox_root", &setup.root),
        ("subdirectory", &setup.sub),
    ];

    for (desc, cwd_path) in cwd_targets {
        let _guard = CwdGuard::change_to(cwd_path);

        // 1. Relative path "file.txt"
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "file.txt".to_string(),
            },
        ).with_test_id(format!("TEST-REL-{}", desc));

        let decision = setup.harness.policy_engine.evaluate(&req);
        assert_eq!(
            decision.decision,
            Decision::Deny,
            "CWD={}: PolicyEngine must DENY relative path 'file.txt'",
            desc
        );
        assert_eq!(
            decision.matched_policy_id,
            "fail-closed-relative-path",
            "CWD={}: PolicyEngine must match 'fail-closed-relative-path'",
            desc
        );

        let report = setup.harness.execute_request(req);
        assert_eq!(
            report.decision,
            Decision::Deny,
            "CWD={}: Report decision must be Deny",
            desc
        );
        assert_eq!(
            report.policy,
            "fail-closed-relative-path",
            "CWD={}: Report policy must be 'fail-closed-relative-path'",
            desc
        );
        assert_eq!(
            report.enforcement,
            EnforcementAction::BlockRequest,
            "CWD={}: Enforcement must be BlockRequest",
            desc
        );
        assert_eq!(
            report.observed_result,
            ObservedResult::BlockedByFirewall,
            "CWD={}: Observed result must be BlockedByFirewall",
            desc
        );

        // 2. Relative path "sub/sub_file.txt"
        let req_nested = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "sub/sub_file.txt".to_string(),
            },
        ).with_test_id(format!("TEST-REL-NESTED-{}", desc));

        let dec_nested = setup.harness.policy_engine.evaluate(&req_nested);
        assert_eq!(
            dec_nested.decision,
            Decision::Deny,
            "CWD={}: PolicyEngine must DENY relative nested path",
            desc
        );
        assert_eq!(
            dec_nested.matched_policy_id,
            "fail-closed-relative-path",
            "CWD={}: PolicyEngine must match 'fail-closed-relative-path'",
            desc
        );
    }
}

/// 3: A relative path that worked only because the working directory equals the root is now denied.
#[test]
fn test_relative_path_working_only_because_cwd_equals_root_now_denied() {
    let _lock = acquire_cwd_lock();
    let setup = TestSetup::new();

    // Policy allows <root>/*
    let policy = Policy::new("p-allow-root", "Allow root", 1).with_rule(PolicyRule {
        id: "r-allow-root".to_string(),
        description: "Allow all in root".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", setup.root.display()),
        priority: 10,
    });
    setup.harness.policy_engine.add_policy(policy).unwrap();

    // Set CWD to the sandbox root.
    // In commit d568dd7, requesting "file.txt" succeeded because resolve_real_path evaluated
    // against current_dir() yielding <root>/file.txt which matched the policy rule!
    let _guard = CwdGuard::change_to(&setup.root);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "file.txt".to_string(),
        },
    ).with_test_id("TEST-CWD-EQUALS-ROOT-DENIED");

    let decision = setup.harness.policy_engine.evaluate(&req);
    assert_eq!(
        decision.decision,
        Decision::Deny,
        "Relative path MUST be denied even when CWD == root"
    );
    assert_eq!(
        decision.matched_policy_id,
        "fail-closed-relative-path",
        "Reason ID must be fail-closed-relative-path"
    );

    let report = setup.harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);
    assert_eq!(report.policy, "fail-closed-relative-path");
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(
        !report.logs.contains("ROOT_FILE_CONTENT"),
        "File content must not be accessed or leaked"
    );
}

/// 3: The Scenario F test:
/// Working directory <root>/sub, Allow <root>/sub/*, Deny <root>/file.txt, request "file.txt".
/// Must be denied by POLICY, not just blocked by the post-open check.
#[test]
fn test_scenario_f_denied_by_policy_not_just_post_open() {
    let _lock = acquire_cwd_lock();
    let setup = TestSetup::new();

    // Policy configuration for Scenario F:
    // Rule 1: Allow <root>/sub/*
    // Rule 2: Deny <root>/file.txt
    let policy = Policy::new("p-scenario-f", "Scenario F Policy", 1)
        .with_rule(PolicyRule {
            id: "r-allow-sub".to_string(),
            description: "Allow sub directory".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", setup.sub.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "r-deny-root-file".to_string(),
            description: "Deny root file".to_string(),
            decision: Decision::Deny,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: setup.root_file.to_string_lossy().to_string(),
            priority: 10,
        });
    setup.harness.policy_engine.add_policy(policy).unwrap();

    // Create sub/file.txt so that under CWD=<root>/sub, "file.txt" resolves against CWD to <root>/sub/file.txt
    let sub_file_txt = setup.sub.join("file.txt");
    fs::write(&sub_file_txt, "SUB_FILE_CONTENT").expect("write sub file.txt");

    // Set working directory to <root>/sub
    let _guard = CwdGuard::change_to(&setup.sub);

    // Request relative "file.txt"
    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "file.txt".to_string(),
        },
    ).with_test_id("TEST-SCENARIO-F");

    // In commit d568dd7:
    // PolicyEngine resolved "file.txt" against CWD (<root>/sub) -> <root>/sub/file.txt,
    // which matched "r-allow-sub" -> PolicyEngine returned ALLOW!
    // FilesystemEnforcer re-rooted "file.txt" to <root>/file.txt, and only the post-open check blocked it.
    //
    // With the fix:
    // PolicyEngine MUST reject "file.txt" directly with Deny and "fail-closed-relative-path"!
    let decision = setup.harness.policy_engine.evaluate(&req);
    assert_eq!(
        decision.decision,
        Decision::Deny,
        "Scenario F MUST be denied by policy directly at the boundary, not permitted to enforcer"
    );
    assert_eq!(
        decision.matched_policy_id,
        "fail-closed-relative-path",
        "Policy reason must be fail-closed-relative-path, not post-open check"
    );

    let report = setup.harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);
    assert_eq!(report.policy, "fail-closed-relative-path");
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(
        !report.logs.contains("ROOT_FILE_CONTENT"),
        "File content must not be read or logged"
    );
}

/// 3: Absolute paths still work exactly as before.
#[test]
fn test_absolute_paths_work_exactly_as_before() {
    let _lock = acquire_cwd_lock();
    let setup = TestSetup::new();

    let policy = Policy::new("p-allow-sub", "Allow sub directory", 1).with_rule(PolicyRule {
        id: "r-allow-sub".to_string(),
        description: "Allow sub directory".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", setup.sub.display()),
        priority: 10,
    });
    setup.harness.policy_engine.add_policy(policy).unwrap();

    // Set CWD outside root to prove working directory does not impact absolute paths
    let _guard = CwdGuard::change_to(&setup.outside);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: setup.sub_file.to_string_lossy().to_string(),
        },
    ).with_test_id("TEST-ABSOLUTE-PATH-SUCCESS");

    let decision = setup.harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(decision.matched_policy_id, "p-allow-sub");

    let report = setup.harness.execute_request(req);
    assert_eq!(report.decision, Decision::Allow);
    assert_eq!(report.enforcement, EnforcementAction::PermitExecution);
    assert_eq!(report.observed_result, ObservedResult::AccessSuccess);
    assert!(
        report.logs.contains("SUB_FILE_CONTENT"),
        "Enforcer must successfully read authorized absolute path"
    );
}

/// 4: Adversarial case for the change:
/// A path made of "./" prefixes, an empty string, a string of only spaces, and "~"
/// must all be denied, never treated as absolute.
#[test]
fn test_adversarial_non_absolute_vectors_denied() {
    let _lock = acquire_cwd_lock();
    let setup = TestSetup::new();

    // Permissive wildcard policy for filesystem actions
    let policy = Policy::new("p-wildcard", "Wildcard Allow", 1).with_rule(PolicyRule {
        id: "r-wildcard".to_string(),
        description: "Wildcard Allow".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile, ActionType::WriteFile],
        resource_pattern: "*".to_string(),
        priority: 10,
    });
    setup.harness.policy_engine.add_policy(policy).unwrap();

    let adversarial_vectors = vec![
        "./",
        "./file.txt",
        "./././file.txt",
        ".",
        "..",
        "../file.txt",
        "./sub/../../secret.txt",
        "",
        "   ",
        "\t\n",
        "~",
        "~/file.txt",
        "~root",
        "~root/secret.txt",
    ];

    for crafted in adversarial_vectors {
        // Test ReadFile
        let req_read = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: crafted.to_string(),
            },
        ).with_test_id("ADV-READ");

        let dec_read = setup.harness.policy_engine.evaluate(&req_read);
        assert_eq!(
            dec_read.decision,
            Decision::Deny,
            "ReadFile with crafted path '{}' must be Denied",
            crafted
        );
        assert_eq!(
            dec_read.matched_policy_id,
            "fail-closed-relative-path",
            "ReadFile with crafted path '{}' must match fail-closed-relative-path",
            crafted
        );

        // Test WriteFile
        let req_write = ActionRequest::new(
            "agent-001",
            ActionPayload::WriteFile {
                path: crafted.to_string(),
                content: "malicious".to_string(),
            },
        ).with_test_id("ADV-WRITE");

        let dec_write = setup.harness.policy_engine.evaluate(&req_write);
        assert_eq!(
            dec_write.decision,
            Decision::Deny,
            "WriteFile with crafted path '{}' must be Denied",
            crafted
        );
        assert_eq!(
            dec_write.matched_policy_id,
            "fail-closed-relative-path",
            "WriteFile with crafted path '{}' must match fail-closed-relative-path",
            crafted
        );

        // Test ReadSecret: non-file actions are NOT treated as relative paths and do not match filesystem rule
        if crafted.starts_with('.') || crafted.starts_with('~') || crafted.contains('/') {
            let req_secret = ActionRequest::new(
                "agent-001",
                ActionPayload::ReadSecret {
                    secret_id: crafted.to_string(),
                },
            ).with_test_id("ADV-SECRET");

            let dec_secret = setup.harness.policy_engine.evaluate(&req_secret);
            assert_eq!(
                dec_secret.decision,
                Decision::Deny,
                "ReadSecret with crafted path '{}' must be Denied",
                crafted
            );
            assert_ne!(
                dec_secret.matched_policy_id,
                "fail-closed-relative-path",
                "ReadSecret with crafted path '{}' must NOT be treated as a relative path",
                crafted
            );
        }
    }
}
