use agnes_common::{
    ActionPayload, ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult,
};
use agnes_policy::{Policy, PolicyRule};
use agnes_tests::SecurityTestHarness;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

const SECRET_CANARY_001: &str = "SECRET_CANARY_001_ROOT_KEY_999";
const SECRET_CANARY_002: &str = "SECRET_CANARY_002_SYMLINK_888";
const SECRET_CANARY_003: &str = "SECRET_CANARY_003_NESTED_TRAVERSAL_777";
const SECRET_CANARY_004: &str = "SECRET_CANARY_004_ALT_REP_666";
const SECRET_CANARY_005: &str = "SECRET_CANARY_005_RELATIVE_555";
const SECRET_CANARY_006: &str = "SECRET_CANARY_006_ABSOLUTE_444";
const SECRET_CANARY_007: &str = "SECRET_CANARY_007_CHAINED_SYM_333";
const SECRET_CANARY_008: &str = "SECRET_CANARY_008_TOCTOU_SYM_222";
const SECRET_CANARY_009: &str = "SECRET_CANARY_009_RENAME_DIR_111";
const SECRET_CANARY_010: &str = "SECRET_CANARY_010_SWAP_FILE_000";
const SECRET_CANARY_011: &str = "SECRET_CANARY_011_MULTI_SYM_998";
const SECRET_CANARY_012: &str = "SECRET_CANARY_012_PARENT_ESC_887";
const SECRET_CANARY_013: &str = "SECRET_CANARY_013_ALT_PATH_776";
const SECRET_CANARY_014: &str = "SECRET_CANARY_014_PERM_CHANGE_665";
const SECRET_CANARY_015: &str = "SECRET_CANARY_015_DEL_RACE_554";

struct TestEnv {
    _temp: tempfile::TempDir,
    allowed_dir: PathBuf,
    forbidden_dir: PathBuf,
    harness: SecurityTestHarness,
}

impl TestEnv {
    fn new(policy_id: &str) -> Self {
        let temp = tempdir().expect("tempdir failed");
        let allowed_dir = temp.path().join("allowed");
        let forbidden_dir = temp.path().join("forbidden");
        fs::create_dir_all(&allowed_dir).expect("mkdir allowed");
        fs::create_dir_all(&forbidden_dir).expect("mkdir forbidden");

        let harness = SecurityTestHarness::new();
        harness.fs_enforcer.register_sandbox_root(&allowed_dir);

        let allowed_pattern = format!("{}/*", allowed_dir.display());
        let policy = Policy::new(policy_id, "Filesystem Confinement Policy", 1)
            .with_rule(PolicyRule {
                id: "rule-allow-sandbox".to_string(),
                description: "Allow agent-001 access to allowed sandbox only".to_string(),
                decision: Decision::Allow,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: allowed_pattern,
                priority: 10,
            });

        harness.policy_engine.add_policy(policy);

        Self {
            _temp: temp,
            allowed_dir,
            forbidden_dir,
            harness,
        }
    }
}

// REGRESSION-001: Path traversal must be denied.
#[test]
fn test_regression_001_path_traversal() {
    let env = TestEnv::new("reg-001");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_001).unwrap();

    let malicious_path = format!("{}/../forbidden/secret.txt", env.allowed_dir.display());
    let req = ActionRequest::new("agent-001", ActionPayload::ReadFile { path: malicious_path })
        .with_test_id("REGRESSION-001");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_001));
}

// REGRESSION-002: Symlink escape must be denied.
#[test]
fn test_regression_002_symlink_escape() {
    let env = TestEnv::new("reg-002");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_002).unwrap();

    let symlink = env.allowed_dir.join("leak_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&forbidden_file, &symlink).unwrap();

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: symlink.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-002");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_002));
}

// REGRESSION-003: Nested traversal (/allowed/a/b/../../../../forbidden/secret.txt).
#[test]
fn test_regression_003_nested_traversal() {
    let env = TestEnv::new("reg-003");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_003).unwrap();

    let sub_dir = env.allowed_dir.join("a").join("b");
    fs::create_dir_all(&sub_dir).unwrap();

    let nested_path = format!("{}/../../../../forbidden/secret.txt", sub_dir.display());
    let req = ActionRequest::new("agent-001", ActionPayload::ReadFile { path: nested_path })
        .with_test_id("REGRESSION-003");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_003));
}

// REGRESSION-004: Encoded / alternate path representation.
#[test]
fn test_regression_004_alternate_representations() {
    let env = TestEnv::new("reg-004");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_004).unwrap();

    // Redundant slashes and dot segments
    let alt_path = format!("{}/././..//forbidden/secret.txt", env.allowed_dir.display());
    let req = ActionRequest::new("agent-001", ActionPayload::ReadFile { path: alt_path })
        .with_test_id("REGRESSION-004");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_004));
}

// REGRESSION-005: Relative path access.
#[test]
fn test_regression_005_relative_path_access() {
    let env = TestEnv::new("reg-005");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_005).unwrap();

    let rel_path = "../forbidden/secret.txt".to_string();
    let req = ActionRequest::new("agent-001", ActionPayload::ReadFile { path: rel_path })
        .with_test_id("REGRESSION-005");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_005));
}

// REGRESSION-006: Absolute path outside allowed root.
#[test]
fn test_regression_006_absolute_path_outside_root() {
    let env = TestEnv::new("reg-006");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_006).unwrap();

    let abs_path = forbidden_file.to_str().unwrap().to_string();
    let req = ActionRequest::new("agent-001", ActionPayload::ReadFile { path: abs_path })
        .with_test_id("REGRESSION-006");

    let report = env.harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_006));
}

// REGRESSION-007: Nested symlink (allowed/a -> allowed/b, allowed/b -> forbidden/secret).
#[test]
fn test_regression_007_chained_symlinks() {
    let env = TestEnv::new("reg-007");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_007).unwrap();

    let link_b = env.allowed_dir.join("link_b.txt");
    let link_a = env.allowed_dir.join("link_a.txt");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&forbidden_file, &link_b).unwrap();
        std::os::unix::fs::symlink(&link_b, &link_a).unwrap();
    }

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: link_a.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-007");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_007));
}

// REGRESSION-008: Symlink created after policy evaluation (TOCTOU).
#[test]
fn test_regression_008_symlink_created_after_policy() {
    let env = TestEnv::new("reg-008");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_008).unwrap();

    let target_file = env.allowed_dir.join("target.txt");
    fs::write(&target_file, "BENIGN_INIT").unwrap();

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: target_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-008");

    // Evaluate policy first
    let decision = env.harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);

    // Attacker modifies filesystem AFTER policy evaluation: replaces target with symlink to secret
    fs::remove_file(&target_file).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&forbidden_file, &target_file).unwrap();

    // Now enforcement runs
    let enforcement_res = env.harness.fs_enforcer.enforce_read(&req, &decision);

    // KERNEL ENFORCEMENT MUST CATCH THE ESCAPE AT OPEN TIME!
    assert_ne!(enforcement_res.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(
        enforcement_res.enforcement_action,
        EnforcementAction::KernelResolveBeneathBlock
    );
    assert_eq!(enforcement_res.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(enforcement_res.output, None);
}

// REGRESSION-009: Allowed directory renamed/replaced between validation and access.
#[test]
fn test_regression_009_dir_rename_replacement() {
    let env = TestEnv::new("reg-009");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_009).unwrap();

    let sub_dir = env.allowed_dir.join("sub_safe");
    fs::create_dir_all(&sub_dir).unwrap();
    let file = sub_dir.join("file.txt");
    fs::write(&file, "VALID_CONTENT").unwrap();

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-009");

    let decision = env.harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);

    // Replace sub_safe with symlink to forbidden_dir
    fs::remove_file(&file).unwrap();
    fs::remove_dir(&sub_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&env.forbidden_dir, &sub_dir).unwrap();

    let enforcement_res = env.harness.fs_enforcer.enforce_read(&req, &decision);
    assert_ne!(enforcement_res.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(enforcement_res.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(enforcement_res.output, None);
}

// REGRESSION-010: Allowed file replaced by symlink before actual access.
#[test]
fn test_regression_010_file_replaced_by_symlink() {
    let env = TestEnv::new("reg-010");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_010).unwrap();

    let normal_file = env.allowed_dir.join("document.txt");
    fs::write(&normal_file, "STANDARD_ALLOWED_DOC").unwrap();

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: normal_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-010");

    let decision = env.harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);

    // Swap document with symlink to forbidden
    fs::remove_file(&normal_file).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&forbidden_file, &normal_file).unwrap();

    let enforcement_res = env.harness.fs_enforcer.enforce_read(&req, &decision);
    assert_ne!(enforcement_res.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(
        enforcement_res.enforcement_action,
        EnforcementAction::KernelResolveBeneathBlock
    );
    assert_eq!(enforcement_res.observed_result, ObservedResult::BlockedByFirewall);
}

// REGRESSION-011: Multiple nested symlinks.
#[test]
fn test_regression_011_multiple_nested_symlinks() {
    let env = TestEnv::new("reg-011");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_011).unwrap();

    // 5 chained symlinks
    let mut current_target = forbidden_file.to_str().unwrap().to_string();
    for i in 1..=5 {
        let link_path = env.allowed_dir.join(format!("chain_link_{}.txt", i));
        #[cfg(unix)]
        std::os::unix::fs::symlink(&current_target, &link_path).unwrap();
        current_target = link_path.to_str().unwrap().to_string();
    }

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: current_target,
        },
    ).with_test_id("REGRESSION-011");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_011));
}

// REGRESSION-012: Attempt to escape using parent directories.
#[test]
fn test_regression_012_parent_directory_escape() {
    let env = TestEnv::new("reg-012");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_012).unwrap();

    let parent_path = format!("{}/..", env.allowed_dir.display());
    let req = ActionRequest::new("agent-001", ActionPayload::ReadFile { path: parent_path })
        .with_test_id("REGRESSION-012");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_012));
}

// REGRESSION-013: Attempt to access forbidden file through another filesystem path.
#[test]
fn test_regression_013_alternate_forbidden_path() {
    let env = TestEnv::new("reg-013");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_013).unwrap();

    // Alternate path notation: /proc/self/cwd/forbidden/...
    let alt_path = format!("/tmp/../{}", forbidden_file.strip_prefix("/").unwrap().display());
    let req = ActionRequest::new("agent-001", ActionPayload::ReadFile { path: alt_path })
        .with_test_id("REGRESSION-013");

    let report = env.harness.execute_request(req);
    assert_ne!(report.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert!(!report.logs.contains(SECRET_CANARY_013));
}

// REGRESSION-014: Permission changes after policy evaluation.
#[test]
fn test_regression_014_permission_changes_after_policy() {
    let env = TestEnv::new("reg-014");
    let allowed_file = env.allowed_dir.join("permission_test.txt");
    fs::write(&allowed_file, SECRET_CANARY_014).unwrap();

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: allowed_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-014");

    let decision = env.harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);

    // Change file mode to 0000 (no permissions)
    let mut perms = fs::metadata(&allowed_file).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&allowed_file, perms).unwrap();

    let res = env.harness.fs_enforcer.enforce_read(&req, &decision);
    // Access must fail due to real OS permission denial
    assert_ne!(res.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(res.observed_result, ObservedResult::AccessFailed);
    assert_eq!(res.output, None);

    // Restore permissions for cleanup
    let mut restore_perms = fs::metadata(&allowed_file).unwrap().permissions();
    restore_perms.set_mode(0o644);
    let _ = fs::set_permissions(&allowed_file, restore_perms);
}

// REGRESSION-015: Concurrency & File deletion/replacement race (Controlled Multi-threaded TOCTOU test).
#[test]
fn test_regression_015_concurrent_toctou_race() {
    let env = Arc::new(TestEnv::new("reg-015"));
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_015).unwrap();

    let race_file = env.allowed_dir.join("race_target.txt");
    fs::write(&race_file, "SAFE_INITIAL_DATA").unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();
    let _env_clone = env.clone();
    let race_file_clone = race_file.clone();
    let forbidden_clone = forbidden_file.clone();

    // Attacker Thread (Process B): Rapidly swaps race_target between real file and symlink to forbidden secret
    let attacker_handle = thread::spawn(move || {
        barrier_clone.wait();
        for _ in 0..100 {
            let _ = fs::remove_file(&race_file_clone);
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&forbidden_clone, &race_file_clone);
            thread::sleep(Duration::from_micros(50));
            let _ = fs::remove_file(&race_file_clone);
            let _ = fs::write(&race_file_clone, "SAFE_RECREATED_DATA");
            thread::sleep(Duration::from_micros(50));
        }
    });

    // Defender Thread (Process A): Executes requests through Project Agnes during active attacker race
    barrier.wait();
    for i in 0..100 {
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: race_file.to_str().unwrap().to_string(),
            },
        ).with_test_id(format!("REGRESSION-015-ITER-{}", i));

        let report = env.harness.execute_request(req);

        // INVARIANT CHECK:
        // Even under rapid concurrent symlink swapping, the forbidden secret CANARY MUST NEVER BE LEAKED!
        if let Some(output) = report.logs.strip_prefix("...") {
            assert!(!output.contains(SECRET_CANARY_015));
        }
        assert!(
            !report.logs.contains(SECRET_CANARY_015),
            "CRITICAL TOCTOU FAILURE: Secret canary leaked during concurrent filesystem race on iteration {}!",
            i
        );

        // If the file was pointing to symlink during open, observed result must NOT be AccessSuccess
        if report.enforcement == EnforcementAction::KernelResolveBeneathBlock {
            assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
        }
    }

    attacker_handle.join().unwrap();
}

// REGRESSION-016: Whitespace-trimming mismatch between policy resolution and enforcement.
// Files with leading/trailing whitespace must be rejected at the policy boundary (failing closed)
// rather than silently trimmed and matched against a policy rule.
#[test]
fn test_regression_016_whitespace_trimming_mismatch() {
    let temp = tempdir().expect("tempdir failed");
    let allowed_dir = temp.path().join("allowed");
    fs::create_dir_all(&allowed_dir).expect("mkdir allowed");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&allowed_dir);

    // Create a file with a trailing space in its name
    let file_with_trailing_space = allowed_dir.join("sensitive_file.txt ");
    fs::write(&file_with_trailing_space, "RESTRICTED_DATA_WHITESPACE").unwrap();

    let file_with_space_str = file_with_trailing_space.to_str().unwrap().to_string();

    // Register a policy that denies access to the file by exact path, and allows sandbox directory
    let policy = Policy::new("policy-whitespace-test", "Whitespace Boundary Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-deny-exact-space".to_string(),
            description: "Deny exact path of file with trailing space".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: file_with_space_str.clone(),
            priority: 100,
        })
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox".to_string(),
            description: "Allow sandbox access".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", allowed_dir.display()),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: file_with_space_str.clone(),
        },
    ).with_test_id("REGRESSION-016");

    let report = harness.execute_request(req);

    // Assertions:
    // 1. The request must be denied and blocked by firewall
    assert_eq!(report.decision, Decision::Deny);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(report.enforcement, EnforcementAction::BlockRequest);

    // 2. Fail-closed at policy boundary:
    // Requesting the untrimmed path must be rejected at the policy boundary (fail-closed-path-resolution),
    // rather than being silently trimmed and matched against the trimmed version via rule-deny-exact-space.
    assert_eq!(
        report.policy, "fail-closed-path-resolution",
        "Untrimmed path must be rejected fail-closed at policy boundary, not matched to policy rule"
    );
    assert_ne!(
        report.policy, "policy-whitespace-test",
        "Request must NOT be silently matched against policy rule via trimmed path"
    );
    assert!(
        !report.logs.contains("rule-deny-exact-space"),
        "Must not match rule-deny-exact-space on trimmed path representation"
    );
    assert!(
        report.logs.contains("Path resolution failed") && report.logs.contains("whitespace"),
        "Logs must indicate boundary resolution failure due to whitespace"
    );
}

// REGRESSION-017: Filesystem path must be resolved exactly once per evaluate() call.
// Duplicate path resolution in matches_target() introduces redundant filesystem I/O
// and TOCTOU risks during evaluation.
#[test]
fn test_regression_017_single_path_resolution_per_request() {
    let temp = tempdir().expect("tempdir failed");
    let allowed_dir = temp.path().join("allowed");
    fs::create_dir_all(&allowed_dir).expect("mkdir allowed");

    let canonical_allowed_dir = allowed_dir.canonicalize().expect("canonicalize allowed_dir");

    let target_file = canonical_allowed_dir.join("single_res_file.txt");
    fs::write(&target_file, "TEST_DATA_SINGLE_RESOLUTION").expect("write test file");

    let target_file_str = target_file.to_str().unwrap().to_string();

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&canonical_allowed_dir);

    // Policy with 3 rules matching the agent and action type.
    // If redundant resolution occurs in matches_target(), each rule will trigger
    // an additional call to resolve_real_path().
    let policy = Policy::new("policy-single-resolution", "Single Resolution Verification Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-dir-prefix".to_string(),
            description: "Allow reading inside allowed sandbox dir".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", canonical_allowed_dir.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-allow-exact-file".to_string(),
            description: "Allow reading target file by exact path".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: target_file_str.clone(),
            priority: 20,
        })
        .with_rule(PolicyRule {
            id: "rule-allow-wildcard-fallback".to_string(),
            description: "Wildcard rule matching agent and action type".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 5,
        });

    harness.policy_engine.add_policy(policy);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: target_file_str.clone(),
        },
    ).with_test_id("REGRESSION-017");

    // Reset resolution counter before calling evaluate
    agnes_policy::reset_resolution_count();

    let report = harness.execute_request(req);

    let count = agnes_policy::resolution_count();

    // The request should be evaluated and permitted
    assert_ne!(report.observed_result, ObservedResult::Error);
    assert_eq!(report.decision, Decision::Allow);

    // CRITICAL REGRESSION ASSERTION:
    // Path resolution for the target resource must occur EXACTLY ONCE per request.
    // Without the fix, matches_target() re-resolves the target for every matching rule (count >= 4).
    assert_eq!(
        count, 1,
        "Path resolution must happen exactly once per evaluate() call, but occurred {} times",
        count
    );
}

// REGRESSION-017-B: Atomic resolution must evaluate against the path resolved at the
// policy boundary without picking up mid-evaluation filesystem modifications.
// If a symlink pointing to an allowed file is repointed mid-evaluation to a denied path,
// the policy decision must remain Allow (the decision of the first resolution) rather than
// re-resolving from disk and matching Deny.
#[test]
fn test_regression_017_target_resolution_atomic_against_mid_evaluation_change() {
    let temp = tempdir().expect("tempdir failed");
    let allowed_dir = temp.path().join("allowed");
    let denied_dir = temp.path().join("denied");
    fs::create_dir_all(&allowed_dir).expect("mkdir allowed");
    fs::create_dir_all(&denied_dir).expect("mkdir denied");

    let canonical_allowed_dir = allowed_dir.canonicalize().expect("canonicalize allowed");
    let canonical_denied_dir = denied_dir.canonicalize().expect("canonicalize denied");

    let allowed_target = canonical_allowed_dir.join("allowed_file.txt");
    fs::write(&allowed_target, "SAFE_CANARY_017").expect("write allowed file");

    let denied_target = canonical_denied_dir.join("denied_file.txt");
    fs::write(&denied_target, "RESTRICTED_CANARY_017").expect("write denied file");

    // Initially, symlink inside allowed_dir points to allowed_target (in allowed_dir)
    let symlink_path = canonical_allowed_dir.join("swappable_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&allowed_target, &symlink_path).expect("create initial symlink");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&canonical_allowed_dir);

    // Policy allows access only to allowed_dir/*; anything else fails closed (Deny).
    let policy = Policy::new("policy-atomic-swap", "Atomic Resolution Mid-Evaluation Swap Test", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox-dir".to_string(),
            description: "Allow reading inside allowed_dir".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", canonical_allowed_dir.display()),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    let symlink_path_clone = symlink_path.clone();
    let allowed_target_clone = allowed_target.clone();
    let denied_target_clone = denied_target.clone();

    // Reset resolution counter before request
    agnes_policy::reset_resolution_count();

    // Hook fires immediately after the first resolve_real_path completes (in PolicyEngine::evaluate)
    // and repoints both symlink_path and allowed_target to point to denied_target.
    // If matches_target() re-resolves either the symlink or the target from disk, it will resolve
    // to denied_target and fail to match rule-allow-sandbox-dir, defaulting to Decision::Deny.
    // Because resolution happens exactly once, evaluate() uses the first resolved path (allowed_target)
    // and evaluates to Decision::Allow (rule-allow-sandbox-dir).
    agnes_policy::set_resolution_hook(move |_resolved_raw| {
        let _ = fs::remove_file(&symlink_path_clone);
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&denied_target_clone, &symlink_path_clone);

        let _ = fs::remove_file(&allowed_target_clone);
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&denied_target_clone, &allowed_target_clone);
    });

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: symlink_path.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-017-SWAP");

    let decision = harness.policy_engine.evaluate(&req);
    agnes_policy::clear_resolution_hook();

    let count = agnes_policy::resolution_count();

    assert_eq!(
        decision.decision,
        Decision::Allow,
        "Policy evaluation must succeed atomically using the single resolved path without re-resolving from disk"
    );
    assert_eq!(
        decision.matched_policy_id,
        "policy-atomic-swap",
        "Must match the allowed policy"
    );
    assert_eq!(
        decision.reason.rule_id.as_deref(),
        Some("rule-allow-sandbox-dir"),
        "Must match rule-allow-sandbox-dir from initial resolution rather than picking up swapped denied target"
    );
    assert_eq!(
        count, 1,
        "Path resolution must happen exactly once, but occurred {} times",
        count
    );
}

// REGRESSION-018: TOCTOU race where an intra-sandbox symlink is swapped
// between policy evaluation and kernel file open.
// Both allowed_doc and internal_secret reside within the allowed sandbox root.
// Policy explicitly allows access to allowed_doc and denies internal_secret.
// Request targets swappable_link, which points to allowed_doc at evaluation time (Decision::Allow).
// Attacker replaces swappable_link with a symlink to internal_secret before enforcement runs.
// Without atomic descriptor-target verification, openat2(RESOLVE_BENEATH) succeeds because
// internal_secret is within the sandbox root, leaking secret data despite policy denial.
#[test]
fn test_regression_018_toctou_symlink_swap_between_policy_and_enforcement() {
    let temp = tempdir().expect("tempdir failed");
    let allowed_dir = temp.path().join("allowed_sandbox");
    fs::create_dir_all(&allowed_dir).expect("mkdir allowed_sandbox");

    let canonical_root = allowed_dir.canonicalize().expect("canonicalize root");

    let allowed_file = canonical_root.join("public_doc.txt");
    fs::write(&allowed_file, "SAFE_PUBLIC_DATA_018").expect("write public file");

    let secret_file = canonical_root.join("internal_secret.txt");
    fs::write(&secret_file, "CLASSIFIED_SECRET_018").expect("write secret file");

    let swappable_link = canonical_root.join("swappable_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("public_doc.txt", &swappable_link).expect("create symlink");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&canonical_root);

    let allowed_str = allowed_file.to_str().unwrap().to_string();
    let secret_str = secret_file.to_str().unwrap().to_string();

    let policy = Policy::new("policy-toctou-gap", "TOCTOU Intra-Sandbox Test Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-public".to_string(),
            description: "Allow reading public doc only".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: allowed_str.clone(),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-secret".to_string(),
            description: "Deny reading internal secret".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: secret_str.clone(),
            priority: 20,
        });

    harness.policy_engine.add_policy(policy);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: swappable_link.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-018-TOCTOU");

    // 1. Time of Check: PolicyEngine evaluates swappable_link pointing to allowed_file -> Decision::Allow
    let decision = harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(
        decision.resolved_resource.as_deref(),
        Some(allowed_str.as_str()),
        "Policy engine must have approved the resolved public file path"
    );

    // 2. TOCTOU Window: Attacker swaps swappable_link to point to internal_secret (relative symlink)
    fs::remove_file(&swappable_link).expect("remove symlink");
    #[cfg(unix)]
    std::os::unix::fs::symlink("internal_secret.txt", &swappable_link).expect("swap symlink to secret");

    // 3. Time of Use: Enforcement runs on swappable_link
    let enforcement_res = harness.fs_enforcer.enforce_read(&req, &decision);

    // MUST FAIL-CLOSED AND NOT LEAK THE SECRET!
    assert_ne!(
        enforcement_res.observed_result,
        ObservedResult::AccessSuccess,
        "CRITICAL TOCTOU FAILURE: Enforcement permitted access after symlink was swapped to unauthorized file!"
    );
    assert_eq!(
        enforcement_res.observed_result,
        ObservedResult::BlockedByFirewall,
        "Enforcement must block the request when opened file does not match approved policy resource"
    );
    assert_eq!(
        enforcement_res.output,
        None,
        "Must never leak file content when a TOCTOU race condition is detected"
    );
}

// Non-race companion test: When no symlink swap occurs, the benign request succeeds
// cleanly through openat2 and post-open descriptor verification.
#[test]
fn test_regression_018_non_race_path_succeeds() {
    let temp = tempdir().expect("tempdir failed");
    let allowed_dir = temp.path().join("allowed_sandbox");
    fs::create_dir_all(&allowed_dir).expect("mkdir allowed_sandbox");

    let canonical_root = allowed_dir.canonicalize().expect("canonicalize root");

    let allowed_file = canonical_root.join("public_doc.txt");
    fs::write(&allowed_file, "SAFE_PUBLIC_DATA_018").expect("write public file");

    let swappable_link = canonical_root.join("swappable_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("public_doc.txt", &swappable_link).expect("create symlink");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&canonical_root);

    let allowed_str = allowed_file.to_str().unwrap().to_string();

    let policy = Policy::new("policy-benign", "Benign Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-public".to_string(),
            description: "Allow reading public doc".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: allowed_str.clone(),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: swappable_link.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-018-BENIGN");

    let decision = harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);

    let enforcement_res = harness.fs_enforcer.enforce_read(&req, &decision);
    assert_eq!(enforcement_res.observed_result, ObservedResult::AccessSuccess);
    assert_eq!(enforcement_res.enforcement_action, EnforcementAction::PermitExecution);
    assert_eq!(enforcement_res.output, Some("SAFE_PUBLIC_DATA_018".to_string()));
}

// REGRESSION-019: Target file itself replaced by symlink to unauthorized file after policy evaluation.
// Policy allows public_doc.txt and denies internal_secret.txt, both in the sandbox.
// Request targets a symlink to public_doc.txt.
// After evaluation, attacker replaces public_doc.txt itself with a symlink to internal_secret.txt.
// In the pre-fix code with canonicalize-based fallback, expected_path.canonicalize() re-resolves
// public_doc.txt from disk at enforcement time, matching opened_path.canonicalize(), leaking the secret.
// Under strict path-equality enforcement without disk re-resolution fallback, enforcement blocks the request.
#[test]
fn test_regression_019_approved_file_replaced_by_symlink() {
    let temp = tempdir().expect("tempdir failed");
    let allowed_dir = temp.path().join("allowed_sandbox");
    fs::create_dir_all(&allowed_dir).expect("mkdir allowed_sandbox");

    let canonical_root = allowed_dir.canonicalize().expect("canonicalize root");

    let allowed_file = canonical_root.join("public_doc.txt");
    fs::write(&allowed_file, "SAFE_PUBLIC_DATA_019").expect("write public file");

    let secret_file = canonical_root.join("internal_secret.txt");
    fs::write(&secret_file, "CLASSIFIED_SECRET_019").expect("write secret file");

    let swappable_link = canonical_root.join("swappable_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("public_doc.txt", &swappable_link).expect("create symlink");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&canonical_root);

    let allowed_str = allowed_file.to_str().unwrap().to_string();
    let secret_str = secret_file.to_str().unwrap().to_string();

    let policy = Policy::new("policy-reg-019", "REGRESSION-019 Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-public".to_string(),
            description: "Allow reading public doc".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: allowed_str.clone(),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-secret".to_string(),
            description: "Deny reading internal secret".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: secret_str.clone(),
            priority: 20,
        });

    harness.policy_engine.add_policy(policy);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: swappable_link.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-019-TARGET-SWAP");

    // 1. Policy evaluation approves access to public_doc.txt
    let decision = harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(
        decision.resolved_resource.as_deref(),
        Some(allowed_str.as_str()),
        "Policy engine must have approved public_doc.txt"
    );

    // 2. TOCTOU: Attacker replaces public_doc.txt itself with a symlink to internal_secret.txt
    fs::remove_file(&allowed_file).expect("remove allowed file");
    #[cfg(unix)]
    std::os::unix::fs::symlink("internal_secret.txt", &allowed_file)
        .expect("replace allowed file with symlink to secret");

    // 3. Enforcement runs
    let enforcement_res = harness.fs_enforcer.enforce_read(&req, &decision);

    // Assert BlockedByFirewall, output == None, and secret never leaked
    assert_ne!(
        enforcement_res.observed_result,
        ObservedResult::AccessSuccess,
        "CRITICAL TOCTOU FAILURE: Enforcement permitted access after approved file was replaced by symlink!"
    );
    assert_eq!(
        enforcement_res.observed_result,
        ObservedResult::BlockedByFirewall,
        "Enforcement must block the request when opened file does not match approved policy resource"
    );
    assert_eq!(
        enforcement_res.output,
        None,
        "Output must be None on boundary violation"
    );
    assert!(
        !enforcement_res.output.as_deref().unwrap_or_default().contains("CLASSIFIED_SECRET_019"),
        "Secret must never appear in enforcement output"
    );
}

// REGRESSION-020: Zero matching rules resolves to Deny (fail-closed default).
#[test]
fn test_regression_020_zero_matching_rules_resolves_to_deny() {
    let harness = SecurityTestHarness::new();
    let policy = Policy::new("policy-agent-002", "Agent 002 Only", 1).with_rule(PolicyRule {
        id: "rule-agent-002-only".to_string(),
        description: "Allow only agent-002".to_string(),
        decision: Decision::Allow,
        agent_pattern: "agent-002".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: "/sandbox/*".to_string(),
        priority: 10,
    });
    harness.policy_engine.add_policy(policy);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/sandbox/file.txt".to_string(),
        },
    ).with_test_id("REGRESSION-020-ZERO-RULES");

    let report = harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);
    assert_eq!(report.policy, "default-fail-closed");
    assert_eq!(report.enforcement, EnforcementAction::BlockRequest);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
}

// REGRESSION-021: Policy configuration parsing failure at startup fails safely (safe startup failure).
#[test]
fn test_regression_021_policy_config_parsing_failure_safe_startup() {
    // Malformed JSON must fail to parse safely
    let malformed_json = r#"{"id": "bad", "name": "broken", rules: [INVALID]}"#;
    let res = Policy::from_json(malformed_json);
    assert!(res.is_err(), "Malformed policy JSON must fail parsing safely");

    // Attempting to load malformed JSON into the engine must return Err
    let harness = SecurityTestHarness::new();
    let load_res = harness.policy_engine.load_policy_from_json(malformed_json);
    assert!(load_res.is_err(), "Engine must reject malformed policy config at startup");

    // Any request to an unpopulated or failed engine must fail closed to Deny
    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/sandbox/canary.txt".to_string(),
        },
    ).with_test_id("REGRESSION-021-PARSE-FAIL");

    let report = harness.execute_request(req);
    assert_eq!(report.decision, Decision::Deny);
    assert_eq!(report.enforcement, EnforcementAction::BlockRequest);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
}

// REGRESSION-022: Policy evaluation function panic or internal error fails closed to Deny.
#[test]
fn test_regression_022_evaluation_panic_fails_closed_to_deny() {
    let harness = SecurityTestHarness::new();
    let policy = Policy::new("policy-allow-all", "Allow All", 1).with_rule(PolicyRule {
        id: "rule-allow".to_string(),
        description: "Allow all".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: "*".to_string(),
        priority: 10,
    });
    harness.policy_engine.add_policy(policy);

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/sandbox/panic_test.txt".to_string(),
        },
    ).with_test_id("REGRESSION-022-PANIC");

    // Simulate internal evaluation panic via resolution hook
    agnes_policy::set_resolution_hook(|_| {
        panic!("FATAL_SIMULATED_INTERNAL_EVALUATION_PANIC");
    });

    let report = harness.execute_request(req);
    agnes_policy::clear_resolution_hook();

    assert_eq!(
        report.decision,
        Decision::Deny,
        "Evaluation panic must be caught and fail closed to Deny"
    );
    assert_eq!(report.policy, "fail-closed-evaluation-panic");
    assert_eq!(report.enforcement, EnforcementAction::BlockRequest);
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
}

// REGRESSION-023: Non-atomic config load preserves valid policies when load fails.
#[test]
fn test_regression_023_non_atomic_config_load_preserves_valid_policies() {
    let harness = SecurityTestHarness::new();
    let valid_json = r#"{
        "id": "policy-valid",
        "name": "Valid Policy",
        "version": 1,
        "rules": [{
            "id": "rule-allow-valid",
            "description": "Allow read",
            "decision": "ALLOW",
            "agent_pattern": "*",
            "action_types": ["READ_FILE"],
            "resource_pattern": "*",
            "priority": 10
        }]
    }"#;

    assert!(harness.policy_engine.load_policy_from_json(valid_json).is_ok());

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/sandbox/file.txt".to_string(),
        },
    ).with_test_id("REGRESSION-023-ATOMIC-LOAD");

    assert_eq!(harness.policy_engine.evaluate(&req).decision, Decision::Allow);

    // Attempting invalid load leaves valid policy active
    let invalid_json = r#"{"id": "bad", "rules": [ INVALID_JSON"#;
    assert!(harness.policy_engine.load_policy_from_json(invalid_json).is_err());

    let decision = harness.policy_engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);
    assert_eq!(decision.matched_policy_id, "policy-valid");
}

// REGRESSION-024: Adversarial empty patterns and invalid path inputs resolve to Deny.
#[test]
fn test_regression_024_adversarial_empty_patterns_and_invalid_paths_denied() {
    let harness = SecurityTestHarness::new();

    // 1. Empty agent_pattern
    harness.policy_engine.add_policy(
        Policy::new("p1", "p", 1).with_rule(PolicyRule {
            id: "r1".to_string(),
            description: "r".to_string(),
            decision: Decision::Allow,
            agent_pattern: "".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        })
    );
    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/sandbox/file.txt".to_string(),
        },
    );
    assert_eq!(harness.policy_engine.evaluate(&req).decision, Decision::Deny);

    // 2. Empty action_types
    harness.policy_engine.clear();
    harness.policy_engine.add_policy(
        Policy::new("p2", "p", 1).with_rule(PolicyRule {
            id: "r2".to_string(),
            description: "r".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![],
            resource_pattern: "*".to_string(),
            priority: 10,
        })
    );
    assert_eq!(harness.policy_engine.evaluate(&req).decision, Decision::Deny);

    // 3. Empty resource_pattern
    harness.policy_engine.clear();
    harness.policy_engine.add_policy(
        Policy::new("p3", "p", 1).with_rule(PolicyRule {
            id: "r3".to_string(),
            description: "r".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "".to_string(),
            priority: 10,
        })
    );
    assert_eq!(harness.policy_engine.evaluate(&req).decision, Decision::Deny);

    // 4. Unresolvable path with null byte under allow-all
    harness.policy_engine.clear();
    harness.policy_engine.add_policy(
        Policy::new("p4", "p", 1).with_rule(PolicyRule {
            id: "r4".to_string(),
            description: "r".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 10,
        })
    );
    let req_null = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/sandbox/null\0byte.txt".to_string(),
        },
    );
    assert_eq!(harness.policy_engine.evaluate(&req_null).decision, Decision::Deny);
}






