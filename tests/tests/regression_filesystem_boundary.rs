use agnes_common::{
    ActionPayload, ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult,
};
use agnes_policy::{Policy, PolicyLoadError, PolicyRule};
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
const SECRET_CANARY_032: &str = "SECRET_CANARY_032_RELATIVE_CLIMB_101";

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

        harness.policy_engine.add_policy(policy).unwrap();

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

    assert!(harness.policy_engine.add_policy(policy).is_err());

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

    harness.policy_engine.add_policy(policy).unwrap();

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

    harness.policy_engine.add_policy(policy).unwrap();

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

    harness.policy_engine.add_policy(policy).unwrap();

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

    harness.policy_engine.add_policy(policy).unwrap();

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

    harness.policy_engine.add_policy(policy).unwrap();

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
    harness.policy_engine.add_policy(policy).unwrap();

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
    harness.policy_engine.add_policy(policy).unwrap();

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
    ).unwrap();
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
    ).unwrap();
    assert_eq!(harness.policy_engine.evaluate(&req).decision, Decision::Deny);

    // 3. Empty resource_pattern is rejected atomically at load time
    harness.policy_engine.clear();
    assert!(harness.policy_engine.add_policy(
        Policy::new("p3", "p", 1).with_rule(PolicyRule {
            id: "r3".to_string(),
            description: "r".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "".to_string(),
            priority: 10,
        })
    ).is_err());
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
    ).unwrap();
    let req_null = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: "/sandbox/null\0byte.txt".to_string(),
        },
    );
    assert_eq!(harness.policy_engine.evaluate(&req_null).decision, Decision::Deny);
}

// REGRESSION-025: Symlink loop target resolution failure resolves to Deny.
#[test]
fn test_regression_025_symlink_loop_resolves_to_deny() {
    let harness = SecurityTestHarness::new();
    let temp = tempfile::tempdir().unwrap();
    let loop_a = temp.path().join("loop_a");
    let loop_b = temp.path().join("loop_b");

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&loop_b, &loop_a).unwrap();
        std::os::unix::fs::symlink(&loop_a, &loop_b).unwrap();
    }

    // Allow-all policy: will match and allow if resolution error doesn't fail closed
    let policy = Policy::new("policy-allow-all", "Allow all", 1).with_rule(PolicyRule {
        id: "rule-allow".to_string(),
        description: "Allow all".to_string(),
        decision: Decision::Allow,
        agent_pattern: "*".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: "*".to_string(),
        priority: 10,
    });
    harness.policy_engine.add_policy(policy).unwrap();

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: loop_a.to_string_lossy().to_string(),
        },
    ).with_test_id("REGRESSION-025-SYMLINK-LOOP");

    let decision = harness.policy_engine.evaluate(&req);
    assert_eq!(
        decision.decision,
        Decision::Deny,
        "Symlink loop must fail closed to Deny"
    );
    assert_eq!(decision.matched_policy_id, "fail-closed-path-resolution");
}

// REGRESSION-026: Precedence order for multiple matching rules.
// When multiple rules match the same path at equal priority:
// 1. Most-specific match wins (subdirectory beats parent directory).
// 2. When precedence is ambiguous (equal specificity and priority), Deny wins.
#[test]
fn test_regression_026_precedence_most_specific_match_and_deny_on_ambiguity() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let parent_dir = sandbox_root.join("parent");
    let sub_dir = parent_dir.join("sub");
    fs::create_dir_all(&sub_dir).expect("mkdir sub");

    let file_in_sub = sub_dir.join("sub_file.txt");
    fs::write(&file_in_sub, "SUB_DATA").expect("write sub_file");

    let file_in_parent = parent_dir.join("parent_file.txt");
    fs::write(&file_in_parent, "PARENT_DATA").expect("write parent_file");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Case 1: Deny subdirectory inside Allow parent (equal priority 10)
    // Most specific rule (sub_dir) must win -> Deny.
    {
        harness.policy_engine.clear();
        let policy = Policy::new("policy-sub-deny", "Sub Deny", 1)
            .with_rule(PolicyRule {
                id: "rule-allow-parent".to_string(),
                description: "Allow parent directory".to_string(),
                decision: Decision::Allow,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", parent_dir.display()),
                priority: 10,
            })
            .with_rule(PolicyRule {
                id: "rule-deny-sub".to_string(),
                description: "Deny subdirectory".to_string(),
                decision: Decision::Deny,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", sub_dir.display()),
                priority: 10,
            });
        harness.policy_engine.add_policy(policy).unwrap();

        // Read in sub must be Denied because sub_dir is more specific
        let req_sub = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: file_in_sub.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-026-SUB-DENY");
        let report_sub = harness.execute_request(req_sub);
        assert_eq!(
            report_sub.decision,
            Decision::Deny,
            "Deny subdirectory inside Allow parent must resolve to Deny"
        );
        assert_eq!(report_sub.observed_result, ObservedResult::BlockedByFirewall);

        // Read in parent must be Allowed because only parent rule matches
        let req_parent = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: file_in_parent.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-026-PARENT-ALLOW");
        let report_parent = harness.execute_request(req_parent);
        assert_eq!(
            report_parent.decision,
            Decision::Allow,
            "Read in parent must resolve to Allow"
        );
        assert_eq!(report_parent.observed_result, ObservedResult::AccessSuccess);
    }

    // Case 2: Allow subdirectory inside Deny parent (equal priority 10)
    // Most specific rule (sub_dir) must win -> Allow.
    {
        harness.policy_engine.clear();
        let policy = Policy::new("policy-sub-allow", "Sub Allow", 1)
            .with_rule(PolicyRule {
                id: "rule-deny-parent".to_string(),
                description: "Deny parent directory".to_string(),
                decision: Decision::Deny,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", parent_dir.display()),
                priority: 10,
            })
            .with_rule(PolicyRule {
                id: "rule-allow-sub".to_string(),
                description: "Allow subdirectory".to_string(),
                decision: Decision::Allow,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", sub_dir.display()),
                priority: 10,
            });
        harness.policy_engine.add_policy(policy).unwrap();

        // Read in sub must be Allowed because sub_dir rule is more specific than parent rule
        let req_sub = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: file_in_sub.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-026-SUB-ALLOW");
        let report_sub = harness.execute_request(req_sub);
        assert_eq!(
            report_sub.decision,
            Decision::Allow,
            "Allow subdirectory inside Deny parent must resolve to Allow by specificity"
        );
        assert_eq!(report_sub.observed_result, ObservedResult::AccessSuccess);

        // Read in parent must be Denied because parent rule is Deny
        let req_parent = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: file_in_parent.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-026-PARENT-DENY");
        let report_parent = harness.execute_request(req_parent);
        assert_eq!(
            report_parent.decision,
            Decision::Deny,
            "Read in parent must resolve to Deny"
        );
        assert_eq!(report_parent.observed_result, ObservedResult::BlockedByFirewall);
    }

    // Case 3: Two equally-specific conflicting rules (equal priority 10)
    // Precedence is ambiguous: Deny must win fail-closed.
    {
        harness.policy_engine.clear();
        let policy = Policy::new("policy-conflict", "Conflict", 1)
            .with_rule(PolicyRule {
                id: "rule-allow-sub-conflict".to_string(),
                description: "Allow sub".to_string(),
                decision: Decision::Allow,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", sub_dir.display()),
                priority: 10,
            })
            .with_rule(PolicyRule {
                id: "rule-deny-sub-conflict".to_string(),
                description: "Deny sub".to_string(),
                decision: Decision::Deny,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", sub_dir.display()),
                priority: 10,
            });
        harness.policy_engine.add_policy(policy).unwrap();

        let req_sub = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: file_in_sub.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-026-AMBIGUOUS-DENY");
        let report_sub = harness.execute_request(req_sub);
        assert_eq!(
            report_sub.decision,
            Decision::Deny,
            "Equally-specific conflicting rules at equal priority must fail-closed to Deny"
        );
        assert_eq!(report_sub.observed_result, ObservedResult::BlockedByFirewall);
    }
}

// REGRESSION-027: Symlinked rule patterns.
// Patterns are resolved to their real canonical location at policy add time (Option 2).
// 1. A Deny rule written against a symlinked path still applies to the real target.
// 2. An Allow rule written against a symlinked path does NOT grant access to anything outside the resolved location.
// 3. A pattern whose symlink is later repointed does NOT silently widen an Allow.
#[test]
fn test_regression_027_symlinked_rule_patterns_resolved_at_load_time() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let real_denied = sandbox_root.join("real_denied");
    let real_allowed = sandbox_root.join("real_allowed");
    let other_dir = sandbox_root.join("other_dir");
    let symlinks_dir = sandbox_root.join("symlinks");
    fs::create_dir_all(&real_denied).expect("mkdir real_denied");
    fs::create_dir_all(&real_allowed).expect("mkdir real_allowed");
    fs::create_dir_all(&other_dir).expect("mkdir other_dir");
    fs::create_dir_all(&symlinks_dir).expect("mkdir symlinks_dir");

    let denied_file = real_denied.join("secret.txt");
    fs::write(&denied_file, "DENIED_SECRET_DATA").expect("write denied");

    let allowed_file = real_allowed.join("public.txt");
    fs::write(&allowed_file, "ALLOWED_PUBLIC_DATA").expect("write allowed");

    let other_file = other_dir.join("other.txt");
    fs::write(&other_file, "OTHER_DATA").expect("write other");

    let symlink_denied = symlinks_dir.join("link_denied");
    let symlink_allowed = symlinks_dir.join("link_allowed");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_denied, &symlink_denied).expect("symlink denied");
        std::os::unix::fs::symlink(&real_allowed, &symlink_allowed).expect("symlink allowed");
    }

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // 1. Deny rule written against a symlinked path still applies to the real target
    {
        harness.policy_engine.clear();
        let policy = Policy::new("p-symlink-deny", "Symlink Deny", 1)
            .with_rule(PolicyRule {
                id: "rule-allow-sandbox".to_string(),
                description: "Allow sandbox".to_string(),
                decision: Decision::Allow,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", sandbox_root.display()),
                priority: 10,
            })
            .with_rule(PolicyRule {
                id: "rule-deny-symlink".to_string(),
                description: "Deny via symlink".to_string(),
                decision: Decision::Deny,
                agent_pattern: "agent-001".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", symlink_denied.display()),
                priority: 10,
            });
        harness.policy_engine.add_policy(policy).unwrap();

        // Accessing the real target must be Denied
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: denied_file.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-027-DENY-REAL");
        let report = harness.execute_request(req);
        assert_eq!(
            report.decision,
            Decision::Deny,
            "Deny rule written against symlinked path must apply to real target"
        );
        assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    }

    // 2. Allow rule written against a symlinked path does NOT grant access to anything outside resolved location
    {
        harness.policy_engine.clear();
        let policy = Policy::new("p-symlink-allow", "Symlink Allow", 1).with_rule(PolicyRule {
            id: "rule-allow-symlink".to_string(),
            description: "Allow via symlink".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", symlink_allowed.display()),
            priority: 10,
        });
        harness.policy_engine.add_policy(policy).unwrap();

        // Access to allowed file via real path succeeds
        let req_allowed = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: allowed_file.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-027-ALLOW-REAL");
        let report_allowed = harness.execute_request(req_allowed);
        assert_eq!(report_allowed.decision, Decision::Allow);
        assert_eq!(report_allowed.observed_result, ObservedResult::AccessSuccess);

        // Access to other_file (outside resolved location) must be Denied fail-closed
        let req_outside = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: other_file.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-027-ALLOW-OUTSIDE");
        let report_outside = harness.execute_request(req_outside);
        assert_eq!(
            report_outside.decision,
            Decision::Deny,
            "Allow rule on symlinked path must NOT grant access outside the resolved location"
        );
        assert_eq!(report_outside.observed_result, ObservedResult::BlockedByFirewall);
    }

    // 3. A pattern whose symlink is later repointed does NOT silently widen an Allow
    {
        harness.policy_engine.clear();
        let real_narrow = sandbox_root.join("real_narrow");
        let real_wide = sandbox_root.join("real_wide");
        fs::create_dir_all(&real_narrow).expect("mkdir real_narrow");
        fs::create_dir_all(&real_wide).expect("mkdir real_wide");

        let narrow_file = real_narrow.join("narrow.txt");
        fs::write(&narrow_file, "NARROW_DATA").expect("write narrow");
        let wide_file = real_wide.join("wide_secret.txt");
        fs::write(&wide_file, "WIDE_CONFIDENTIAL_DATA").expect("write wide");

        let symlink_switchable = symlinks_dir.join("link_switchable");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_narrow, &symlink_switchable).expect("symlink narrow");

        // Rule written against symlink pointing to real_narrow
        let policy = Policy::new("p-switchable", "Switchable", 1).with_rule(PolicyRule {
            id: "rule-allow-switchable".to_string(),
            description: "Allow switchable".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", symlink_switchable.display()),
            priority: 10,
        });
        harness.policy_engine.add_policy(policy).unwrap();

        // Initially reading narrow file is Allowed
        let req_narrow = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: narrow_file.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-027-NARROW-INIT");
        let report_narrow = harness.execute_request(req_narrow);
        assert_eq!(report_narrow.decision, Decision::Allow);

        // Repoint symlink: symlink_switchable now points to real_wide!
        #[cfg(unix)]
        {
            fs::remove_file(&symlink_switchable).expect("remove symlink");
            std::os::unix::fs::symlink(&real_wide, &symlink_switchable).expect("repoint symlink to wide");
        }

        // Reading wide_file must still be DENIED because the pattern was resolved and bound at load time!
        let req_wide = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: wide_file.to_str().unwrap().to_string(),
            },
        ).with_test_id("REGRESSION-027-WIDE-DENIED");
        let report_wide = harness.execute_request(req_wide);
        assert_eq!(
            report_wide.decision,
            Decision::Deny,
            "Repointing a rule pattern's symlink must NOT silently widen the Allow rule"
        );
        assert_eq!(report_wide.observed_result, ObservedResult::BlockedByFirewall);
    }
}

// REGRESSION-028: Rule with unresolvable pattern (e.g. symlink loop in pattern) is rejected at load time.
#[test]
fn test_regression_028_unresolvable_rule_pattern_rejected_at_load_time() {
    let temp = tempdir().expect("tempdir failed");
    let loop_a = temp.path().join("pattern_loop_a");
    let loop_b = temp.path().join("pattern_loop_b");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&loop_b, &loop_a).expect("symlink a");
        std::os::unix::fs::symlink(&loop_a, &loop_b).expect("symlink b");
    }

    let valid_dir = temp.path().join("valid");
    fs::create_dir_all(&valid_dir).expect("mkdir valid");
    let valid_file = valid_dir.join("valid.txt");
    fs::write(&valid_file, "VALID").expect("write valid");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(temp.path());

    // Policy has a rule with a loop in the resource_pattern
    let policy = Policy::new("p-bad-pattern", "Bad Pattern", 1).with_rule(PolicyRule {
        id: "rule-bad-loop".to_string(),
        description: "Rule with symlink loop pattern".to_string(),
        decision: Decision::Allow,
        agent_pattern: "agent-001".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", loop_a.display()),
        priority: 10,
    });
    // Add policy: unresolvable rule must be rejected at load time
    let res = harness.policy_engine.add_policy(policy);
    assert!(
        res.is_err(),
        "Policy with unresolvable rule pattern must fail to load atomically"
    );
    let err: PolicyLoadError = res.unwrap_err();
    assert_eq!(err.policy_id(), Some("p-bad-pattern"));
    assert_eq!(err.rule_id(), Some("rule-bad-loop"));

    // Request should receive default Deny because the entire policy was rejected
    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: valid_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-028-REJECTED-RULE");
    let report = harness.execute_request(req);
    assert_eq!(
        report.decision,
        Decision::Deny,
        "Policy with unresolvable rule pattern must fail-closed to Deny"
    );
    assert_eq!(report.policy, "default-fail-closed");
}

// REGRESSION-029: Never drop a Deny rule silently.
// If ANY rule in a policy fails to resolve, reject the WHOLE policy, load nothing from it,
// and leave previously loaded policies untouched.

#[test]
fn test_regression_029_leading_space_pattern_rejects_whole_policy_and_denies() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let secret_dir = sandbox_root.join("secret");
    fs::create_dir_all(&secret_dir).expect("mkdir secret");

    let secret_file = secret_dir.join("k.txt");
    fs::write(&secret_file, "SECRET_KEY").expect("write secret");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Case 1: Allow root/* at priority 10 + Deny leading-space secret/* at priority 100
    let policy = Policy::new("p-leading-space", "Leading Space Repro", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-root".to_string(),
            description: "Allow all under sandbox".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", sandbox_root.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-secret".to_string(),
            description: "Deny secret with leading space".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!(" {}/*", secret_dir.display()),
            priority: 100,
        });

    let load_res = harness.policy_engine.add_policy(policy);
    assert!(load_res.is_err(), "Must reject entire policy on leading-space rule pattern");
    let err = load_res.unwrap_err();
    assert_eq!(err.policy_id(), Some("p-leading-space"));
    assert_eq!(err.rule_id(), Some("rule-deny-secret"));

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: secret_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-LEADING-SPACE");

    let report = harness.execute_request(req);
    // On 7f98b41, rule-deny-secret was silently dropped, and rule-allow-root allowed the read!
    // With atomic loading, the policy must be rejected, and the request must be Denied.
    assert_eq!(
        report.decision,
        Decision::Deny,
        "Deny rule with leading space must NOT be silently dropped to allow access!"
    );
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(report.policy, "default-fail-closed");
}

#[test]
fn test_regression_029_trailing_space_pattern_rejects_whole_policy_and_denies() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let secret_dir = sandbox_root.join("secret");
    fs::create_dir_all(&secret_dir).expect("mkdir secret");

    let secret_file = secret_dir.join("k.txt");
    fs::write(&secret_file, "SECRET_KEY").expect("write secret");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Case 2: Allow root/* at priority 10 + Deny trailing-space secret/* at priority 100
    let policy = Policy::new("p-trailing-space", "Trailing Space Repro", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-root".to_string(),
            description: "Allow all under sandbox".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", sandbox_root.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-secret".to_string(),
            description: "Deny secret with trailing space".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/* ", secret_dir.display()),
            priority: 100,
        });

    let load_res = harness.policy_engine.add_policy(policy);
    assert!(load_res.is_err(), "Must reject entire policy on trailing-space rule pattern");
    let err = load_res.unwrap_err();
    assert_eq!(err.policy_id(), Some("p-trailing-space"));
    assert_eq!(err.rule_id(), Some("rule-deny-secret"));

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: secret_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-TRAILING-SPACE");

    let report = harness.execute_request(req);
    assert_eq!(
        report.decision,
        Decision::Deny,
        "Deny rule with trailing space must NOT be silently dropped to allow access!"
    );
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(report.policy, "default-fail-closed");
}

#[test]
fn test_regression_029_symlink_loop_pattern_rejects_whole_policy_and_denies() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let secret_dir = sandbox_root.join("secret");
    fs::create_dir_all(&secret_dir).expect("mkdir secret");

    let secret_file = secret_dir.join("k.txt");
    fs::write(&secret_file, "SECRET_KEY").expect("write secret");

    let loop_a = temp.path().join("loop_pattern_a");
    let loop_b = temp.path().join("loop_pattern_b");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&loop_b, &loop_a).expect("symlink a");
        std::os::unix::fs::symlink(&loop_a, &loop_b).expect("symlink b");
    }

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Case 3: Allow root/* at priority 10 + Deny symlink-loop pattern at priority 100
    let policy = Policy::new("p-symlink-loop", "Symlink Loop Repro", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-root".to_string(),
            description: "Allow all under sandbox".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", sandbox_root.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-loop".to_string(),
            description: "Deny pattern containing symlink loop".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", loop_a.display()),
            priority: 100,
        });

    let load_res = harness.policy_engine.add_policy(policy);
    assert!(load_res.is_err(), "Must reject entire policy on symlink-loop rule pattern");
    let err = load_res.unwrap_err();
    assert_eq!(err.policy_id(), Some("p-symlink-loop"));
    assert_eq!(err.rule_id(), Some("rule-deny-loop"));

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: secret_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-SYMLINK-LOOP");

    let report = harness.execute_request(req);
    assert_eq!(
        report.decision,
        Decision::Deny,
        "Deny rule with symlink loop must NOT be silently dropped to allow access!"
    );
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(report.policy, "default-fail-closed");
}

#[test]
fn test_regression_029_null_byte_pattern_rejects_whole_policy_and_denies() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let secret_dir = sandbox_root.join("secret");
    fs::create_dir_all(&secret_dir).expect("mkdir secret");

    let secret_file = secret_dir.join("k.txt");
    fs::write(&secret_file, "SECRET_KEY").expect("write secret");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Case 4: Allow root/* at priority 10 + Deny null-byte pattern at priority 100
    let policy = Policy::new("p-null-byte", "Null Byte Repro", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-root".to_string(),
            description: "Allow all under sandbox".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", sandbox_root.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-null".to_string(),
            description: "Deny pattern containing null byte".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}\0/*", secret_dir.display()),
            priority: 100,
        });

    let load_res = harness.policy_engine.add_policy(policy);
    assert!(load_res.is_err(), "Must reject entire policy on null-byte rule pattern");
    let err = load_res.unwrap_err();
    assert_eq!(err.policy_id(), Some("p-null-byte"));
    assert_eq!(err.rule_id(), Some("rule-deny-null"));

    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: secret_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-NULL-BYTE");

    let report = harness.execute_request(req);
    assert_eq!(
        report.decision,
        Decision::Deny,
        "Deny rule with null byte must NOT be silently dropped to allow access!"
    );
    assert_eq!(report.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(report.policy, "default-fail-closed");
}

#[test]
fn test_regression_029_rejected_policy_leaves_existing_valid_policy_in_force() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let public_dir = sandbox_root.join("public");
    let other_dir = sandbox_root.join("other");
    fs::create_dir_all(&public_dir).expect("mkdir public");
    fs::create_dir_all(&other_dir).expect("mkdir other");

    let public_file = public_dir.join("public.txt");
    let other_file = other_dir.join("other.txt");
    fs::write(&public_file, "PUBLIC_DATA").expect("write public");
    fs::write(&other_file, "OTHER_DATA").expect("write other");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // 1. Successfully load a valid policy
    let valid_policy = Policy::new("p-already-loaded", "Valid Active Policy", 1).with_rule(PolicyRule {
        id: "rule-allow-public".to_string(),
        description: "Allow public access".to_string(),
        decision: Decision::Allow,
        agent_pattern: "agent-001".to_string(),
        action_types: vec![ActionType::ReadFile],
        resource_pattern: format!("{}/*", public_dir.display()),
        priority: 10,
    });
    harness.policy_engine.add_policy(valid_policy).expect("load valid policy");

    let req_public = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: public_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-PUBLIC-INITIAL");
    let report_initial = harness.execute_request(req_public.clone());
    assert_eq!(report_initial.decision, Decision::Allow);
    assert_eq!(report_initial.policy, "p-already-loaded");

    // 2. Attempt to load an invalid policy with a bad rule pattern (leading space)
    let bad_policy = Policy::new("p-bad-rejected", "Rejected Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-other".to_string(),
            description: "Allow other".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", other_dir.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-bad-space".to_string(),
            description: "Bad space pattern".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: " /secret/*".to_string(),
            priority: 100,
        });

    let load_res = harness.policy_engine.add_policy(bad_policy);
    assert!(load_res.is_err(), "Rejected policy must return Err");

    // 3. The already-loaded policy must remain fully in force
    let report_after = harness.execute_request(req_public);
    assert_eq!(
        report_after.decision,
        Decision::Allow,
        "Existing valid policy must remain intact and in force after rejected policy"
    );
    assert_eq!(report_after.policy, "p-already-loaded");

    // 4. The rejected policy's rules were not registered (other file must Deny fail-closed)
    let req_other = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: other_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-OTHER-DENIED");
    let report_other = harness.execute_request(req_other);
    assert_eq!(
        report_other.decision,
        Decision::Deny,
        "Rules from rejected policy must not be active"
    );
    assert_eq!(report_other.policy, "default-fail-closed");
}

#[test]
fn test_regression_029_adversarial_last_rule_invalid_proves_no_partial_load() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let first_dir = sandbox_root.join("first");
    let second_dir = sandbox_root.join("second");
    let third_dir = sandbox_root.join("third");
    fs::create_dir_all(&first_dir).expect("mkdir first");
    fs::create_dir_all(&second_dir).expect("mkdir second");
    fs::create_dir_all(&third_dir).expect("mkdir third");

    let first_file = first_dir.join("file1.txt");
    let second_file = second_dir.join("file2.txt");
    fs::write(&first_file, "DATA_1").expect("write 1");
    fs::write(&second_file, "DATA_2").expect("write 2");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Policy where Rules 1 and 2 are completely valid, but the LAST rule (Rule 3) has an invalid pattern
    let policy = Policy::new("p-partial-adversarial", "Adversarial Partial Load Attempt", 1)
        .with_rule(PolicyRule {
            id: "rule-valid-1".to_string(),
            description: "Valid rule 1".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", first_dir.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-valid-2".to_string(),
            description: "Valid rule 2".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", second_dir.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-bad-last".to_string(),
            description: "Invalid last rule with leading space".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!(" {}/*", third_dir.display()),
            priority: 100,
        });

    let res = harness.policy_engine.add_policy(policy);
    assert!(
        res.is_err(),
        "Policy with invalid last rule must be completely rejected"
    );
    let err = res.unwrap_err();
    assert_eq!(err.policy_id(), Some("p-partial-adversarial"));
    assert_eq!(err.rule_id(), Some("rule-bad-last"));

    // Proving NO partial load occurred: requests matching rule-valid-1 and rule-valid-2 must be Denied
    let req1 = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: first_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-NO-PARTIAL-1");
    let report1 = harness.execute_request(req1);
    assert_eq!(
        report1.decision,
        Decision::Deny,
        "Rule 1 must NOT have been partially loaded into engine!"
    );
    assert_eq!(report1.policy, "default-fail-closed");

    let req2 = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: second_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-029-NO-PARTIAL-2");
    let report2 = harness.execute_request(req2);
    assert_eq!(
        report2.decision,
        Decision::Deny,
        "Rule 2 must NOT have been partially loaded into engine!"
    );
    assert_eq!(report2.policy, "default-fail-closed");
}

// REGRESSION-030: Path normalization edge cases in policy engine rule matching.
// Verifies that trailing slashes, repeated slashes, and `.` segments cannot be used
// to make a path look different from its canonical form at rule-matching time.

#[test]
fn test_regression_030_exact_rule_trailing_and_repeated_slashes_match_clean_form() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    fs::create_dir_all(&sandbox_root).expect("mkdir sandbox");

    let target_file = sandbox_root.join("data.txt");
    fs::write(&target_file, "AUTHORIZED_PAYLOAD").expect("write data");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    let clean_path = target_file.to_str().unwrap().to_string();

    // Exact-path rule matching target_file
    let policy = Policy::new("p-exact-normalize", "Exact Path Normalization", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-data-exact".to_string(),
            description: "Allow exact data file".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: clean_path.clone(),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy).expect("load policy");

    // 1. Clean form
    let req_clean = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: clean_path.clone(),
        },
    ).with_test_id("REGRESSION-030-CLEAN");
    let eval_clean = harness.policy_engine.evaluate(&req_clean);
    assert_eq!(eval_clean.decision, Decision::Allow);
    assert_eq!(eval_clean.matched_policy_id, "p-exact-normalize");
    assert_eq!(eval_clean.reason.rule_id.as_deref(), Some("rule-allow-data-exact"));

    // 2. Trailing slash variant on file
    let req_trailing = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: format!("{}/", clean_path),
        },
    ).with_test_id("REGRESSION-030-TRAILING-SLASH");
    let eval_trailing = harness.policy_engine.evaluate(&req_trailing);
    assert_eq!(
        eval_trailing.decision,
        Decision::Allow,
        "Trailing slash variant must match the exact same rule as clean form"
    );
    assert_eq!(eval_trailing.matched_policy_id, "p-exact-normalize");
    assert_eq!(eval_trailing.reason.rule_id.as_deref(), Some("rule-allow-data-exact"));
    assert_eq!(eval_trailing.resolved_resource, eval_clean.resolved_resource);

    // 3. Multiple trailing slashes variant
    let req_multi_trailing = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: format!("{}///", clean_path),
        },
    ).with_test_id("REGRESSION-030-MULTI-TRAILING");
    let eval_multi_trailing = harness.policy_engine.evaluate(&req_multi_trailing);
    assert_eq!(eval_multi_trailing.decision, Decision::Allow);
    assert_eq!(eval_multi_trailing.matched_policy_id, "p-exact-normalize");
    assert_eq!(eval_multi_trailing.reason.rule_id.as_deref(), Some("rule-allow-data-exact"));
    assert_eq!(eval_multi_trailing.resolved_resource, eval_clean.resolved_resource);

    // 4. Repeated slashes variant
    let repeated_slash_path = format!("{}///data.txt", sandbox_root.display());
    let req_rep = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: repeated_slash_path,
        },
    ).with_test_id("REGRESSION-030-REPEATED-SLASH");
    let eval_rep = harness.policy_engine.evaluate(&req_rep);
    assert_eq!(
        eval_rep.decision,
        Decision::Allow,
        "Repeated slash variant must match the exact same rule as clean form"
    );
    assert_eq!(eval_rep.matched_policy_id, "p-exact-normalize");
    assert_eq!(eval_rep.reason.rule_id.as_deref(), Some("rule-allow-data-exact"));
    assert_eq!(eval_rep.resolved_resource, eval_clean.resolved_resource);

    // 5. Dot segments variant
    let dot_segment_path = format!("{}/./data.txt", sandbox_root.display());
    let req_dot = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: dot_segment_path,
        },
    ).with_test_id("REGRESSION-030-DOT-SEGMENT");
    let eval_dot = harness.policy_engine.evaluate(&req_dot);
    assert_eq!(eval_dot.decision, Decision::Allow);
    assert_eq!(eval_dot.matched_policy_id, "p-exact-normalize");
    assert_eq!(eval_dot.reason.rule_id.as_deref(), Some("rule-allow-data-exact"));
    assert_eq!(eval_dot.resolved_resource, eval_clean.resolved_resource);

    // 6. Combined variant (multiple leading slashes, dot segments, repeated slashes, trailing slash)
    let combined_path = format!("///{}///./data.txt///", sandbox_root.display().to_string().trim_start_matches('/'));
    let req_comb = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: combined_path,
        },
    ).with_test_id("REGRESSION-030-COMBINED");
    let eval_comb = harness.policy_engine.evaluate(&req_comb);
    assert_eq!(eval_comb.decision, Decision::Allow);
    assert_eq!(eval_comb.matched_policy_id, "p-exact-normalize");
    assert_eq!(eval_comb.reason.rule_id.as_deref(), Some("rule-allow-data-exact"));
    assert_eq!(eval_comb.resolved_resource, eval_clean.resolved_resource);
}

#[test]
fn test_regression_030_prefix_rule_trailing_and_repeated_slashes_match_clean_form() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let public_dir = sandbox_root.join("public");
    let sub_dir = public_dir.join("sub");
    fs::create_dir_all(&sub_dir).expect("mkdir sub");

    let file_in_sub = sub_dir.join("nested.txt");
    fs::write(&file_in_sub, "NESTED_PUBLIC_DATA").expect("write nested");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Prefix rule for public directory
    let policy = Policy::new("p-prefix-normalize", "Prefix Normalization", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-public-prefix".to_string(),
            description: "Allow all under public".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", public_dir.display()),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy).expect("load policy");

    let clean_file_path = file_in_sub.to_str().unwrap().to_string();

    // 1. Clean file path
    let req_clean = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: clean_file_path.clone(),
        },
    ).with_test_id("REGRESSION-030-PREFIX-CLEAN");
    let eval_clean = harness.policy_engine.evaluate(&req_clean);
    assert_eq!(eval_clean.decision, Decision::Allow);
    assert_eq!(eval_clean.matched_policy_id, "p-prefix-normalize");
    assert_eq!(eval_clean.reason.rule_id.as_deref(), Some("rule-allow-public-prefix"));

    // 2. Trailing slash on file under prefix
    let req_trailing_file = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: format!("{}/", clean_file_path),
        },
    ).with_test_id("REGRESSION-030-PREFIX-TRAILING-FILE");
    let eval_trailing_file = harness.policy_engine.evaluate(&req_trailing_file);
    assert_eq!(eval_trailing_file.decision, Decision::Allow);
    assert_eq!(eval_trailing_file.matched_policy_id, "p-prefix-normalize");
    assert_eq!(eval_trailing_file.reason.rule_id.as_deref(), Some("rule-allow-public-prefix"));
    assert_eq!(eval_trailing_file.resolved_resource, eval_clean.resolved_resource);

    // 3. Repeated slashes in file path under prefix
    let rep_file_path = format!("{}///sub////nested.txt", public_dir.display());
    let req_rep_file = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: rep_file_path,
        },
    ).with_test_id("REGRESSION-030-PREFIX-REP-FILE");
    let eval_rep_file = harness.policy_engine.evaluate(&req_rep_file);
    assert_eq!(eval_rep_file.decision, Decision::Allow);
    assert_eq!(eval_rep_file.matched_policy_id, "p-prefix-normalize");
    assert_eq!(eval_rep_file.reason.rule_id.as_deref(), Some("rule-allow-public-prefix"));
    assert_eq!(eval_rep_file.resolved_resource, eval_clean.resolved_resource);

    // 4. Directory target clean form vs trailing slash variants
    let clean_dir_path = sub_dir.to_str().unwrap().to_string();
    let req_clean_dir = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: clean_dir_path.clone(),
        },
    ).with_test_id("REGRESSION-030-DIR-CLEAN");
    let eval_clean_dir = harness.policy_engine.evaluate(&req_clean_dir);
    assert_eq!(eval_clean_dir.decision, Decision::Allow);
    assert_eq!(eval_clean_dir.reason.rule_id.as_deref(), Some("rule-allow-public-prefix"));

    let req_trailing_dir = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: format!("{}/", clean_dir_path),
        },
    ).with_test_id("REGRESSION-030-DIR-TRAILING");
    let eval_trailing_dir = harness.policy_engine.evaluate(&req_trailing_dir);
    assert_eq!(
        eval_trailing_dir.decision,
        Decision::Allow,
        "Directory path with trailing slash must match identical prefix rule"
    );
    assert_eq!(eval_trailing_dir.reason.rule_id.as_deref(), Some("rule-allow-public-prefix"));
    assert_eq!(eval_trailing_dir.resolved_resource, eval_clean_dir.resolved_resource);

    let req_multi_slash_dir = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: format!("{}///sub///", public_dir.display()),
        },
    ).with_test_id("REGRESSION-030-DIR-MULTI-SLASH");
    let eval_multi_slash_dir = harness.policy_engine.evaluate(&req_multi_slash_dir);
    assert_eq!(eval_multi_slash_dir.decision, Decision::Allow);
    assert_eq!(eval_multi_slash_dir.reason.rule_id.as_deref(), Some("rule-allow-public-prefix"));
    assert_eq!(eval_multi_slash_dir.resolved_resource, eval_clean_dir.resolved_resource);
}

#[test]
fn test_regression_030_deny_rule_cannot_be_bypassed_via_slashes_or_dots() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let secret_dir = sandbox_root.join("secret");
    fs::create_dir_all(&secret_dir).expect("mkdir secret");

    let secret_file = secret_dir.join("passwords.txt");
    fs::write(&secret_file, "CONFIDENTIAL_KEY").expect("write secret");

    let exact_secret = sandbox_root.join("exact_secret.txt");
    fs::write(&exact_secret, "CONFIDENTIAL_EXACT").expect("write exact secret");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Policy: Allow all under sandbox at priority 10, but Deny secret at priority 100
    let policy = Policy::new("p-deny-bypass-test", "Deny Bypass Normalization Test", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox".to_string(),
            description: "Allow sandbox root".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", sandbox_root.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-secret-prefix".to_string(),
            description: "Deny secret prefix".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", secret_dir.display()),
            priority: 100,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-exact-file".to_string(),
            description: "Deny exact secret file".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: exact_secret.to_str().unwrap().to_string(),
            priority: 100,
        });

    harness.policy_engine.add_policy(policy).expect("load policy");

    let clean_secret_path = secret_file.to_str().unwrap().to_string();

    // 1. Clean form targeting prefix-denied resource
    let req_clean = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: clean_secret_path.clone(),
        },
    ).with_test_id("REGRESSION-030-DENY-CLEAN");
    let eval_clean = harness.policy_engine.evaluate(&req_clean);
    assert_eq!(eval_clean.decision, Decision::Deny);
    assert_eq!(eval_clean.reason.rule_id.as_deref(), Some("rule-deny-secret-prefix"));

    // 2. Trailing slash attempt against prefix-denied resource
    let req_trailing = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: format!("{}/", clean_secret_path),
        },
    ).with_test_id("REGRESSION-030-DENY-TRAILING");
    let eval_trailing = harness.policy_engine.evaluate(&req_trailing);
    assert_eq!(
        eval_trailing.decision,
        Decision::Deny,
        "Trailing slash variant must NOT bypass prefix Deny rule!"
    );
    assert_eq!(eval_trailing.reason.rule_id.as_deref(), Some("rule-deny-secret-prefix"));

    // 3. Repeated slashes attempt against prefix-denied resource
    let rep_secret_path = format!("{}///secret////passwords.txt", sandbox_root.display());
    let req_rep = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: rep_secret_path,
        },
    ).with_test_id("REGRESSION-030-DENY-REPEATED");
    let eval_rep = harness.policy_engine.evaluate(&req_rep);
    assert_eq!(
        eval_rep.decision,
        Decision::Deny,
        "Repeated slash variant must NOT bypass prefix Deny rule!"
    );
    assert_eq!(eval_rep.reason.rule_id.as_deref(), Some("rule-deny-secret-prefix"));

    // 4. Dot segments attempt against prefix-denied resource
    let dot_secret_path = format!("{}/./secret/./passwords.txt", sandbox_root.display());
    let req_dot = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: dot_secret_path,
        },
    ).with_test_id("REGRESSION-030-DENY-DOT");
    let eval_dot = harness.policy_engine.evaluate(&req_dot);
    assert_eq!(
        eval_dot.decision,
        Decision::Deny,
        "Dot segment variant must NOT bypass prefix Deny rule!"
    );
    assert_eq!(eval_dot.reason.rule_id.as_deref(), Some("rule-deny-secret-prefix"));

    // 5. Combined attempt against exact-denied file
    let clean_exact_path = exact_secret.to_str().unwrap().to_string();
    let comb_exact_path = format!("{}///./exact_secret.txt///", sandbox_root.display());
    let req_comb_exact = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: comb_exact_path,
        },
    ).with_test_id("REGRESSION-030-DENY-EXACT-COMBINED");
    let eval_comb_exact = harness.policy_engine.evaluate(&req_comb_exact);
    assert_eq!(
        eval_comb_exact.decision,
        Decision::Deny,
        "Combined slash/dot variant must NOT bypass exact Deny rule!"
    );
    assert_eq!(eval_comb_exact.reason.rule_id.as_deref(), Some("rule-deny-exact-file"));

    let eval_clean_exact = harness.policy_engine.evaluate(&ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: clean_exact_path,
        },
    ));
    assert_eq!(eval_comb_exact.resolved_resource, eval_clean_exact.resolved_resource);
}

#[test]
fn test_regression_030_rule_patterns_with_redundant_slashes_match_clean_requests() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let public_dir = sandbox_root.join("public");
    let sub_dir = public_dir.join("sub");
    fs::create_dir_all(&sub_dir).expect("mkdir sub");

    let test_file = public_dir.join("test.txt");
    fs::write(&test_file, "DATA").expect("write test");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    // Rule patterns defined with redundant slashes:
    // 1. Prefix rule with repeated slashes and trailing slashes before wildcard: "///sandbox///public///*"
    // 2. Exact directory rule with trailing slash: "/sandbox/public/sub/"
    let pattern_with_slashes = format!("///{}///public///*", sandbox_root.display().to_string().trim_start_matches('/'));
    let exact_dir_trailing = format!("{}/", sub_dir.display());

    let policy = Policy::new("p-pattern-slashes", "Redundant Slashes in Pattern", 1)
        .with_rule(PolicyRule {
            id: "rule-prefix-slashes".to_string(),
            description: "Prefix rule with redundant slashes".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: pattern_with_slashes,
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-exact-dir-trailing".to_string(),
            description: "Exact directory with trailing slash".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: exact_dir_trailing,
            priority: 20,
        });

    assert!(
        harness.policy_engine.add_policy(policy).is_ok(),
        "Policy rules with redundant slashes must be canonicalized and successfully loaded"
    );

    // Clean request matches rule defined with redundant slashes
    let req_file = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: test_file.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-030-CLEAN-REQ-MATCHES-SLASH-PATTERN");
    let eval_file = harness.policy_engine.evaluate(&req_file);
    assert_eq!(eval_file.decision, Decision::Allow);
    assert_eq!(eval_file.reason.rule_id.as_deref(), Some("rule-prefix-slashes"));

    // Clean directory request matches exact directory rule defined with trailing slash
    let req_dir = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: sub_dir.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-030-CLEAN-DIR-MATCHES-TRAILING-SLASH-PATTERN");
    let eval_dir = harness.policy_engine.evaluate(&req_dir);
    assert_eq!(eval_dir.decision, Decision::Allow);
    assert_eq!(eval_dir.reason.rule_id.as_deref(), Some("rule-exact-dir-trailing"));
}

#[test]
fn test_regression_030_non_existent_file_normalization_variants_match_same_rule() {
    let temp = tempdir().expect("tempdir failed");
    let sandbox_root = temp.path().join("sandbox");
    let write_dir = sandbox_root.join("output");
    fs::create_dir_all(&write_dir).expect("mkdir output");

    let harness = SecurityTestHarness::new();
    harness.fs_enforcer.register_sandbox_root(&sandbox_root);

    let policy = Policy::new("p-write-normalize", "Write Normalization", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-write".to_string(),
            description: "Allow write to output".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::WriteFile],
            resource_pattern: format!("{}/*", write_dir.display()),
            priority: 10,
        });

    harness.policy_engine.add_policy(policy).expect("load policy");

    let clean_non_existent = format!("{}/new_report.txt", write_dir.display());
    let rep_non_existent = format!("{}///output////new_report.txt", sandbox_root.display());
    let dot_non_existent = format!("{}/./output/./new_report.txt", sandbox_root.display());
    let trailing_non_existent = format!("{}/new_report.txt/", write_dir.display());

    let eval_clean = harness.policy_engine.evaluate(&ActionRequest::new(
        "agent-001",
        ActionPayload::WriteFile {
            path: clean_non_existent.clone(),
            content: "REPORT".to_string(),
        },
    ));
    assert_eq!(eval_clean.decision, Decision::Allow);
    assert_eq!(eval_clean.reason.rule_id.as_deref(), Some("rule-allow-write"));

    let eval_rep = harness.policy_engine.evaluate(&ActionRequest::new(
        "agent-001",
        ActionPayload::WriteFile {
            path: rep_non_existent,
            content: "REPORT".to_string(),
        },
    ));
    assert_eq!(eval_rep.decision, Decision::Allow);
    assert_eq!(eval_rep.reason.rule_id.as_deref(), Some("rule-allow-write"));
    assert_eq!(eval_rep.resolved_resource, eval_clean.resolved_resource);

    let eval_dot = harness.policy_engine.evaluate(&ActionRequest::new(
        "agent-001",
        ActionPayload::WriteFile {
            path: dot_non_existent,
            content: "REPORT".to_string(),
        },
    ));
    assert_eq!(eval_dot.decision, Decision::Allow);
    assert_eq!(eval_dot.reason.rule_id.as_deref(), Some("rule-allow-write"));
    assert_eq!(eval_dot.resolved_resource, eval_clean.resolved_resource);

    let eval_trailing = harness.policy_engine.evaluate(&ActionRequest::new(
        "agent-001",
        ActionPayload::WriteFile {
            path: trailing_non_existent,
            content: "REPORT".to_string(),
        },
    ));
    assert_eq!(eval_trailing.decision, Decision::Allow);
    assert_eq!(eval_trailing.reason.rule_id.as_deref(), Some("rule-allow-write"));
    assert_eq!(eval_trailing.resolved_resource, eval_clean.resolved_resource);
}

// ============================================================================
// REGRESSION-031: Case & Unicode normalization sensitivity and physical parent resolution
// ============================================================================

/// REGRESSION-031: Case and Unicode NFD variants of denied paths return no file content.
///
/// Verified fact: With Allow "<root>/*" and Deny "<root>/secret/*", a request for
/// "<root>/SECRET/k.txt" or for a Unicode NFD spelling of an NFC directory fails
/// byte-for-byte rule matching and falls through to the broad Allow rule, but the OS open
/// fails because the underlying filesystem is case and normalization sensitive.
/// This test pins that under no circumstances is file content returned.
#[test]
fn test_regression_031_denied_path_case_variant_and_unicode_nfd_variant_returns_no_content() {
    let harness = SecurityTestHarness::new();
    let temp = tempfile::tempdir().unwrap();
    let sandbox_root = temp.path().join("sandbox");
    let secret_dir = sandbox_root.join("secret");
    let unicode_secret_dir = sandbox_root.join("secr\u{00e9}t"); // Composed NFC: é (U+00E9)

    fs::create_dir_all(&secret_dir).unwrap();
    fs::create_dir_all(&unicode_secret_dir).unwrap();

    let secret_file_case = secret_dir.join("k.txt");
    let secret_file_unicode = unicode_secret_dir.join("k.txt");

    fs::write(&secret_file_case, "TOP_SECRET_CASE_PAYLOAD").unwrap();
    fs::write(&secret_file_unicode, "TOP_SECRET_UNICODE_PAYLOAD").unwrap();

    let canonical_root = sandbox_root.canonicalize().unwrap();
    harness.fs_enforcer.register_sandbox_root(&canonical_root);

    let root_str = canonical_root.to_str().unwrap();
    let policy = Policy::new("p-case-unicode", "Case and Unicode", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-sandbox".to_string(),
            description: "Allow sandbox".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", root_str),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-secret-case".to_string(),
            description: "Deny secret case".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/secret/*", root_str),
            priority: 20,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-secret-unicode".to_string(),
            description: "Deny secret unicode".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/secr\u{00e9}t/*", root_str),
            priority: 20,
        });

    harness.policy_engine.add_policy(policy).unwrap();

    // 1. Direct clean requests to the exact denied paths are explicitly blocked by policy
    let req_clean_case = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: secret_file_case.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-031-CLEAN-CASE");
    let eval_clean_case = harness.policy_engine.evaluate(&req_clean_case);
    assert_eq!(eval_clean_case.decision, Decision::Deny);
    let enf_clean_case = harness.fs_enforcer.enforce_read(&req_clean_case, &eval_clean_case);
    assert_eq!(enf_clean_case.enforcement_action, EnforcementAction::BlockRequest);
    assert_eq!(enf_clean_case.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(enf_clean_case.output, None);

    let req_clean_unicode = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: secret_file_unicode.to_str().unwrap().to_string(),
        },
    ).with_test_id("REGRESSION-031-CLEAN-UNICODE");
    let eval_clean_unicode = harness.policy_engine.evaluate(&req_clean_unicode);
    assert_eq!(eval_clean_unicode.decision, Decision::Deny);
    let enf_clean_unicode = harness.fs_enforcer.enforce_read(&req_clean_unicode, &eval_clean_unicode);
    assert_eq!(enf_clean_unicode.enforcement_action, EnforcementAction::BlockRequest);
    assert_eq!(enf_clean_unicode.observed_result, ObservedResult::BlockedByFirewall);
    assert_eq!(enf_clean_unicode.output, None);

    // 2. Request using case variant: "<root>/SECRET/k.txt"
    let case_variant_path = format!("{}/SECRET/k.txt", root_str);
    let req_case_variant = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: case_variant_path,
        },
    ).with_test_id("REGRESSION-031-CASE-VARIANT");
    let eval_case_variant = harness.policy_engine.evaluate(&req_case_variant);
    // Verified fact: Under Allow "<root>/*" and Deny "<root>/secret/*", "/SECRET/k.txt"
    // does not match Deny "/secret/*" byte-for-byte and falls through to Allow "<root>/*".
    assert_eq!(
        eval_case_variant.decision,
        Decision::Allow,
        "Case variant request evaluates to Allow due to byte-for-byte comparison"
    );

    let enf_case_variant = harness.fs_enforcer.enforce_read(&req_case_variant, &eval_case_variant);
    // Because this filesystem is case-sensitive, "/SECRET/k.txt" does not exist and openat2 fails (ENOENT)
    assert_eq!(
        enf_case_variant.observed_result,
        ObservedResult::AccessFailed,
        "Open fails with AccessFailed because file does not exist on case-sensitive filesystem"
    );
    assert_eq!(
        enf_case_variant.output, None,
        "Case variant returns NO file content"
    );

    // 3. Request using Unicode NFD variant: "<root>/secr{e\u{0301}}t/k.txt"
    // (decomposed NFD e + combining acute accent U+0301)
    let nfd_variant_path = format!("{}/secr{}t/k.txt", root_str, "e\u{0301}");
    let req_nfd_variant = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: nfd_variant_path,
        },
    ).with_test_id("REGRESSION-031-UNICODE-NFD-VARIANT");
    let eval_nfd_variant = harness.policy_engine.evaluate(&req_nfd_variant);
    // Verified fact: NFD variant does not match NFC Deny byte-for-byte and falls through to Allow
    assert_eq!(
        eval_nfd_variant.decision,
        Decision::Allow,
        "Unicode NFD variant evaluates to Allow due to byte-for-byte comparison"
    );

    let enf_nfd_variant = harness.fs_enforcer.enforce_read(&req_nfd_variant, &eval_nfd_variant);
    // Because this filesystem is normalization-sensitive, NFD path does not exist and openat2 fails
    assert_eq!(
        enf_nfd_variant.observed_result,
        ObservedResult::AccessFailed,
        "Open fails with AccessFailed on normalization-sensitive filesystem"
    );
    assert_eq!(
        enf_nfd_variant.output, None,
        "Unicode NFD variant returns NO file content"
    );
}

/// REGRESSION-031: A read through "link/../k.txt", where link points into a denied directory,
/// is evaluated against the physical parent and denied.
///
/// In lexical path resolution, "allowed/link/../k.txt" would cancel out "link/.." to "allowed/k.txt" (Allow).
/// In physical path resolution (Rule 4), symlinks are followed first. Following "link" enters
/// "denied/sub", and ".." ascends to "denied", resolving physically to "denied/k.txt".
/// The policy engine must evaluate this against the physical parent ("denied/k.txt") and Deny.
#[test]
fn test_regression_031_symlink_parent_traversal_evaluated_against_physical_parent_and_denied() {
    let harness = SecurityTestHarness::new();
    let temp = tempfile::tempdir().unwrap();
    let sandbox_root = temp.path().join("sandbox");
    let allowed_dir = sandbox_root.join("allowed");
    let denied_dir = sandbox_root.join("denied");
    let denied_sub = denied_dir.join("sub");

    fs::create_dir_all(&allowed_dir).unwrap();
    fs::create_dir_all(&denied_sub).unwrap();

    let denied_k = denied_dir.join("k.txt");
    fs::write(&denied_k, "TOP_SECRET_PHYSICAL_PARENT_DATA").unwrap();

    // Create symlink: allowed/link -> denied/sub
    let link_path = allowed_dir.join("link");
    std::os::unix::fs::symlink(&denied_sub, &link_path).unwrap();

    let canonical_root = sandbox_root.canonicalize().unwrap();
    harness.fs_enforcer.register_sandbox_root(&canonical_root);

    let root_str = canonical_root.to_str().unwrap();
    let policy = Policy::new("p-parent-symlink", "Parent Symlink", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-allowed".to_string(),
            description: "Allow allowed".to_string(),
            decision: Decision::Allow,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", allowed_dir.display()),
            priority: 10,
        })
        .with_rule(PolicyRule {
            id: "rule-deny-denied".to_string(),
            description: "Deny denied".to_string(),
            decision: Decision::Deny,
            agent_pattern: "agent-001".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: format!("{}/*", denied_dir.display()),
            priority: 20,
        });

    harness.policy_engine.add_policy(policy).unwrap();

    // Adversarial request: "allowed/link/../k.txt"
    // Lexically: "allowed/k.txt" (would match Allow policy!)
    // Physically: "denied/k.txt" (matches Deny policy!)
    let adversarial_path = format!("{}/allowed/link/../k.txt", root_str);
    let req = ActionRequest::new(
        "agent-001",
        ActionPayload::ReadFile {
            path: adversarial_path,
        },
    ).with_test_id("REGRESSION-031-PHYSICAL-PARENT-TRAVERSAL");

    let eval = harness.policy_engine.evaluate(&req);

    // Rule 4 requirement: Must be evaluated against real physical path, resolving to Deny
    assert_eq!(
        eval.decision,
        Decision::Deny,
        "Request through 'link/../k.txt' must be evaluated against physical parent and Denied"
    );

    // Verify resolved resource is indeed the physical parent target
    let canonical_denied_k = denied_k.canonicalize().unwrap();
    assert_eq!(
        eval.resolved_resource.as_deref(),
        canonical_denied_k.to_str(),
        "Resolved resource must equal canonical physical target 'denied/k.txt'"
    );

    let enf = harness.fs_enforcer.enforce_read(&req, &eval);
    assert_eq!(
        enf.enforcement_action,
        EnforcementAction::BlockRequest,
        "Enforcement must block access to physical parent target"
    );
    assert_eq!(
        enf.observed_result,
        ObservedResult::BlockedByFirewall,
        "Result must be BlockedByFirewall"
    );
    assert_eq!(
        enf.output, None,
        "No confidential data may be returned"
    );
}

/// REGRESSION-031: Verify filesystem folding probe on active root and ensure probe cleanup.
#[test]
fn test_regression_031_filesystem_folding_probe_passes_and_cleans_up() {
    let temp = tempfile::tempdir().unwrap();
    let sandbox_root = temp.path().join("probe_test_dir");
    fs::create_dir_all(&sandbox_root).unwrap();

    let probe = agnes_enforcement::DefaultFilesystemFoldingProbe;
    let res = agnes_enforcement::FilesystemFoldingProbe::detect_folding(&probe, &sandbox_root);
    assert!(
        res.is_ok(),
        "DefaultFilesystemFoldingProbe must pass on Linux non-folding filesystem: {:?}",
        res
    );

    // Verify that the temporary probe file was deleted and does not remain on disk
    let entries: Vec<_> = fs::read_dir(&sandbox_root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        entries.is_empty(),
        "Probe file must never remain on disk: found {:?}",
        entries
    );
}

/// REGRESSION-032: Crafted relative paths using `..` segments attempting to climb above the sandbox root
/// must be rejected before symlink resolution or kernel access, both under default policy and overly broad policy.
#[test]
fn test_regression_032_crafted_relative_path_climbing_above_sandbox_root_rejected() {
    let env = TestEnv::new("reg-032");
    let forbidden_file = env.forbidden_dir.join("secret.txt");
    fs::write(&forbidden_file, SECRET_CANARY_032).unwrap();

    let sub_dir = env.allowed_dir.join("sub").join("nested");
    fs::create_dir_all(&sub_dir).unwrap();

    // 1. Array of crafted relative paths attempting to climb above sandbox root
    let climbing_relative_vectors = vec![
        "sub/../../forbidden/secret.txt",
        "sub/nested/../../../forbidden/secret.txt",
        "../forbidden/secret.txt",
        "./sub/../../forbidden/secret.txt",
        "sub/..//../forbidden/secret.txt",
        "sub/nested/../../../../forbidden/secret.txt",
        "sub/nested/./../../..//forbidden/secret.txt",
        "sub/nested/../../..",
    ];

    for (idx, crafted_path) in climbing_relative_vectors.iter().enumerate() {
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: crafted_path.to_string(),
            },
        ).with_test_id(format!("REGRESSION-032-{}", idx));

        let report = env.harness.execute_request(req);
        assert_ne!(
            report.observed_result,
            ObservedResult::AccessSuccess,
            "Crafted relative path '{}' must NEVER succeed in accessing file",
            crafted_path
        );
        assert_eq!(
            report.observed_result,
            ObservedResult::BlockedByFirewall,
            "Crafted relative path '{}' must be BlockedByFirewall",
            crafted_path
        );
        assert!(
            !report.logs.contains(SECRET_CANARY_032),
            "Canary must not be leaked for '{}'",
            crafted_path
        );
    }

    // 2. Test under an overly broad wildcard policy ("*")
    // Confirms that even if PolicyEngine permits "*", the FilesystemEnforcer's lexical and
    // kernel boundary checks fail-closed and reject the crafted relative path attempt.
    let broad_harness = SecurityTestHarness::new();
    broad_harness.fs_enforcer.register_sandbox_root(&env.allowed_dir);
    let broad_policy = Policy::new("policy-broad-wildcard", "Wildcard Permissive Policy", 1)
        .with_rule(PolicyRule {
            id: "rule-allow-all".to_string(),
            description: "Overly broad allow all rule".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "*".to_string(),
            priority: 100,
        });
    broad_harness.policy_engine.add_policy(broad_policy).unwrap();

    for crafted_path in &climbing_relative_vectors {
        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: crafted_path.to_string(),
            },
        ).with_test_id("REGRESSION-032-BROAD");

        let report = broad_harness.execute_request(req);
        assert_ne!(
            report.observed_result,
            ObservedResult::AccessSuccess,
            "Wildcard policy must still be blocked by filesystem enforcer for '{}'",
            crafted_path
        );
        assert_eq!(
            report.observed_result,
            ObservedResult::BlockedByFirewall,
            "Enforcement must produce BlockedByFirewall under wildcard policy for '{}'",
            crafted_path
        );
        assert!(
            !report.logs.contains(SECRET_CANARY_032),
            "Canary must not be leaked under wildcard policy for '{}'",
            crafted_path
        );
    }
}










