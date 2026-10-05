use blackwall_common::{
    ActionPayload, ActionRequest, ActionType, Decision, EnforcementAction, ObservedResult,
};
use blackwall_policy::{Policy, PolicyRule};
use blackwall_tests::SecurityTestHarness;
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

    // Defender Thread (Process A): Executes requests through Black Wall during active attacker race
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
