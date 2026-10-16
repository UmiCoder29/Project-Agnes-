use agnes_common::{
    ActionPayload, ActionRequest, ActionType, Decision, ObservedResult,
};
use agnes_policy::{Policy, PolicyRule};
use agnes_tests::SecurityTestHarness;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

const FUZZ_SECRET_CANARY: &str = "AGNES_FUZZ_FORBIDDEN_CANARY_X999";

struct FuzzEnv {
    _temp: tempfile::TempDir,
    allowed_dir: PathBuf,
    forbidden_file: PathBuf,
    harness: SecurityTestHarness,
}

impl FuzzEnv {
    fn setup() -> Self {
        let temp = tempdir().expect("tempdir");
        let allowed_dir = temp.path().join("allowed_zone");
        let forbidden_dir = temp.path().join("forbidden_zone");
        fs::create_dir_all(&allowed_dir).unwrap();
        fs::create_dir_all(&forbidden_dir).unwrap();

        let forbidden_file = forbidden_dir.join("forbidden_secret.txt");
        fs::write(&forbidden_file, FUZZ_SECRET_CANARY).unwrap();

        let harness = SecurityTestHarness::new();
        harness.fs_enforcer.register_sandbox_root(&allowed_dir);

        let allowed_pattern = format!("{}/*", allowed_dir.display());
        let policy = Policy::new("fuzz-policy", "Fuzz Boundary Policy", 1)
            .with_rule(PolicyRule {
                id: "rule-fuzz-sandbox".to_string(),
                description: "Allow agent access only to allowed_zone".to_string(),
                decision: Decision::Allow,
                agent_pattern: "agent-fuzz".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: allowed_pattern,
                priority: 10,
            });

        harness.policy_engine.add_policy(policy).unwrap();

        Self {
            _temp: temp,
            allowed_dir,
            forbidden_file,
            harness,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct FuzzRecord {
    input_path: String,
    decision: Decision,
    enforcement_result: String,
    observed_result: ObservedResult,
    escape_occurred: bool,
}

#[test]
fn test_adversarial_filesystem_fuzzing() {
    let env = FuzzEnv::setup();

    // Setup complex nested directory structures inside allowed
    let deep_dir = env.allowed_dir.join("sub1").join("sub2").join("sub3");
    fs::create_dir_all(&deep_dir).unwrap();

    let safe_file = deep_dir.join("safe.txt");
    fs::write(&safe_file, "BENIGN_FUZZ_TARGET").unwrap();

    // Create a symlink to outside
    let bad_link = env.allowed_dir.join("bad_symlink");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&env.forbidden_file, &bad_link).unwrap();

    // Create a symlink to an internal file
    let good_link = env.allowed_dir.join("good_symlink");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&safe_file, &good_link).unwrap();

    let mut generator_inputs = Vec::new();

    // Combinations of traversal and separators
    let prefixes = [
        env.allowed_dir.to_str().unwrap(),
        deep_dir.to_str().unwrap(),
    ];

    let traversal_patterns = [
        "..",
        "../..",
        "../../..",
        "../../../..",
        "../../../../..",
        "../../../../../../../../etc",
        ".",
        "./.",
        "./..",
        "sub1/../../..",
        "sub1/sub2/../../../forbidden_zone",
        "//",
        "///",
        "/././",
        "/../",
    ];

    let targets = [
        "forbidden_secret.txt",
        "forbidden_zone/forbidden_secret.txt",
        "safe.txt",
        "nonexistent.txt",
    ];

    for prefix in &prefixes {
        for trav in &traversal_patterns {
            for target in &targets {
                generator_inputs.push(format!("{}/{}/{}", prefix, trav, target));
                generator_inputs.push(format!("{}//{}/{}", prefix, trav, target));
                generator_inputs.push(format!("{}/{}/.//{}", prefix, trav, target));
            }
        }
    }

    // Direct symlink tests
    generator_inputs.push(bad_link.to_str().unwrap().to_string());
    generator_inputs.push(format!("{}/..", bad_link.to_str().unwrap()));
    generator_inputs.push(good_link.to_str().unwrap().to_string());
    generator_inputs.push(format!("{}/.", good_link.to_str().unwrap()));

    // Relative path tests
    generator_inputs.push("../forbidden_zone/forbidden_secret.txt".to_string());
    generator_inputs.push("./bad_symlink".to_string());
    generator_inputs.push("bad_symlink".to_string());

    println!("\n=== RUNNING ADVERSARIAL FILESYSTEM FUZZING ({} test vectors) ===", generator_inputs.len());

    let mut fuzz_records: Vec<FuzzRecord> = Vec::new();
    let mut total_escapes = 0;

    for (idx, input_path) in generator_inputs.into_iter().enumerate() {
        let req = ActionRequest::new(
            "agent-fuzz",
            ActionPayload::ReadFile {
                path: input_path.clone(),
            },
        ).with_test_id(format!("FUZZ-{:04}", idx));

        let report = env.harness.execute_request(req);

        let escape_occurred = report.logs.contains(FUZZ_SECRET_CANARY);
        if escape_occurred {
            total_escapes += 1;
            eprintln!("CRITICAL FUZZ ESCAPE DETECTED for input: {}", input_path);
        }

        fuzz_records.push(FuzzRecord {
            input_path,
            decision: report.decision,
            enforcement_result: format!("{:?}", report.enforcement),
            observed_result: report.observed_result,
            escape_occurred,
        });
    }

    println!("Adversarial Fuzzing Complete. Total vectors evaluated: {}. Escapes: {}", fuzz_records.len(), total_escapes);

    // Verify zero escapes across all generated vectors
    assert_eq!(total_escapes, 0, "SUCCESS CRITERION VIOLATED: At least one unauthorized read succeeded!");
}
