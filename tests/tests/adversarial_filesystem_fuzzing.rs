use agnes_common::{
    ActionPayload, ActionRequest, ActionType, Decision, ObservedResult,
};
use agnes_policy::{
    resolve_real_path, resolve_request_target,
    Policy, PolicyEngine, PolicyRule,
};
use agnes_tests::SecurityTestHarness;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
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

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 60,
        max_shrink_iters: 500,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/proptest-regressions/adversarial_filesystem_fuzzing.txt",
        ))),
        .. ProptestConfig::default()
    })]

    // INVARIANT 1: No input makes resolve_real_path, resolve_request_target,
    // PolicyEngine::evaluate, or any rule matching function panic or hang.
    #[test]
    fn test_fuzz_property_1_no_panics_or_hangs_on_arbitrary_inputs(
        path in prop_oneof![
            3 => any::<String>(),
            2 => "[\\x00-\\x7F]{0,100}",
            2 => "[a-zA-Z0-9/._-]{1000,3000}",
            2 => "(?:/[a-zA-Z0-9_]{1,6}|/\\.\\.|/\\.|//){10,40}",
            1 => "[\\u{0000}-\\u{001F}\\u{007F}-\\u{009F}\\u{FEFF}\\u{FFFF}\\u{200B}]{1,20}",
        ]
    ) {
        let temp = tempdir().unwrap();
        let loop_a = temp.path().join("fuzz_loop_a");
        let loop_b = temp.path().join("fuzz_loop_b");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&loop_b, &loop_a);
            let _ = std::os::unix::fs::symlink(&loop_a, &loop_b);
        }

        let engine = PolicyEngine::new();
        let rule = PolicyRule {
            id: "r-fuzz".to_string(),
            description: "fuzz test rule".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile, ActionType::WriteFile],
            resource_pattern: "/sandbox/*".to_string(),
            priority: 10,
        };
        let _ = engine.add_policy(Policy::new("p-fuzz", "Fuzz", 1).with_rule(rule.clone()));

        // 1. resolve_real_path must never panic or hang
        let _ = resolve_real_path(&path);
        let loop_path = format!("{}/extra", loop_a.display());
        let _ = resolve_real_path(&loop_path);

        // 2. resolve_request_target must never panic or hang (ReadFile and WriteFile)
        let req_read = ActionRequest::new(
            "agent-fuzz",
            ActionPayload::ReadFile { path: path.clone() },
        );
        let _ = resolve_request_target(&req_read);

        let req_write = ActionRequest::new(
            "agent-fuzz",
            ActionPayload::WriteFile { path: path.clone(), content: "data".to_string() },
        );
        let _ = resolve_request_target(&req_write);

        // 3. PolicyEngine::evaluate must never panic or hang
        let _ = engine.evaluate(&req_read);
        let _ = engine.evaluate(&req_write);

        // 4. Rule matching functions must never panic or hang
        let _ = rule.matches_target(&req_read, &path);
        let _ = rule.matches_resource(&path);
    }

    // INVARIANT 2: resolve_real_path never returns Ok for a path with a null byte,
    // an empty string, leading or trailing whitespace, or a relative path.
    #[test]
    fn test_fuzz_property_2_resolve_real_path_rejects_null_empty_whitespace_relative(
        case in prop_oneof![
            1 => prop::string::string_regex(".{0,20}\\x00.{0,20}").unwrap(),
            1 => Just("".to_string()),
            1 => prop::string::string_regex("[ \t\r\n]+/[a-zA-Z0-9/._-]*").unwrap(),
            1 => prop::string::string_regex("/[a-zA-Z0-9/._-]*[ \t\r\n]+").unwrap(),
            1 => prop::string::string_regex("[a-zA-Z0-9._][a-zA-Z0-9/._-]{0,30}").unwrap(),
        ]
    ) {
        let res = resolve_real_path(&case);
        prop_assert!(
            res.is_err(),
            "resolve_real_path must never return Ok for invalid path {:?}, got {:?}",
            case,
            res
        );
    }

    // INVARIANT 3: Build a sandbox with an Allow on the root and a Deny on a secret directory,
    // including symlinks into the secret directory. For every generated path, if the decision
    // is Allow then the real path on disk must not be inside the secret directory (use canonicalize
    // on the generated path as the oracle, and treat disagreement as a bug).
    #[test]
    fn test_fuzz_property_3_sandbox_oracle_allow_never_accesses_secret_directory(
        segments in prop::collection::vec(
            prop_oneof![
                Just("safe.txt"),
                Just("sub"),
                Just("nested.txt"),
                Just("link_to_safe"),
                Just("link_to_secret_file"),
                Just("link_to_secret_dir"),
                Just("link_escape"),
                Just("loop_a"),
                Just("secret.txt"),
                Just(".."),
                Just("."),
                Just("secret"),
                Just("keys.txt"),
                Just("nonexistent.txt"),
            ],
            1..8
        )
    ) {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("sandbox");
        let secret_dir = temp.path().join("secret");
        fs::create_dir_all(&sandbox_dir).unwrap();
        fs::create_dir_all(sandbox_dir.join("sub")).unwrap();
        fs::create_dir_all(secret_dir.join("sub_secret")).unwrap();

        let safe_file = sandbox_dir.join("safe.txt");
        fs::write(&safe_file, "SAFE_CANARY").unwrap();
        let nested_file = sandbox_dir.join("sub").join("nested.txt");
        fs::write(&nested_file, "NESTED_CANARY").unwrap();

        let secret_file = secret_dir.join("secret.txt");
        fs::write(&secret_file, "SECRET_DATA").unwrap();
        let keys_file = secret_dir.join("sub_secret").join("keys.txt");
        fs::write(&keys_file, "KEYS_DATA").unwrap();

        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&safe_file, sandbox_dir.join("link_to_safe"));
            let _ = std::os::unix::fs::symlink(&secret_file, sandbox_dir.join("link_to_secret_file"));
            let _ = std::os::unix::fs::symlink(&secret_dir, sandbox_dir.join("link_to_secret_dir"));
            let _ = std::os::unix::fs::symlink(&secret_file, sandbox_dir.join("link_escape"));
            let _ = std::os::unix::fs::symlink(&secret_file, sandbox_dir.join("sub").join("link_escape"));

            let loop_a = sandbox_dir.join("loop_a");
            let loop_b = sandbox_dir.join("loop_b");
            let _ = std::os::unix::fs::symlink(&loop_b, &loop_a);
            let _ = std::os::unix::fs::symlink(&loop_a, &loop_b);
        }

        let canonical_sandbox = sandbox_dir.canonicalize().unwrap();
        let canonical_secret = secret_dir.canonicalize().unwrap();

        let engine = PolicyEngine::new();
        let policy = Policy::new("p-oracle", "Oracle Sandbox Policy", 1)
            .with_rule(PolicyRule {
                id: "r-allow-sandbox".to_string(),
                description: "Allow sandbox".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", canonical_sandbox.display()),
                priority: 10,
            })
            .with_rule(PolicyRule {
                id: "r-deny-secret".to_string(),
                description: "Deny secret".to_string(),
                decision: Decision::Deny,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", canonical_secret.display()),
                priority: 100,
            });
        engine.add_policy(policy).unwrap();

        let mut candidate_path = sandbox_dir.clone();
        for seg in segments {
            candidate_path.push(seg);
        }
        let candidate_str = candidate_path.to_string_lossy().to_string();

        let req = ActionRequest::new(
            "agent-oracle",
            ActionPayload::ReadFile { path: candidate_str.clone() },
        );

        let outcome = engine.evaluate(&req);

        // Security Invariant (Oracle):
        // If decision is Allow, then the real path on disk must NOT be inside the secret directory,
        // and MUST be within the approved sandbox.
        if outcome.decision == Decision::Allow {
            if let Ok(real_canon) = std::fs::canonicalize(&candidate_path) {
                prop_assert!(
                    !real_canon.starts_with(&canonical_secret),
                    "ORACLE VIOLATION: Path {:?} was ALLOWED but real path {:?} is inside secret dir {:?}",
                    candidate_str,
                    real_canon,
                    canonical_secret
                );
                prop_assert!(
                    real_canon.starts_with(&canonical_sandbox),
                    "Allowed path {:?} real path {:?} is outside sandbox {:?}",
                    candidate_str,
                    real_canon,
                    canonical_sandbox
                );
            }
        }
    }

    // INVARIANT 4: Slash, dot, and trailing slash variants of a path always get the same decision as the clean form.
    #[test]
    fn test_fuzz_property_4_slash_dot_variants_preserve_decision(
        extra_slashes in prop_oneof![
            Just("/"),
            Just("//"),
            Just("///"),
        ],
        internal_dots in prop_oneof![
            Just(""),
            Just("/."),
            Just("/./."),
            Just("/sub/.."),
        ],
        target_idx in 0..3usize
    ) {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("sandbox");
        fs::create_dir_all(sandbox_dir.join("sub")).unwrap();
        let safe_file = sandbox_dir.join("safe.txt");
        fs::write(&safe_file, "CONTENT").unwrap();
        let nested_file = sandbox_dir.join("sub").join("nested.txt");
        fs::write(&nested_file, "CONTENT2").unwrap();

        let canonical_sandbox = sandbox_dir.canonicalize().unwrap();
        let canonical_safe = safe_file.canonicalize().unwrap();
        let canonical_nested = nested_file.canonicalize().unwrap();
        let nonexistent_file = canonical_sandbox.join("nonexistent.txt");

        let engine = PolicyEngine::new();
        let policy = Policy::new("p-variants", "Variants Policy", 1)
            .with_rule(PolicyRule {
                id: "r-allow-safe".to_string(),
                description: "Allow safe".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: canonical_safe.to_string_lossy().to_string(),
                priority: 10,
            })
            .with_rule(PolicyRule {
                id: "r-allow-sub".to_string(),
                description: "Allow sub".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", canonical_sandbox.join("sub").display()),
                priority: 10,
            });
        engine.add_policy(policy).unwrap();

        let clean_targets = [
            canonical_safe.to_string_lossy().to_string(),
            canonical_nested.to_string_lossy().to_string(),
            nonexistent_file.to_string_lossy().to_string(),
        ];
        let clean_path = &clean_targets[target_idx];

        // Construct variant with redundant leading slashes and internal dots/slashes
        let mut variant_path = format!("{}{}", extra_slashes, clean_path.trim_start_matches('/'));
        if !internal_dots.is_empty() && variant_path.contains("/sub/") {
            variant_path = variant_path.replace("/sub/", &format!("/sub{}/", internal_dots));
        }

        let clean_req = ActionRequest::new("agent-1", ActionPayload::ReadFile { path: clean_path.clone() });
        let clean_decision = engine.evaluate(&clean_req).decision;

        let variant_req = ActionRequest::new("agent-1", ActionPayload::ReadFile { path: variant_path.clone() });
        let variant_decision = engine.evaluate(&variant_req).decision;

        // If the variant resolves to the same canonical path, decision must match clean form
        if let (Ok(clean_res), Ok(variant_res)) = (
            resolve_real_path(clean_path),
            resolve_real_path(&variant_path),
        ) {
            if clean_res == variant_res {
                prop_assert_eq!(
                    variant_decision,
                    clean_decision,
                    "Normalized variant {:?} resolved to {:?} but got decision {:?}, expected {:?}",
                    variant_path,
                    variant_res,
                    variant_decision,
                    clean_decision
                );
            }
        }
    }

    // INVARIANT 5: Rule matching never returns true when the target contains a null byte,
    // and an empty pattern matches nothing.
    #[test]
    fn test_fuzz_property_5_rule_matching_rejects_null_bytes_and_empty_patterns(
        target_prefix in prop_oneof![
            Just("/sandbox/allowed_file".to_string()),
            Just("/sandbox/sub/nested".to_string()),
            Just("/other/path".to_string()),
            "[a-zA-Z0-9/._-]{0,20}",
        ],
        target_suffix in "[a-zA-Z0-9/._-]{0,20}",
        pattern_kind_choice in 0..3usize
    ) {
        let valid_rule = PolicyRule {
            id: "r-valid".to_string(),
            description: "valid rule".to_string(),
            decision: Decision::Allow,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadFile],
            resource_pattern: "/sandbox/*".to_string(),
            priority: 10,
        };

        // 1. Any target containing a null byte MUST never match
        let target_with_null = format!("{}\0{}", target_prefix, target_suffix);
        let req = ActionRequest::new("agent-1", ActionPayload::ReadFile { path: "/sandbox/file.txt".to_string() });

        prop_assert!(
            !valid_rule.matches_target(&req, &target_with_null),
            "Rule matching must reject target containing null byte {:?}",
            target_with_null
        );

        // 2. An empty pattern in a rule matches nothing (fail-closed)
        let empty_rule = match pattern_kind_choice {
            0 => PolicyRule {
                id: "r-empty-resource".to_string(),
                description: "empty resource pattern".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: "".to_string(),
                priority: 10,
            },
            1 => PolicyRule {
                id: "r-empty-agent".to_string(),
                description: "empty agent pattern".to_string(),
                decision: Decision::Allow,
                agent_pattern: "".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: "/sandbox/*".to_string(),
                priority: 10,
            },
            _ => PolicyRule {
                id: "r-empty-actions".to_string(),
                description: "empty action types".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![],
                resource_pattern: "/sandbox/*".to_string(),
                priority: 10,
            },
        };

        let arbitrary_target = format!("/sandbox/{}", target_prefix);
        prop_assert!(
            !empty_rule.matches_target(&req, &arbitrary_target),
            "Empty pattern rule must never match any target {:?}",
            arbitrary_target
        );
    }

    // INVARIANT 6: Policy loading never leaves a partially loaded set: for any generated rule list
    // containing at least one bad rule, the engine's loaded set is unchanged.
    #[test]
    fn test_fuzz_property_6_atomic_policy_loading_never_leaves_partial_state(
        bad_pattern in prop_oneof![
            Just("/tmp/\0bad"),
            Just(" /tmp/bad"),
            Just("/tmp/bad "),
            Just(""),
        ]
    ) {
        let temp = tempdir().unwrap();
        let canonical_dir = temp.path().canonicalize().unwrap();

        let engine = PolicyEngine::new();

        // 1. Establish known baseline policy set
        let initial_policy = Policy::new("p-initial", "Initial Policy", 1)
            .with_rule(PolicyRule {
                id: "r-initial".to_string(),
                description: "Initial allow rule".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/*", canonical_dir.display()),
                priority: 10,
            });
        engine.add_policy(initial_policy).unwrap();

        let probe_file = canonical_dir.join("test.txt");
        let probe_str = probe_file.to_string_lossy().to_string();
        let probe_req = ActionRequest::new("agent-1", ActionPayload::ReadFile { path: probe_str.clone() });

        let baseline_eval = engine.evaluate(&probe_req);
        prop_assert_eq!(baseline_eval.decision, Decision::Allow);
        prop_assert_eq!(&baseline_eval.matched_policy_id, "p-initial");

        // 2. Candidate replacement set containing valid policies + one invalid rule
        let replacement_valid = Policy::new("p-new-valid", "New Valid", 1)
            .with_rule(PolicyRule {
                id: "r-new-allow".to_string(),
                description: "New allow".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/sub/*", canonical_dir.display()),
                priority: 50,
            });

        let replacement_bad = Policy::new("p-bad", "Bad Policy", 1)
            .with_rule(PolicyRule {
                id: "r-good".to_string(),
                description: "Good rule before bad rule".to_string(),
                decision: Decision::Allow,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: format!("{}/other/*", canonical_dir.display()),
                priority: 20,
            })
            .with_rule(PolicyRule {
                id: "r-bad".to_string(),
                description: "Bad pattern rule".to_string(),
                decision: Decision::Deny,
                agent_pattern: "*".to_string(),
                action_types: vec![ActionType::ReadFile],
                resource_pattern: bad_pattern.to_string(),
                priority: 100,
            });

        // 3. Attempt atomic replacement: MUST fail
        let res = engine.replace_policies(vec![replacement_valid, replacement_bad]);
        prop_assert!(res.is_err(), "Replacement with invalid rule must fail");

        // 4. Invariant: Active policy set must be 100% UNCHANGED (no partial load)
        let after_eval = engine.evaluate(&probe_req);
        prop_assert_eq!(after_eval.decision, baseline_eval.decision);
        prop_assert_eq!(after_eval.matched_policy_id, baseline_eval.matched_policy_id);
        prop_assert_eq!(after_eval.reason.rule_id, baseline_eval.reason.rule_id);
    }
}

#[test]
fn test_document_exclusion_non_file_spelling_variants_bypass_milestone_2() {
    // Documented limitation (Milestone 1 Scope):
    // Deny rules for non-file action types (URL, host, executable, secret) match exact text only.
    // Spelling variants (case variations, default ports, doubled slashes) do not match exact Deny rules.
    // Full semantic normalization of URLs, executable paths, and secret IDs is assigned to Milestone 2.
    let engine = PolicyEngine::new();

    let policy = Policy::new("p-non-file-limits", "Documented Non-File Limits", 1)
        .with_rule(PolicyRule {
            id: "r-deny-http-exact".to_string(),
            description: "Exact text Deny on sensitive internal endpoint".to_string(),
            decision: Decision::Deny,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::HttpRequest],
            resource_pattern: "https://api.internal.corp/v1/keys".to_string(),
            priority: 100,
        })
        .with_rule(PolicyRule {
            id: "r-deny-secret-exact".to_string(),
            description: "Exact text Deny on secret id".to_string(),
            decision: Decision::Deny,
            agent_pattern: "*".to_string(),
            action_types: vec![ActionType::ReadSecret],
            resource_pattern: "credentials/db_password".to_string(),
            priority: 100,
        });

    engine.add_policy(policy).unwrap();

    // 1. Exact matches strictly trigger the Deny rule
    let req_http_exact = ActionRequest::new(
        "agent-1",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://api.internal.corp/v1/keys".to_string(),
            headers: None,
            body: None,
        },
    );
    let eval_http_exact = engine.evaluate(&req_http_exact);
    assert_eq!(eval_http_exact.decision, Decision::Deny);
    assert_eq!(eval_http_exact.reason.rule_id.as_deref(), Some("r-deny-http-exact"));

    // 2. Spelling variants DO NOT match the exact text rule (documents Milestone 1 behavior)
    let req_http_case = ActionRequest::new(
        "agent-1",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://API.INTERNAL.CORP/v1/keys".to_string(),
            headers: None,
            body: None,
        },
    );
    let eval_http_case = engine.evaluate(&req_http_case);
    // Unmatched by the exact rule; falls through to default-fail-closed
    assert_ne!(eval_http_case.reason.rule_id.as_deref(), Some("r-deny-http-exact"));

    let req_http_port = ActionRequest::new(
        "agent-1",
        ActionPayload::HttpRequest {
            method: "GET".to_string(),
            url: "https://api.internal.corp:443/v1/keys".to_string(),
            headers: None,
            body: None,
        },
    );
    let eval_http_port = engine.evaluate(&req_http_port);
    assert_ne!(eval_http_port.reason.rule_id.as_deref(), Some("r-deny-http-exact"));

    let req_secret_slashes = ActionRequest::new(
        "agent-1",
        ActionPayload::ReadSecret {
            secret_id: "credentials//db_password".to_string(),
        },
    );
    let eval_secret_slashes = engine.evaluate(&req_secret_slashes);
    assert_ne!(eval_secret_slashes.reason.rule_id.as_deref(), Some("r-deny-secret-exact"));
}
