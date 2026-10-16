use agnes_common::{
    ActionPayload, ActionRequest, Decision, EnforcementAction, ObservedResult, PolicyDecisionResponse,
};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;
use tracing::{info, warn};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// Linux openat2 constants
const SYS_OPENAT2: libc::c_long = 437;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub enforcement_action: EnforcementAction,
    pub observed_result: ObservedResult,
    pub output: Option<String>,
    pub error_message: Option<String>,
}

/// Trait for probing whether a filesystem folds case or Unicode normalization forms.
/// Used at startup to verify sandbox roots are strictly on byte-exact, non-folding filesystems.
pub trait FilesystemFoldingProbe: Send + Sync {
    /// Probes the given canonical directory.
    /// Returns Ok(()) if the filesystem does not fold case or normalization.
    /// Returns Err(String) if folding was detected or probing was not possible.
    fn detect_folding(&self, root: &Path) -> Result<(), String>;
}

/// Production implementation of `FilesystemFoldingProbe`.
/// Creates a temporary probe file with ASCII letters and composed NFC characters,
/// and tests whether the case-swapped name or decomposed NFD-variant resolves to it.
/// If the directory is read-only, tests using an existing directory entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultFilesystemFoldingProbe;

impl FilesystemFoldingProbe for DefaultFilesystemFoldingProbe {
    fn detect_folding(&self, root: &Path) -> Result<(), String> {
        detect_filesystem_folding(root)
    }
}

const PROBE_NFC_CHAR: &str = "\u{00e9}"; // é (composed NFC, U+00E9, [0xC3, 0xA9])
const PROBE_NFD_CHAR: &str = "e\u{0301}"; // e + combining acute accent (decomposed NFD)
const PROBE_UPPER_NFC_CHAR: &str = "\u{00c9}"; // É (uppercase NFC, U+00C9)

/// Detects whether the filesystem hosting `root` folds case or Unicode normalization.
pub fn detect_filesystem_folding(root: &Path) -> Result<(), String> {
    if !root.is_dir() {
        return Err(format!("Root '{}' is not a directory", root.display()));
    }

    // 1. Attempt writable probe: create a temporary file with a unique name
    let probe_uuid = uuid::Uuid::new_v4();
    let probe_leaf = format!(".agnes_probe_{}_fold_test_{}", probe_uuid, PROBE_NFC_CHAR);
    let probe_path = root.join(&probe_leaf);

    match fs::OpenOptions::new().write(true).create_new(true).open(&probe_path) {
        Ok(file) => {
            // Ensure probe file is removed in ALL outcomes via RAII guard
            struct ProbeGuard<'a>(&'a Path);
            impl<'a> Drop for ProbeGuard<'a> {
                fn drop(&mut self) {
                    let _ = fs::remove_file(self.0);
                }
            }
            let _guard = ProbeGuard(&probe_path);
            drop(file);

            // Test 1: Case folding
            let case_swapped_leaf = format!(".AGNES_PROBE_{}_FOLD_TEST_{}", probe_uuid, PROBE_UPPER_NFC_CHAR);
            let case_swapped_path = root.join(&case_swapped_leaf);

            if let Ok(swapped_meta) = fs::symlink_metadata(&case_swapped_path) {
                if let Ok(orig_meta) = fs::symlink_metadata(&probe_path) {
                    if swapped_meta.dev() == orig_meta.dev() && swapped_meta.ino() == orig_meta.ino() {
                        return Err(format!(
                            "Filesystem at '{}' folds case: case-swapped probe '{}' resolves to probe file",
                            root.display(),
                            case_swapped_leaf
                        ));
                    }
                }
                return Err(format!(
                    "Filesystem at '{}' folds case or collides: case-swapped probe '{}' exists",
                    root.display(),
                    case_swapped_leaf
                ));
            }

            // Test 2: Unicode normalization folding
            let nfd_leaf = format!(".agnes_probe_{}_fold_test_{}", probe_uuid, PROBE_NFD_CHAR);
            let nfd_path = root.join(&nfd_leaf);

            if let Ok(nfd_meta) = fs::symlink_metadata(&nfd_path) {
                if let Ok(orig_meta) = fs::symlink_metadata(&probe_path) {
                    if nfd_meta.dev() == orig_meta.dev() && nfd_meta.ino() == orig_meta.ino() {
                        return Err(format!(
                            "Filesystem at '{}' folds Unicode normalization: NFD-variant probe '{}' resolves to probe file",
                            root.display(),
                            nfd_leaf
                        ));
                    }
                }
                return Err(format!(
                    "Filesystem at '{}' folds Unicode normalization: NFD-variant probe '{}' exists",
                    root.display(),
                    nfd_leaf
                ));
            }

            // Explicitly verify cleanup
            drop(_guard);
            if probe_path.exists() {
                let _ = fs::remove_file(&probe_path);
                if probe_path.exists() {
                    return Err(format!(
                        "Failed to clean up temporary probe file '{}'",
                        probe_path.display()
                    ));
                }
            }

            Ok(())
        }
        Err(create_err) => {
            // If the root is not writable (e.g. PermissionDenied, ReadOnlyFilesystem), probe using existing directory entries
            if create_err.kind() == std::io::ErrorKind::PermissionDenied
                || create_err.raw_os_error() == Some(libc::EROFS)
            {
                probe_read_only_root(root)
            } else {
                Err(format!(
                    "Failed to create probe file in root '{}': {}",
                    root.display(),
                    create_err
                ))
            }
        }
    }
}

fn probe_read_only_root(root: &Path) -> Result<(), String> {
    let entries = fs::read_dir(root).map_err(|e| {
        format!(
            "Root '{}' is not writable and directory entries cannot be read: {}",
            root.display(),
            e
        )
    })?;

    let mut found_cased_entry = false;
    let mut found_unicode_entry = false;

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = match file_name.to_str() {
            Some(s) => s,
            None => continue,
        };

        if name_str == "." || name_str == ".." {
            continue;
        }

        let entry_path = entry.path();
        let orig_meta = match fs::symlink_metadata(&entry_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Case probe on existing entry
        if !found_cased_entry && name_str.chars().any(|c| c.is_alphabetic()) {
            let swapped_name = swap_case_string(name_str);
            if swapped_name != name_str {
                found_cased_entry = true;
                let swapped_path = root.join(&swapped_name);
                if let Ok(swapped_meta) = fs::symlink_metadata(&swapped_path) {
                    if swapped_meta.dev() == orig_meta.dev() && swapped_meta.ino() == orig_meta.ino() {
                        return Err(format!(
                            "Filesystem at '{}' folds case: existing entry '{}' resolves to case-swapped '{}'",
                            root.display(),
                            name_str,
                            swapped_name
                        ));
                    }
                }
            }
        }

        // Unicode normalization probe on existing entry
        if !found_unicode_entry {
            if let Some(variant_name) = toggle_normalization_string(name_str) {
                found_unicode_entry = true;
                let variant_path = root.join(&variant_name);
                if let Ok(var_meta) = fs::symlink_metadata(&variant_path) {
                    if var_meta.dev() == orig_meta.dev() && var_meta.ino() == orig_meta.ino() {
                        return Err(format!(
                            "Filesystem at '{}' folds Unicode normalization: existing entry '{}' resolves to variant '{}'",
                            root.display(),
                            name_str,
                            variant_name
                        ));
                    }
                }
            }
        }

        if found_cased_entry && found_unicode_entry {
            break;
        }
    }

    if !found_cased_entry && !found_unicode_entry {
        Err(format!(
            "Root '{}' is not writable and contains no suitable directory entries with letters or non-ASCII characters to probe for case or Unicode folding",
            root.display()
        ))
    } else {
        Ok(())
    }
}

fn swap_case_string(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_lowercase() {
                c.to_uppercase().collect::<String>()
            } else if c.is_uppercase() {
                c.to_lowercase().collect::<String>()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn toggle_normalization_string(s: &str) -> Option<String> {
    const PAIRS: &[(&str, &str)] = &[
        ("\u{00e9}", "e\u{0301}"),
        ("\u{00e8}", "e\u{0300}"),
        ("\u{00e0}", "a\u{0300}"),
        ("\u{00e1}", "a\u{0301}"),
        ("\u{00fc}", "u\u{0308}"),
        ("\u{00f6}", "o\u{0308}"),
        ("\u{00e4}", "a\u{0308}"),
        ("\u{00f1}", "n\u{0303}"),
        ("\u{00c9}", "E\u{0301}"),
        ("\u{00dc}", "U\u{0308}"),
    ];

    for &(nfc, nfd) in PAIRS {
        if s.contains(nfc) {
            return Some(s.replace(nfc, nfd));
        } else if s.contains(nfd) {
            return Some(s.replace(nfd, nfc));
        }
    }
    None
}

pub struct FilesystemEnforcer {
    sandbox_roots: RwLock<Vec<PathBuf>>,
}

impl Default for FilesystemEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl FilesystemEnforcer {
    pub fn new() -> Self {
        Self {
            sandbox_roots: RwLock::new(Vec::new()),
        }
    }

    pub fn register_sandbox_root(&self, root: impl AsRef<Path>) {
        if let Ok(canonical) = root.as_ref().canonicalize() {
            let mut guard = match self.sandbox_roots.write() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!("Recovering poisoned sandbox_roots write lock");
                    poisoned.into_inner()
                }
            };
            self.sandbox_roots.clear_poison();
            if !guard.contains(&canonical) {
                info!(root = %canonical.display(), "Registered sandbox root for kernel confinement");
                guard.push(canonical);
            }
        }
    }

    /// Enforces file read action according to the deterministic policy decision
    /// and Linux kernel-enforced confinement (openat2 with RESOLVE_BENEATH).
    ///
    /// # TOCTOU Confinement Guarantee & Limits
    ///
    /// **Guarantee**:
    /// 1. Atomic Kernel Confinement: `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`
    ///    executes resolution and opening in a single atomic syscall anchored to `dirfd`.
    ///    The kernel VFS rejects any traversal ascending above `dirfd` or following an
    ///    out-of-tree symlink with `EXDEV`.
    /// 2. Post-Open Inode Identity Verification: Once `openat2` opens `file_fd`, the inode
    ///    is pinned in kernel memory. Reading `/proc/self/fd/{file_fd}` verifies that the
    ///    opened descriptor matches the exact canonical target approved by the policy engine
    ///    (`decision_resp.resolved_resource`). Any intra-sandbox symlink swap occurring
    ///    in the TOCTOU window between policy evaluation and `openat2` is detected and blocked
    ///    fail-closed before reading file content.
    /// 3. Inode Pinning: Subsequent renames, unlinks, or symlink swaps on disk cannot alter
    ///    the data read from an already-opened descriptor.
    ///
    /// **Limits**:
    /// 1. In-place content mutation: While path and inode substitution races are closed,
    ///    concurrent in-place modifications to the opened file's content by an external process
    ///    are governed by POSIX shared file semantics (unless advisory/mandatory locking is applied).
    /// 2. Sandbox Root Trust: Confinement assumes the registered sandbox root directory itself
    ///    is trusted and cannot be maliciously unmounted or replaced by an unprivileged agent.
    /// 3. Platform Requirement: Native atomic confinement requires Linux 5.6+ `openat2` (syscall 437)
    ///    and a valid `/proc/self/fd` mount.
    pub fn enforce_read(&self, request: &ActionRequest, decision_resp: &PolicyDecisionResponse) -> EnforcementResult {
        let raw_path = match &request.payload {
            ActionPayload::ReadFile { path } => path,
            _ => {
                return EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::Error,
                    output: None,
                    error_message: Some("Invalid payload for file read".to_string()),
                }
            }
        };

        // 1. If policy decided DENY, enforce fail-closed immediately.
        if decision_resp.decision == Decision::Deny {
            info!(
                target = %raw_path,
                agent = %request.agent_id,
                policy = %decision_resp.matched_policy_id,
                "ENFORCEMENT: Policy DENY - blocking physical access"
            );
            return EnforcementResult {
                enforcement_action: EnforcementAction::BlockRequest,
                observed_result: ObservedResult::BlockedByFirewall,
                output: None,
                error_message: Some(format!(
                    "EACCES: Project Agnes denied access to '{}'. Policy: {}",
                    raw_path, decision_resp.matched_policy_id
                )),
            };
        }

        // 2. Policy decided ALLOW -> Enforce physical security boundary via kernel.
        // Reject null bytes
        if raw_path.contains('\0') {
            return EnforcementResult {
                enforcement_action: EnforcementAction::CanonicalBoundaryViolation,
                observed_result: ObservedResult::BlockedByFirewall,
                output: None,
                error_message: Some("Null byte detected in path".to_string()),
            };
        }

        // The policy engine must have resolved and approved a real canonical resource.
        let expected_resolved_target = match decision_resp.resolved_resource.as_deref() {
            Some(res) => res,
            None => {
                warn!(target = %raw_path, "Policy allowed file read but resolved_resource is missing: fail-closed");
                return EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some("Fail-closed: Missing resolved resource for policy verification".to_string()),
                };
            }
        };

        // Find enclosing sandbox root. The sandbox root MUST enclose the authorized expected_path.
        let target_path = Path::new(raw_path);
        let expected_path = Path::new(expected_resolved_target);
        let matching_root = match self.find_sandbox_root(expected_path, target_path, &decision_resp.matched_policy_id) {
            Ok(r) => r,
            Err(_) => {
                tracing::error!("Enforcer sandbox_roots lock is poisoned: fail-closed DENY");
                return EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some("Internal error: sandbox roots lock poisoned (fail-closed block)".to_string()),
                };
            }
        };

        let root_dir = match matching_root {
            Some(r) => r,
            None => {
                // If no registered sandbox root encloses the path, fail-closed
                warn!(target = %raw_path, expected = %expected_resolved_target, "No sandbox root found enclosing policy-approved resource");
                return EnforcementResult {
                    enforcement_action: EnforcementAction::CanonicalBoundaryViolation,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some(format!(
                        "Sandbox boundary violation: '{}' is not within any permitted sandbox root",
                        raw_path
                    )),
                };
            }
        };

        // Enforce kernel resolution beneath root_dir with atomic post-open identity verification
        self.enforce_kernel_confined_read(&root_dir, target_path, raw_path, expected_resolved_target)
    }

    fn find_sandbox_root(&self, expected_path: &Path, target_path: &Path, _policy_id: &str) -> Result<Option<PathBuf>, ()> {
        let roots = self.sandbox_roots.read().map_err(|_| ())?;

        // The sandbox root MUST enclose the policy-approved expected_path.
        // If multiple roots enclose expected_path, select the most specific one (longest prefix).
        let mut best_root: Option<PathBuf> = None;
        for root in roots.iter() {
            if expected_path.starts_with(root) {
                match &best_root {
                    Some(current) => {
                        if root.as_os_str().len() > current.as_os_str().len() {
                            best_root = Some(root.clone());
                        }
                    }
                    None => {
                        best_root = Some(root.clone());
                    }
                }
            }
        }

        if best_root.is_some() {
            return Ok(best_root);
        }

        // If expected_path was not directly enclosed, check if target_path or normalized target_path
        // is enclosed by a registered root that also encloses expected_path.
        // Notice: We strictly reject any fallback that infers a root from target_path.parent()
        // which could select an unapproved root or re-read disk state.
        for root in roots.iter() {
            if target_path.starts_with(root) && expected_path.starts_with(root) {
                return Ok(Some(root.clone()));
            }
        }

        Ok(None)
    }

    pub fn normalize_path(path: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                c => out.push(c.as_os_str()),
            }
        }
        out
    }

    /// Uses Linux openat2 with RESOLVE_BENEATH to atomically confine open to root_dir,
    /// followed by post-open descriptor verification against the policy-approved target.
    fn enforce_kernel_confined_read(
        &self,
        root_dir: &Path,
        target_path: &Path,
        raw_path: &str,
        expected_resolved_target: &str,
    ) -> EnforcementResult {
        let root_c_str = match CString::new(root_dir.to_str().unwrap_or_default()) {
            Ok(s) => s,
            Err(_) => {
                return EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::Error,
                    output: None,
                    error_message: Some("Invalid root path encoding".to_string()),
                }
            }
        };

        // Open directory file descriptor for the root with O_PATH | O_DIRECTORY | O_NOFOLLOW
        let dirfd: RawFd = unsafe {
            libc::open(
                root_c_str.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };

        if dirfd < 0 {
            let err = std::io::Error::last_os_error();
            warn!(root = %root_dir.display(), error = %err, "Failed to open sandbox root directory descriptor");
            return EnforcementResult {
                enforcement_action: EnforcementAction::BlockRequest,
                observed_result: ObservedResult::AccessFailed,
                output: None,
                error_message: Some(format!("Failed to open sandbox root: {}", err)),
            };
        }

        // Calculate relative path string from target to root_dir
        let relative_path_str = if target_path.starts_with(root_dir) {
            match target_path.strip_prefix(root_dir) {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => raw_path.to_string(),
            }
        } else {
            // Raw path might contain traversal sequences like `/allowed/../forbidden`
            // Strip the root prefix manually if it starts with root string
            let root_str = root_dir.to_string_lossy();
            if let Some(rest) = raw_path.strip_prefix(root_str.as_ref()) {
                rest.trim_start_matches('/').to_string()
            } else {
                raw_path.to_string()
            }
        };

        let rel_c_str = match CString::new(relative_path_str.as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                unsafe { libc::close(dirfd); }
                return EnforcementResult {
                    enforcement_action: EnforcementAction::CanonicalBoundaryViolation,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some("Invalid path characters".to_string()),
                };
            }
        };

        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        };

        // Kernel atomic confinement syscall
        let file_fd = unsafe {
            libc::syscall(
                SYS_OPENAT2,
                dirfd,
                rel_c_str.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            ) as libc::c_int
        };

        // Close dirfd
        unsafe {
            libc::close(dirfd);
        }

        if file_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EXDEV) {
                info!(
                    target = %raw_path,
                    "KERNEL CONFINEMENT: openat2 RESOLVE_BENEATH returned EXDEV - blocked escape attempt"
                );
                return EnforcementResult {
                    enforcement_action: EnforcementAction::KernelResolveBeneathBlock,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some(
                        "Kernel EXDEV: Path resolution escaped sandbox boundary (blocked by openat2 RESOLVE_BENEATH)"
                            .to_string(),
                    ),
                };
            } else if err.raw_os_error() == Some(libc::ENOENT) {
                return EnforcementResult {
                    enforcement_action: EnforcementAction::PermitExecution,
                    observed_result: ObservedResult::AccessFailed,
                    output: None,
                    error_message: Some(format!("File not found: {}", raw_path)),
                };
            } else {
                warn!(target = %raw_path, error = %err, "Kernel openat2 call returned error");
                return EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::AccessFailed,
                    output: None,
                    error_message: Some(format!("OS error opening file: {}", err)),
                };
            }
        }

        // Post-Open Inode Identity Verification:
        // Ensure that the file descriptor opened by the kernel corresponds exactly to the
        // canonical resource authorized by the policy engine. If an intra-sandbox symlink was
        // swapped between policy evaluation and openat2, opened_path will diverge from expected_path.
        let opened_path = match fs::read_link(format!("/proc/self/fd/{}", file_fd)) {
            Ok(p) => p,
            Err(e) => {
                unsafe { libc::close(file_fd); }
                warn!(error = %e, "Failed to verify opened file descriptor target via /proc/self/fd");
                return EnforcementResult {
                    enforcement_action: EnforcementAction::BlockRequest,
                    observed_result: ObservedResult::BlockedByFirewall,
                    output: None,
                    error_message: Some(format!("Failed to verify opened file descriptor target: {}", e)),
                };
            }
        };

        // Explicitly check for unlinked/deleted descriptor suffix from /proc/self/fd readlink.
        let opened_str = opened_path.to_string_lossy();
        if opened_str.ends_with(" (deleted)") {
            unsafe { libc::close(file_fd); }
            warn!(
                opened = %opened_str,
                "TOCTOU VIOLATION: Opened file descriptor was unlinked or marked deleted"
            );
            return EnforcementResult {
                enforcement_action: EnforcementAction::CanonicalBoundaryViolation,
                observed_result: ObservedResult::BlockedByFirewall,
                output: None,
                error_message: Some(format!(
                    "TOCTOU violation detected: opened file '{}' was deleted/unlinked",
                    opened_str
                )),
            };
        }

        // Exact path equality: expected_resolved_target is already canonical from policy resolution.
        // We strictly disallow re-resolving expected_path from disk (e.g. via canonicalize), as an attacker
        // who replaces the approved file with a symlink would cause both sides to re-resolve to the unauthorized target.
        let expected_path = Path::new(expected_resolved_target);
        if opened_path != expected_path {
            unsafe { libc::close(file_fd); }
            warn!(
                expected = %expected_path.display(),
                opened = %opened_path.display(),
                "TOCTOU VIOLATION: File opened by kernel does not match policy-approved resource"
            );
            return EnforcementResult {
                enforcement_action: EnforcementAction::CanonicalBoundaryViolation,
                observed_result: ObservedResult::BlockedByFirewall,
                output: None,
                error_message: Some(format!(
                    "TOCTOU violation detected: opened path '{}' does not match authorized path '{}'",
                    opened_path.display(),
                    expected_path.display()
                )),
            };
        }

        // Successfully opened file descriptor guaranteed by kernel to be beneath root_dir
        // and verified to match the authorized policy target.
        let mut file = unsafe { fs::File::from_raw_fd(file_fd) };
        let mut content = String::new();
        match file.read_to_string(&mut content) {
            Ok(_) => EnforcementResult {
                enforcement_action: EnforcementAction::PermitExecution,
                observed_result: ObservedResult::AccessSuccess,
                output: Some(content),
                error_message: None,
            },
            Err(e) => EnforcementResult {
                enforcement_action: EnforcementAction::PermitExecution,
                observed_result: ObservedResult::AccessFailed,
                output: None,
                error_message: Some(format!("Error reading opened file: {}", e)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agnes_common::{ActionPayload, ActionRequest, Decision, PolicyDecisionResponse, DecisionReason};

    #[test]
    fn test_enforcer_poisoned_sandbox_roots_produces_controlled_denial() {
        let enforcer = std::sync::Arc::new(FilesystemEnforcer::new());
        let enforcer_clone = enforcer.clone();

        // Poison the sandbox_roots lock
        let _ = std::thread::spawn(move || {
            let mut guard = enforcer_clone.sandbox_roots.write().unwrap();
            guard.push(PathBuf::from("/sandbox"));
            panic!("Poisoning sandbox_roots write lock");
        }).join();

        let req = ActionRequest::new(
            "agent-001",
            ActionPayload::ReadFile {
                path: "/sandbox/file.txt".to_string(),
            },
        );

        let decision = PolicyDecisionResponse {
            decision: Decision::Allow,
            reason: DecisionReason {
                policy_id: "p1".to_string(),
                rule_id: None,
                explanation: "allowed".to_string(),
            },
            matched_policy_id: "p1".to_string(),
            evaluated_at: chrono::Utc::now(),
            resolved_resource: Some("/sandbox/file.txt".to_string()),
        };

        let result = enforcer.enforce_read(&req, &decision);
        assert_eq!(
            result.observed_result,
            ObservedResult::BlockedByFirewall,
            "Enforcer must produce BlockedByFirewall when sandbox_roots lock is poisoned"
        );
        assert_eq!(
            result.enforcement_action,
            EnforcementAction::BlockRequest,
            "Enforcer must produce BlockRequest when sandbox_roots lock is poisoned"
        );
        assert!(
            result.error_message.as_deref().unwrap_or_default().contains("lock poisoned"),
            "Error message must clearly state lock poisoned"
        );
        assert_eq!(result.output, None);
    }
}

