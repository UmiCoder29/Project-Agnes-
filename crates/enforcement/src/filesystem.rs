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

/// Metadata returned by `FoldingFsLookup` implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeFileMetadata {
    pub dev: u64,
    pub ino: u64,
}

/// Filesystem lookup abstraction used by folding detection.
/// Allows unit tests to simulate case-insensitive and normalization-folding filesystems.
pub trait FoldingFsLookup: Send + Sync {
    /// Checks if the path is a directory.
    fn is_dir(&self, path: &Path) -> bool;

    /// Creates a new probe file inside `root` with the given leaf name.
    /// Fails if the file already exists or if the filesystem is read-only.
    fn create(&self, root: &Path, name: &str) -> std::io::Result<()>;

    /// Fetches file metadata by leaf name inside `root`.
    fn metadata(&self, root: &Path, name: &str) -> std::io::Result<ProbeFileMetadata>;

    /// Removes a file by leaf name inside `root`.
    fn remove(&self, root: &Path, name: &str) -> std::io::Result<()>;

    /// Lists directory entry names inside `root` for read-only probing.
    fn read_dir(&self, root: &Path) -> std::io::Result<Vec<String>>;
}

/// Production implementation of `FoldingFsLookup` backed by `std::fs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdFoldingFsLookup;

impl FoldingFsLookup for StdFoldingFsLookup {
    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn create(&self, root: &Path, name: &str) -> std::io::Result<()> {
        let p = root.join(name);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)?;
        drop(file);
        Ok(())
    }

    fn metadata(&self, root: &Path, name: &str) -> std::io::Result<ProbeFileMetadata> {
        let p = root.join(name);
        let m = fs::symlink_metadata(&p)?;
        Ok(ProbeFileMetadata {
            dev: m.dev(),
            ino: m.ino(),
        })
    }

    fn remove(&self, root: &Path, name: &str) -> std::io::Result<()> {
        let p = root.join(name);
        fs::remove_file(&p)
    }

    fn read_dir(&self, root: &Path) -> std::io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if let Ok(name) = entry.file_name().into_string() {
                names.push(name);
            }
        }
        Ok(names)
    }
}

const PROBE_NFC_CHAR: &str = "\u{00e9}"; // é (composed NFC, U+00E9, [0xC3, 0xA9])
const PROBE_NFD_CHAR: &str = "e\u{0301}"; // e + combining acute accent (decomposed NFD)
const PROBE_UPPER_NFC_CHAR: &str = "\u{00c9}"; // É (uppercase NFC, U+00C9)

const NORMALIZATION_PAIRS: &[(&str, &str)] = &[
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

/// Detects whether the filesystem hosting `root` folds case or Unicode normalization.
///
/// # Security Limitations
///
/// **Per-Directory & Sub-Mount Limit**:
/// This probe inspects only the root directory entry itself. It does NOT probe:
/// 1. Subdirectories inside the root that may have filesystem-level casefolding enabled
///    (e.g., Linux ext4 per-directory casefolding via `chattr +F` / `EXT4_CASEFOLD_FL`).
/// 2. Sub-mounts of case-insensitive or Unicode normalization-folding foreign filesystems
///    (such as VFAT, exFAT, NTFS, or macOS CIFS/NFS shares) mounted beneath the root.
///
/// Administrators deploying Project Agnes must ensure the entire directory tree beneath
/// each configured sandbox root is mounted uniformly on a case-sensitive, non-folding
/// filesystem without directory-level folding attributes enabled.
pub fn detect_filesystem_folding(root: &Path) -> Result<(), String> {
    detect_filesystem_folding_with_fs(root, &StdFoldingFsLookup)
}

/// Detects whether the filesystem hosting `root` folds case or Unicode normalization
/// using the supplied `FoldingFsLookup` implementation.
pub fn detect_filesystem_folding_with_fs(root: &Path, fs: &dyn FoldingFsLookup) -> Result<(), String> {
    if !fs.is_dir(root) {
        return Err(format!("Root '{}' is not a directory", root.display()));
    }

    // 1. Attempt writable probe: create a temporary file with a unique name
    let probe_uuid = uuid::Uuid::new_v4();
    let probe_leaf = format!(".agnes_probe_{}_fold_test_{}", probe_uuid, PROBE_NFC_CHAR);

    match fs.create(root, &probe_leaf) {
        Ok(()) => {
            // Ensure probe file is removed in ALL outcomes via RAII guard
            struct ProbeGuard<'a> {
                fs: &'a dyn FoldingFsLookup,
                root: &'a Path,
                leaf: &'a str,
                active: bool,
            }
            impl<'a> Drop for ProbeGuard<'a> {
                fn drop(&mut self) {
                    if self.active {
                        let _ = self.fs.remove(self.root, self.leaf);
                    }
                }
            }
            let _guard = ProbeGuard {
                fs,
                root,
                leaf: &probe_leaf,
                active: true,
            };

            let orig_meta = match fs.metadata(root, &probe_leaf) {
                Ok(m) => m,
                Err(e) => {
                    return Err(format!(
                        "Failed to query metadata for probe file '{}': {}",
                        probe_leaf, e
                    ));
                }
            };

            // Test 1: Case folding
            let case_swapped_leaf = format!(".AGNES_PROBE_{}_FOLD_TEST_{}", probe_uuid, PROBE_UPPER_NFC_CHAR);
            if let Ok(swapped_meta) = fs.metadata(root, &case_swapped_leaf) {
                if swapped_meta.dev == orig_meta.dev && swapped_meta.ino == orig_meta.ino {
                    return Err(format!(
                        "Filesystem at '{}' folds case: case-swapped probe '{}' resolves to probe file",
                        root.display(),
                        case_swapped_leaf
                    ));
                }
                return Err(format!(
                    "Filesystem at '{}' folds case or collides: case-swapped probe '{}' exists",
                    root.display(),
                    case_swapped_leaf
                ));
            }

            // Test 2: Unicode normalization folding
            let nfd_leaf = format!(".agnes_probe_{}_fold_test_{}", probe_uuid, PROBE_NFD_CHAR);
            if let Ok(nfd_meta) = fs.metadata(root, &nfd_leaf) {
                if nfd_meta.dev == orig_meta.dev && nfd_meta.ino == orig_meta.ino {
                    return Err(format!(
                        "Filesystem at '{}' folds Unicode normalization: NFD-variant probe '{}' resolves to probe file",
                        root.display(),
                        nfd_leaf
                    ));
                }
                return Err(format!(
                    "Filesystem at '{}' folds Unicode normalization: NFD-variant probe '{}' exists",
                    root.display(),
                    nfd_leaf
                ));
            }

            // Explicitly drop guard so removal happens now
            drop(_guard);

            // Verify probe file was removed
            if fs.metadata(root, &probe_leaf).is_ok() {
                let _ = fs.remove(root, &probe_leaf);
                if fs.metadata(root, &probe_leaf).is_ok() {
                    return Err(format!(
                        "Failed to clean up temporary probe file '{}'",
                        probe_leaf
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
                probe_read_only_root(root, fs)
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

/// Probes a read-only root directory for case and Unicode normalization folding using existing entries.
///
/// # Security Limitations
///
/// **Read-Only Partial-Coverage Limit**:
/// When a root directory is read-only, Project Agnes cannot create a controlled probe file
/// containing known ASCII letters and specific multi-byte NFC/NFD Unicode sequences.
/// Probing must rely entirely on whatever entries already exist in the directory:
/// - If existing entries contain only ASCII letters, only case folding can be probed; Unicode
///   normalization folding cannot be verified.
/// - If existing entries contain only non-ASCII characters, only Unicode normalization can be probed;
///   case folding cannot be verified.
/// - If entries contain neither (e.g. only numbers, or an empty directory), neither probe is possible
///   and the root is rejected fail-closed.
/// - Even when suitable entries exist, they only test the specific characters present in those filenames;
///   untested Unicode sequences or filesystem-specific folding quirks outside the existing entry set
///   cannot be validated.
pub fn probe_read_only_root(root: &Path, fs: &dyn FoldingFsLookup) -> Result<(), String> {
    let entries = fs.read_dir(root).map_err(|e| {
        format!(
            "Root '{}' is not writable and directory entries cannot be read: {}",
            root.display(),
            e
        )
    })?;

    let mut found_cased_entry = false;
    let mut found_unicode_entry = false;

    for name_str in &entries {
        if name_str == "." || name_str == ".." {
            continue;
        }

        let orig_meta = match fs.metadata(root, name_str) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Case probe on existing entry
        if !found_cased_entry && name_str.chars().any(|c| c.is_alphabetic()) {
            let swapped_name = swap_case_string(name_str);
            if swapped_name != *name_str {
                found_cased_entry = true;
                if let Ok(swapped_meta) = fs.metadata(root, &swapped_name) {
                    if swapped_meta.dev == orig_meta.dev && swapped_meta.ino == orig_meta.ino {
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
                if let Ok(var_meta) = fs.metadata(root, &variant_name) {
                    if var_meta.dev == orig_meta.dev && var_meta.ino == orig_meta.ino {
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
    for &(nfc, nfd) in NORMALIZATION_PAIRS {
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

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MockFoldingMode {
        None,
        CaseInsensitive,
        UnicodeNormalization,
    }

    pub struct SimulatedFs {
        pub mode: MockFoldingMode,
        pub writable: bool,
        pub files: Mutex<HashMap<String, ProbeFileMetadata>>,
        pub next_ino: AtomicU64,
        pub removed_files: Mutex<Vec<String>>,
    }

    impl SimulatedFs {
        pub fn new(mode: MockFoldingMode, writable: bool) -> Self {
            Self {
                mode,
                writable,
                files: Mutex::new(HashMap::new()),
                next_ino: AtomicU64::new(100),
                removed_files: Mutex::new(Vec::new()),
            }
        }

        pub fn add_file(&self, name: &str) {
            let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
            self.files.lock().unwrap().insert(
                name.to_string(),
                ProbeFileMetadata { dev: 1, ino },
            );
        }

        pub fn active_file_count(&self) -> usize {
            self.files.lock().unwrap().len()
        }

        pub fn was_removed(&self, name_prefix: &str) -> bool {
            let removed = self.removed_files.lock().unwrap();
            removed.iter().any(|r| r.starts_with(name_prefix))
        }

        fn lookup_key(&self, name: &str) -> String {
            match self.mode {
                MockFoldingMode::None => name.to_string(),
                MockFoldingMode::CaseInsensitive => name.to_lowercase(),
                MockFoldingMode::UnicodeNormalization => {
                    let mut out = name.to_string();
                    for &(nfc, nfd) in NORMALIZATION_PAIRS {
                        if out.contains(nfd) {
                            out = out.replace(nfd, nfc);
                        }
                    }
                    out
                }
            }
        }
    }

    impl FoldingFsLookup for SimulatedFs {
        fn is_dir(&self, _path: &Path) -> bool {
            true
        }

        fn create(&self, _root: &Path, name: &str) -> std::io::Result<()> {
            if !self.writable {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Read-only filesystem",
                ));
            }
            let mut files = self.files.lock().unwrap();
            let key = self.lookup_key(name);
            if files.keys().any(|k| self.lookup_key(k) == key) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "File already exists",
                ));
            }
            let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
            files.insert(name.to_string(), ProbeFileMetadata { dev: 1, ino });
            Ok(())
        }

        fn metadata(&self, _root: &Path, name: &str) -> std::io::Result<ProbeFileMetadata> {
            let files = self.files.lock().unwrap();
            let key = self.lookup_key(name);
            for (fname, meta) in files.iter() {
                if self.lookup_key(fname) == key {
                    return Ok(*meta);
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File '{}' not found", name),
            ))
        }

        fn remove(&self, _root: &Path, name: &str) -> std::io::Result<()> {
            let mut files = self.files.lock().unwrap();
            let key = self.lookup_key(name);
            let mut found_key = None;
            for fname in files.keys() {
                if self.lookup_key(fname) == key {
                    found_key = Some(fname.clone());
                    break;
                }
            }
            if let Some(k) = found_key {
                files.remove(&k);
                self.removed_files.lock().unwrap().push(name.to_string());
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File '{}' not found for removal", name),
                ))
            }
        }

        fn read_dir(&self, _root: &Path) -> std::io::Result<Vec<String>> {
            let files = self.files.lock().unwrap();
            Ok(files.keys().cloned().collect())
        }
    }

    #[test]
    fn test_simulated_fs_writable_case_folding_rejected_and_probe_removed() {
        let sim_fs = SimulatedFs::new(MockFoldingMode::CaseInsensitive, true);
        let res = detect_filesystem_folding_with_fs(Path::new("/simulated/root"), &sim_fs);
        assert!(
            res.is_err(),
            "Simulated case-folding filesystem must be rejected on writable probe"
        );
        let err_msg = res.unwrap_err();
        assert!(
            err_msg.contains("folds case"),
            "Error must specify case folding: {}",
            err_msg
        );
        assert_eq!(
            sim_fs.active_file_count(),
            0,
            "Probe file must be unlinked and cleaned up after case folding early-error return"
        );
        assert!(
            sim_fs.was_removed(".agnes_probe_"),
            "Probe file removal must have been invoked on simulated filesystem"
        );
    }

    #[test]
    fn test_simulated_fs_writable_unicode_folding_rejected_and_probe_removed() {
        let sim_fs = SimulatedFs::new(MockFoldingMode::UnicodeNormalization, true);
        let res = detect_filesystem_folding_with_fs(Path::new("/simulated/root"), &sim_fs);
        assert!(
            res.is_err(),
            "Simulated Unicode normalization-folding filesystem must be rejected on writable probe"
        );
        let err_msg = res.unwrap_err();
        assert!(
            err_msg.contains("Unicode normalization"),
            "Error must specify Unicode normalization folding: {}",
            err_msg
        );
        assert_eq!(
            sim_fs.active_file_count(),
            0,
            "Probe file must be unlinked and cleaned up after Unicode folding early-error return"
        );
        assert!(
            sim_fs.was_removed(".agnes_probe_"),
            "Probe file removal must have been invoked on simulated filesystem"
        );
    }

    #[test]
    fn test_simulated_fs_writable_non_folding_accepted_and_probe_removed() {
        let sim_fs = SimulatedFs::new(MockFoldingMode::None, true);
        let res = detect_filesystem_folding_with_fs(Path::new("/simulated/root"), &sim_fs);
        assert!(
            res.is_ok(),
            "Simulated non-folding filesystem must be accepted: {:?}",
            res
        );
        assert_eq!(
            sim_fs.active_file_count(),
            0,
            "Probe file must be unlinked and cleaned up after successful detection"
        );
        assert!(
            sim_fs.was_removed(".agnes_probe_"),
            "Probe file removal must have been invoked on simulated filesystem"
        );
    }

    #[test]
    fn test_simulated_fs_readonly_case_folding_rejected() {
        let sim_fs = SimulatedFs::new(MockFoldingMode::CaseInsensitive, false);
        sim_fs.add_file("entry_with_letters.txt");
        let res = detect_filesystem_folding_with_fs(Path::new("/simulated/root"), &sim_fs);
        assert!(
            res.is_err(),
            "Simulated case-folding filesystem must be rejected on read-only probe"
        );
        let err_msg = res.unwrap_err();
        assert!(
            err_msg.contains("folds case"),
            "Error must specify case folding: {}",
            err_msg
        );
    }

    #[test]
    fn test_simulated_fs_readonly_unicode_folding_rejected() {
        let sim_fs = SimulatedFs::new(MockFoldingMode::UnicodeNormalization, false);
        sim_fs.add_file("caf\u{00e9}.txt");
        let res = detect_filesystem_folding_with_fs(Path::new("/simulated/root"), &sim_fs);
        assert!(
            res.is_err(),
            "Simulated Unicode normalization-folding filesystem must be rejected on read-only probe"
        );
        let err_msg = res.unwrap_err();
        assert!(
            err_msg.contains("Unicode normalization"),
            "Error must specify Unicode normalization folding: {}",
            err_msg
        );
    }

    #[test]
    fn test_simulated_fs_readonly_non_folding_accepted() {
        let sim_fs = SimulatedFs::new(MockFoldingMode::None, false);
        sim_fs.add_file("entry_with_letters.txt");
        sim_fs.add_file("caf\u{00e9}.txt");
        let res = detect_filesystem_folding_with_fs(Path::new("/simulated/root"), &sim_fs);
        assert!(
            res.is_ok(),
            "Simulated non-folding filesystem must be accepted on read-only probe: {:?}",
            res
        );
    }

    #[test]
    fn test_simulated_fs_readonly_empty_rejected() {
        let sim_fs = SimulatedFs::new(MockFoldingMode::None, false);
        let res = detect_filesystem_folding_with_fs(Path::new("/simulated/root"), &sim_fs);
        assert!(
            res.is_err(),
            "Empty read-only root must be rejected fail-closed"
        );
        let err_msg = res.unwrap_err();
        assert!(
            err_msg.contains("contains no suitable directory entries"),
            "Error must state no suitable entries: {}",
            err_msg
        );
    }
}


