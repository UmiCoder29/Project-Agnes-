use blackwall_common::{
    ActionPayload, ActionRequest, Decision, EnforcementAction, ObservedResult, PolicyDecisionResponse,
};
use std::ffi::CString;
use std::fs;
use std::io::Read;
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
            let mut guard = self.sandbox_roots.write().expect("lock poisoned");
            if !guard.contains(&canonical) {
                info!(root = %canonical.display(), "Registered sandbox root for kernel confinement");
                guard.push(canonical);
            }
        }
    }

    /// Enforces file read action according to the deterministic policy decision
    /// and Linux kernel-enforced confinement (openat2 with RESOLVE_BENEATH).
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
                    "EACCES: Black Wall denied access to '{}'. Policy: {}",
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

        // Find enclosing sandbox root
        let target_path = Path::new(raw_path);
        let matching_root = self.find_sandbox_root(target_path, &decision_resp.matched_policy_id);

        let root_dir = match matching_root {
            Some(r) => r,
            None => {
                // If no registered sandbox root encloses the path, check if path itself can be validated
                warn!(target = %raw_path, "No sandbox root found to anchor kernel confinement");
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

        // Enforce kernel resolution beneath root_dir
        self.enforce_kernel_confined_read(&root_dir, target_path, raw_path)
    }

    fn find_sandbox_root(&self, target_path: &Path, _policy_id: &str) -> Option<PathBuf> {
        let roots = self.sandbox_roots.read().expect("lock poisoned");

        // Try to find the best matching root
        for root in roots.iter() {
            if target_path.starts_with(root) {
                return Some(root.clone());
            }
        }

        // If target_path is relative or has lexical traversal, try lexical normalization
        let normalized = Self::normalize_path(target_path);
        for root in roots.iter() {
            if normalized.starts_with(root) {
                return Some(root.clone());
            }
        }

        // If not in explicitly registered roots, infer root from the parent of an allowed target
        // if target_path parent exists
        if let Some(parent) = target_path.parent() {
            if let Ok(canon_parent) = parent.canonicalize() {
                for root in roots.iter() {
                    if canon_parent.starts_with(root) {
                        return Some(root.clone());
                    }
                }
            }
        }

        None
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

    /// Uses Linux openat2 with RESOLVE_BENEATH to atomically confine open to root_dir.
    fn enforce_kernel_confined_read(&self, root_dir: &Path, target_path: &Path, raw_path: &str) -> EnforcementResult {
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

        // Open directory file descriptor for the root with O_PATH | O_DIRECTORY
        let dirfd: RawFd = unsafe {
            libc::open(
                root_c_str.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
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
            if raw_path.starts_with(root_str.as_ref()) {
                let rest = &raw_path[root_str.len()..];
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

        // Successfully opened file descriptor guaranteed by kernel to be beneath root_dir!
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
