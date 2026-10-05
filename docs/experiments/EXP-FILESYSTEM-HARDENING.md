# EXP-FILESYSTEM-HARDENING: Linux Kernel-Enforced Confinement & Path Hardening

- **Date**: 2026-10-05
- **Experiment ID**: EXP-FILESYSTEM-HARDENING
- **Target Subsystem**: Filesystem Security Boundary & Filesystem Enforcer
- **Environment**: Ubuntu 26.04.1 LTS (Kernel: 7.0.0-38-generic, x86_64)

---

## 1. Original Vulnerabilities
1. **BYPASS-002-TRAVERSAL**: An agent with read permissions on `/allowed/*` requested `/allowed/../forbidden/secret.txt`. The naive policy matcher evaluated this as matching prefix `/allowed`, producing `ALLOW`. The runtime executed `std::fs::read_to_string` on the raw path, leaking classified data.
2. **BYPASS-002-SYMLINK**: An agent requested `/allowed/link_to_secret.txt`, where `link_to_secret.txt` was a symlink created inside the allowed sandbox pointing to `/forbidden/secret.txt`. The policy engine evaluated the lexical path within `/allowed`, producing `ALLOW`, and the runtime dereferenced the symlink outside the boundary, leaking secrets.

---

## 2. Root Cause
- **Lexical Decoupling**: Security authorization was evaluated strictly against user-supplied path strings without canonicalization or resolution.
- **Enforcement Absence**: The enforcement plane blindly trusted the policy engine's decision and forwarded raw strings to standard user-space I/O routines (`std::fs::read_to_string`), which follow POSIX traversal and symlink rules indiscriminately.
- **Absence of Kernel Boundary Pinning**: No directory file descriptor pin or kernel confinement flags were applied during inode resolution.

---

## 3. Threat Model
- **Attacker Profile**: Autonomous agent (compromised prompt, malicious MCP tool output, or adversarial goal alignment).
- **Capabilities**: Can craft arbitrary path strings, create symlinks within permitted workspace directories, introduce redundant slashes, dot-dot sequences, URL encoding, or attempt concurrent replacement races (TOCTOU).
- **Target**: Sensitive files on the host or inside parent directories outside the agent's explicit resource boundary.

---

## 4. Candidate Fixes Investigated
1. **User-Space Canonicalization Only (`path.canonicalize()`)**:
   - *Pros*: Simple to implement in Rust.
   - *Cons*: Prone to Time-of-Check to Time-of-Use (TOCTOU) races (e.g. an attacker thread replaces a directory or file with a symlink immediately after `canonicalize()` but before `fs::read()`). Does not work if intermediate directories do not exist or are swapped dynamically.
2. **Landlock LSM (`landlock_create_ruleset`, `landlock_restrict_self`)**:
   - *Pros*: Kernel-level process confinement; restricts process tree from reading outside specific directory descriptors.
   - *Cons*: Process-wide or thread-wide unprivileged confinement; once applied to a process or thread, Landlock restrictions are irreversible for that process tree. In an agent gateway serving multiple agents with distinct sandboxes, applying Landlock to the central gateway process would restrict the gateway itself.
3. **Mount Namespaces (`unshare(CLONE_NEWNS)`) & Pivot Root**:
   - *Pros*: Complete OS-level filesystem isolation.
   - *Cons*: Requires root privileges (`CAP_SYS_ADMIN`) or user namespaces (`CLONE_NEWUSER`), heavy overhead per action request, complex container nesting.
4. **Linux `openat2(2)` with `RESOLVE_BENEATH` (Syscall 437)**:
   - *Pros*: Kernel-enforced atomic path resolution anchored to a directory file descriptor (`dirfd`). Automatically and atomically rejects any `..` traversal that ascends above `dirfd`, and rejects any symlink that escapes the `dirfd` hierarchy with `EXDEV` (errno 18). Eliminates the TOCTOU window between verification and opening because the check and open are unified into a single atomic kernel operation.
   - *Cons*: Linux 5.6+ specific (empirically confirmed present and active on our 7.0.0-38-generic kernel).

---

## 5. Technologies Investigated & Empirical Kernel Findings
- **Kernel Version**: Linux `7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`.
- **Syscall Availability**: `SYS_openat2` (syscall 437) verified via C test harnesses (`scratch/test_openat2.c`, `scratch/test_openat2_symlink.c`).
- **Observed Kernel Behavior**:
  - `openat2(dirfd, "../etc/passwd", RESOLVE_BENEATH)` returned `EXDEV` (errno 18).
  - `openat2(dirfd, "symlink_escape", RESOLVE_BENEATH)` pointing to `/etc/passwd` returned `EXDEV` (errno 18).
  - `openat2(dirfd, "internal_link", RESOLVE_BENEATH)` pointing within the directory successfully succeeded with `ALLOW`.

---

## 6. Selected Enforcement Mechanism: Defense-in-Depth Confinement
We select a two-tiered defense-in-depth architecture:

1. **Tier 1: Canonical Boundary Verification & Path Normalization in Policy**:
   - Lexical and canonical path resolution relative to explicit allowed sandbox roots.
   - Fail-closed validation rejecting illegal null bytes, control characters, and out-of-boundary canonical targets.
2. **Tier 2: Kernel-Enforced Atomic Confinement (`openat2` + `RESOLVE_BENEATH`)**:
   - Filesystem enforcement opens an `O_PATH | O_DIRECTORY | O_CLOEXEC` descriptor to the canonical root.
   - Subpath resolution is performed directly via `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`.
   - The file handle obtained is read directly via `read_to_end` from the resulting descriptor, preventing TOCTOU file replacement races.
   - If `openat2` returns `EXDEV`, the operation is blocked with `KERNEL_RESOLVE_BENEATH_BLOCK` and `ObservedResult::BlockedByFirewall`.

---

## 7. Why Selected
- **Atomic Kernel Confinement**: The kernel guarantees during the VFS walk that resolution never steps out of `dirfd`.
- **TOCTOU Immunity**: No separate `stat` -> `sleep` -> `read`. The descriptor is opened atomically under kernel flags.
- **Portability & Safety**: Clean fallback with safe canonical verification if running on platforms without `openat2`, but native `openat2` on Linux.

---

## 8. Planned Tests & Test Plan
1. `REGRESSION-001`: Direct `../` traversal blocked.
2. `REGRESSION-002`: Direct symlink escape blocked.
3. `REGRESSION-003`: Deeply nested traversal (`/allowed/a/b/../../../../forbidden/secret.txt`).
4. `REGRESSION-004`: Redundant slashes and alternate representations (`/allowed/././../forbidden/secret.txt`).
5. `REGRESSION-005`: Relative path attempts.
6. `REGRESSION-006`: Absolute paths outside root.
7. `REGRESSION-007`: Chained/nested symlinks (`a -> b -> forbidden/secret`).
8. `REGRESSION-008`: Symlink created dynamically after policy check.
9. `REGRESSION-009`: Directory rename/replacement race.
10. `REGRESSION-010`: Allowed file replaced by symlink before read.
11. `REGRESSION-011`: Multiple nested symlinks.
12. `REGRESSION-012`: Parent directory escape.
13. `REGRESSION-013`: Alternate path traversal.
14. `REGRESSION-014`: Permission changes.
15. `REGRESSION-015`: TOCTOU concurrency stress fuzzing.

---

## 9. Remaining Risks & Considerations
- Cross-mount bind-mount traversal behavior when `RESOLVE_NO_XDEV` is toggled.
- Directory listing and metadata disclosure (`getdents64`, `statx`) which will be addressed in subsequent filesystem controls.
