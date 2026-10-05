# THREAT MODEL: FILESYSTEM RUNTIME BOUNDARY

Documenting the threat landscape, failure modes, and defenses for autonomous agent filesystem interactions.

---

## THREAT 1: Filesystem Traversal (`../`)

- **ATTACK**: Directory traversal sequence injection into file paths.
- **PRECONDITION**: Agent is granted read access to a specific subtree (e.g., `/allowed/*`).
- **ATTACK PATH**: The agent submits an action request with path `/allowed/../forbidden/secret.txt`.
- **CURRENT DEFENSE (v0.1)**: Prefix matching on the raw path string (`path.starts_with("/allowed")`).
- **CURRENT FAILURE**: The lexical string starts with `/allowed`, resulting in an `ALLOW` decision. The OS follows `..` and reads `/forbidden/secret.txt`.
- **NEW DEFENSE**:
  1. Policy-layer path canonicalization against registered sandbox roots.
  2. Kernel enforcement using `openat2()` with `RESOLVE_BENEATH` anchored to the allowed root `dirfd`. The kernel VFS rejects any traversal stepping above `dirfd` with `EXDEV`.
- **TEST**: `REGRESSION-001`, `REGRESSION-003`, `REGRESSION-004`.
- **RESULT**: Kernel returns `EXDEV` (errno 18); access is blocked with `BLOCKED_BY_FIREWALL`.

---

## THREAT 2: Symlink Escape

- **ATTACK**: Symbolic link created inside an allowed directory pointing to a target outside the allowed directory.
- **PRECONDITION**: A symlink exists or is created within an allowed directory pointing to `/forbidden/secret.txt`.
- **ATTACK PATH**: Agent requests read of `/allowed/link_to_secret.txt`.
- **CURRENT DEFENSE (v0.1)**: Lexical path inspection.
- **CURRENT FAILURE**: Path `/allowed/link_to_secret.txt` starts with `/allowed`, so policy evaluates to `ALLOW`. Standard `fs::read` dereferences the symlink and reads forbidden data.
- **NEW DEFENSE**:
  1. Canonical target verification.
  2. Kernel enforcement via `openat2()` with `RESOLVE_BENEATH`. If the symlink destination is outside the directory tree rooted at `dirfd`, the kernel aborts with `EXDEV`.
- **TEST**: `REGRESSION-002`, `REGRESSION-007`, `REGRESSION-011`.
- **RESULT**: Kernel halts dereference at boundary; blocked with `BLOCKED_BY_FIREWALL`.

---

## THREAT 3: Time-of-Check to Time-of-Use (TOCTOU) / Symlink Race

- **ATTACK**: Concurrently replacing a legitimate file or directory with a symlink after authorization check but before the file is read.
- **PRECONDITION**: Agent or concurrent process can write or rename entries in the allowed directory.
- **ATTACK PATH**:
  1. Agent requests `/allowed/safe.txt`.
  2. Security system verifies `/allowed/safe.txt` is inside boundary.
  3. Attacker thread quickly unlinks `/allowed/safe.txt` and symlinks it to `/forbidden/secret.txt`.
  4. Security system opens and reads the path.
- **CURRENT DEFENSE (v0.1)**: None.
- **CURRENT FAILURE**: Check and Use are decoupled in time; malicious object opened.
- **NEW DEFENSE**: Atomic kernel resolution. The directory root descriptor is held open, and `openat2` performs resolution and file opening in a single atomic syscall with `RESOLVE_BENEATH`. Any symlink swap that tries to escape the root during resolution triggers `EXDEV` inside the kernel walk.
- **TEST**: `REGRESSION-008`, `REGRESSION-010`, `REGRESSION-015`.
- **RESULT**: TOCTOU race window eliminated at VFS layer.

---

## THREAT 4: Path Substitution & Redundant Separators

- **ATTACK**: Redundant slashes, relative dot prefixes, or alternate representations (e.g. `//forbidden`, `./forbidden`).
- **PRECONDITION**: Policy matcher assumes absolute, normalized paths.
- **ATTACK PATH**: Agent supplies relative path `../secret.txt` or `///allowed/../forbidden`.
- **CURRENT DEFENSE (v0.1)**: String prefix check.
- **CURRENT FAILURE**: Mismatches or accidental passes depending on path formatting.
- **NEW DEFENSE**: Lexical normalization + anchor to directory descriptor.
- **TEST**: `REGRESSION-004`, `REGRESSION-005`, `REGRESSION-006`.
- **RESULT**: Fail-closed denial.

---

## THREAT 5: Resource Replacement / Directory Renaming

- **ATTACK**: Renaming an allowed parent directory while access is in progress.
- **PRECONDITION**: Concurrent filesystem mutations.
- **ATTACK PATH**: Renaming `allowed/` to `moved/` and replacing with a symlink.
- **CURRENT DEFENSE (v0.1)**: String validation.
- **CURRENT FAILURE**: Path string no longer matches real filesystem inode.
- **NEW DEFENSE**: Pinning to directory file descriptor (`O_PATH | O_DIRECTORY`). File descriptors point to the kernel struct file/inode, unaffected by path renames.
- **TEST**: `REGRESSION-009`.
- **RESULT**: Access remains bound to the original inode or fails closed if invalidated.

---

## THREAT 6: Policy / Enforcement Mismatch

- **ATTACK**: Policy engine reports `DENY`, but enforcement mechanism fails to block physical access (or vice versa).
- **PRECONDITION**: Bug in enforcer logic or disconnected execution.
- **ATTACK PATH**: Policy evaluates to `DENY`, but the file is nonetheless opened and returned.
- **CURRENT DEFENSE (v0.1)**: Explicit check on `decision == Decision::Deny`.
- **NEW DEFENSE**: Tripartite contract:
  - If `decision == DENY`, enforcer will NOT call open syscall; verified failure.
  - If `decision == ALLOW`, enforcer executes kernel-confined open; if kernel rejects (`EXDEV`), observed result is `BLOCKED_BY_FIREWALL`, preventing any data leakage.
- **TEST**: All regression and unit tests.
- **RESULT**: Invariant INVARIANT-001 strictly enforced.
