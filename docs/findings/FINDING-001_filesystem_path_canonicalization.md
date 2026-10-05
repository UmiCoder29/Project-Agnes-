# FINDING-001: Lexical String-Based Policy Evaluation Allows Boundary Escapes

- **Finding ID**: FINDING-001
- **Severity**: High (Boundary Bypass)
- **Component**: Policy Engine / Filesystem Enforcer
- **Status**: Discovered & Documented

## Summary
In runtime security enforcement for autonomous agents, if policy evaluation relies on the raw lexical path submitted by the agent:
1. `../` directory traversal sequences allow an agent to construct paths that match the prefix of an allowed resource while resolving to a forbidden target.
2. Symbolic links residing within an allowed directory can dereference to forbidden target resources outside the security sandbox.

## Countermeasure for Next Iteration
1. **Canonicalization**: Canonicalize and sanitize path representations prior to policy evaluation.
2. **Kernel Enforcement**: Utilize Linux `openat2(2)` with `RESOLVE_BENEATH` or `RESOLVE_NO_SYMLINKS`, or Landlock sandboxing at the OS level to ensure the kernel itself enforces boundary restrictions regardless of lexical tricks.
