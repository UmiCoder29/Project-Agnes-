# EXPERIMENT REPORT: EXP-001 & EXP-002

- **Date**: 2026-10-05
- **Experiment ID**: EXP-001 / EXP-002
- **Component**: Project Agnes Filesystem Security Boundary & Gateway
- **Target Actions**: `READ_FILE`

---

## 1. Objectives & Hypotheses

- **TEST-001 (Allowed File Read)**:
  - *Hypothesis*: An action explicitly matching an ALLOW policy will be permitted and the actual target content retrieved.
  - *Result*: **SUPPORTED** (`ALLOW` decision, `PERMIT_EXECUTION` enforcement, `ACCESS_SUCCESS` observed).

- **TEST-002 (Forbidden File Read)**:
  - *Hypothesis*: An action targeting a resource outside permitted boundaries will be blocked by default-deny (fail-closed) policy and access will physically fail.
  - *Result*: **SUPPORTED** (`DENY` decision, `BLOCK_REQUEST` enforcement, `BLOCKED_BY_FIREWALL` observed).

---

## 2. Adversarial Bypass Attempts (Bypass Testing on TEST-002)

### Bypass 1: Uncanonicalized Path Traversal (`../`)
- **Payload**: `/allowed/../forbidden/secret.txt`
- **Mechanism**: The policy engine performed prefix matching against the uncanonicalized request string.
- **Observed Result**:
  - Decision: `ALLOW` (Vulnerability)
  - Enforcement: `PERMIT_EXECUTION`
  - Observed Result: `ACCESS_SUCCESS` (Secret data leaked: `HIGHLY_CONFIDENTIAL_KEY=sk-99999-forbidden`)
- **Root Cause**: Naive string-based policy matching without canonicalization before policy evaluation, combined with unsanitized file descriptor opening.

### Bypass 2: Symlink Escape (`link_to_secret.txt -> /forbidden/secret.txt`)
- **Payload**: `/allowed/link_to_secret.txt`
- **Mechanism**: A symbolic link was created inside an allowed path pointing to a forbidden resource outside the boundary.
- **Observed Result**:
  - Decision: `ALLOW` (Vulnerability)
  - Enforcement: `PERMIT_EXECUTION`
  - Observed Result: `ACCESS_SUCCESS` (Secret data leaked: `DATABASE_MASTER_PASSWORD=SuperSecret123!`)
- **Root Cause**: Policy evaluated only the lexical path, failing to evaluate the canonical resolved target at runtime, allowing symlink dereference attacks.

---

## 3. Telemetry Evidence Summary
Both standard tests and adversarial runs produced complete structured audit records with correlation IDs, policy IDs, rule IDs, enforcement actions, and observed results.
