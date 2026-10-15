SKILL.md — Project Agnes Fix Verification Discipline

This applies to every prompt executed against the Project Agnes codebase
(Rust workspace: agnes-common, agnes-policy, agnes-enforcement, agnes-state,
agnes-telemetry, agnes-core, agnes-tests). Follow this in addition to the
Master Context rules for whichever milestone prompt you are given.

1. Restate the bug precisely.
   Before writing code, state in one sentence exactly which function and
   crate is wrong, and why. If you cannot do this precisely, you do not
   understand the bug well enough to fix it.

2. Hunt for siblings before declaring done.
   Project Agnes has repeated the same mistake more than once: a fix lands
   in one function (e.g. resolve_real_path in policy/src/path.rs) while a
   sibling call site (e.g. the enforcer in enforcement/src/filesystem.rs,
   or matches_resource's own canonicalization fallback in policy/src/model.rs)
   still has the old, inconsistent behavior. Before finishing any prompt,
   grep the whole workspace for every other place that touches the same
   logic, data, or assumption you just changed. List every other call site
   you checked and what you found there, even if you changed nothing.

3. A regression test must fail on the old code.
   Every new regression test must be checked against the pre-fix version
   of the code and shown to fail there. A test that would pass against
   both the old and new code (like the first version of the atomic
   resolution test) is not a regression test, it's decoration, and it will
   be rejected in review. State explicitly, in your summary, why the test
   would have failed before your fix.

4. No test-only scaffolding in production code.
   Counters, hooks, or instrumentation added only to prove a fix (like the
   global resolution counter and hook) must be gated behind a feature flag
   such as test-hooks or #[cfg(test)], never shipped in a normal build.
   Say explicitly in your summary that you gated it and how.

5. Fail closed, always.
   Any new edge case, error path, or ambiguous input introduced by your
   change must deny or reject by default, never silently allow or fall
   back to old behavior.

6. Think like the adversary who reads this diff.
   Before finishing, name at least one way an adversary would specifically
   target the exact thing you just changed. If your fix doesn't already
   handle it, say so plainly instead of staying silent about it.

7. End with a real summary, not a changelog.
   Every response must end with: what you changed, every other location in
   the workspace you checked and did not need to change, what you
   deliberately did not fix and why, and any new risk this change
   introduces that the next prompt should know about.