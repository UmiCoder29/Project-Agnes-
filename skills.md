skills.md: Project Agnes change discipline

Applies to every change in the Project Agnes workspace (agnes-common, agnes-policy, agnes-enforcement, agnes-state, agnes-telemetry, agnes-core, agnes-tests). Follow it together with the Master Context.

1. State the problem precisely.
   Before writing code, say in one sentence which function in which crate is wrong, or which gap exists, and why. If you cannot, you do not understand it yet.

2. Hunt for siblings.
   Fixes have repeatedly landed in one place while another call site kept the old behavior. Grep the whole workspace for every other place that touches the same logic, data, or assumption. List each place you checked and what you found, even if you changed nothing. Check the effect on EVERY action type and every caller, not just the one in the test.

3. A regression test must fail on the old code.
   Run each new test against the pre fix code and show it failing. A test that passes on both old and new code is a guard, and you must say so plainly instead of calling it a fix test. Then run a mutation check: break the fix again and show which tests fail. If none fail, the tests are not pinning the fix.

4. Tests must be reliable.
   Tests that touch shared process state (working directory, environment variables, global locks) must serialize and must recover from a poisoned lock. Avoid probabilistic assertions. Run the whole workspace as a non root user and paste the per suite result lines.

5. No test only code in production builds.
   Counters, hooks, and instrumentation must sit behind a feature flag such as test-hooks or #[cfg(test)]. Say how you gated them.

6. Fail closed, always.
   Any new edge case, error path, or ambiguous input denies or rejects. A rule, policy, or config that cannot be fully validated is rejected as a whole. Never drop, skip, or partially apply it.

7. No decision may depend on process state.
   Working directory, environment, locale, and clock must not change a policy decision.

8. Think like the adversary who reads this diff.
   Name at least one way to attack the exact thing you changed. If your change does not handle it, say so.

9. Stay in scope, and report what is outside it.
   Do not build later milestone features. If you find a problem outside this change, report it in the summary instead of silently fixing it.

10. Be honest about verification.
   State what you could not run or confirm. Do not claim a result you did not observe.

11. End with a real summary.
   What changed. Every other location checked and left alone. What you deliberately did not fix and why. What you could not verify. Any new risk the next change should know about. Test counts before and after. A suggested commit message that describes the change and does not use prompt numbers.