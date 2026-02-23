# Browser Test Rules (Speed + Determinism)

- Run browser tests via `make test-browser`. Use native Go test parallelism (`go test -p ... -parallel ...`) configured in `Makefile`.
- Keep browser tests free of `t.Parallel()` unless a specific file is proven parallel-safe; package-level native parallelism is the default.
- Use `Navigate(...)` plus explicit selector waits. Prefer `LoadStateDomcontentloaded`; avoid `LoadStateNetworkidle`.
- Do not use unconditional sleeps/timeouts (`WaitForTimeout`, fixed `time.Sleep` without polling logic).
- For external dependencies (for example sprite readiness), use bounded polling with short intervals and explicit deadlines.
- Keep browser waits bounded by shared constants (`browserMaxTimeoutMS`, `spriteTimeoutMS` only where required).
- Use unique identities (`GenerateUniqueEmail(...)`) in browser tests. Avoid fixed authenticated emails.
- For email assertions, use recipient-scoped checks (`LastEmailForRecipient`) instead of global `LastEmail()`/`Count()` assumptions.
- Do not call global `EmailService.Clear()` inside browser tests.
- Prefer stable selectors (ID, attribute, role) over broad text-only waits.
