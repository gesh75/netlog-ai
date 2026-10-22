## Summary

<!-- What does this change and why? Link the issue / review finding. -->

## Verification

<!-- How did you test it? Paste commands and results. -->

- [ ] `ruff check src/ tests/` is clean
- [ ] Targeted tests pass; new behavior has tests (bug fixes have a regression test)
- [ ] Docs updated where behavior or configuration changed (README, `docs/ENVIRONMENT.md` for new env vars)

## Risk and rollback

- [ ] Any new path that sends text to an LLM goes through `sanitize()` first
- [ ] No real device configs, hostnames, tokens or customer data in samples/tests
- [ ] New environment variables are documented in `docs/ENVIRONMENT.md` and `.env.example`
- [ ] Behavior or default changes are called out below (and in the CHANGELOG)

**Risk level:** low / medium / high

**Rollback:** <!-- e.g. revert this PR; is there a data/schema migration to undo? -->
