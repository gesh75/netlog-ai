# netlog-ai

AI-powered network log analyzer with LLM-assisted root-cause analysis for Junos, EOS, and FRR.
Runs against a local Docker Model Runner or Anthropic Claude, and sanitizes log content before
it reaches any model. MIT licensed, published to PyPI.

**Stack.** Python >=3.10, packaged via `pyproject.toml`. Docker + docker-compose. JS front end.

**Layout.** `src/` package, `demo/`, `scripts/`, `tests/`, `docs/`

## Build and test

```bash
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest -q
```

Note: the `parse` and `all` extras pin `tfsm-fire`, which is **not published on PyPI**. Install
the `dev` extra for development; `.[all,dev]` currently fails to resolve.

## Engineering conventions (non-negotiable)

- **Type hints on every function signature.** No bare `def f(x):`.
- **async/await for I/O** in async code paths. Never block an event loop with a sync call.
- **Immutable data.** Return new objects; do not mutate arguments in place.
- **Tests first.** Write the failing test, watch it fail, then implement. Target 80%+ coverage.
- **Small files.** 200-400 lines typical, 800 hard max. Extract modules rather than growing a file.
- **Small functions.** Under 50 lines. Nesting no deeper than 4 levels - use early returns.
- **Handle every error explicitly.** Never swallow an exception silently.
- **Validate at boundaries.** Never trust user input, API responses, or file contents.
- **No hardcoded secrets, ever.** Environment variables or a secret manager only. No credentials
  in code, comments, logs, tests, or fixtures.
- **Conventional Commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`.
  Imperative mood, lower case, no trailing period. Do **not** add `Co-authored-by` trailers.

## Public repo + published package - extra care

- **Sanitize before LLM is the core guarantee.** Any new code path sending log content to a
  model must route through the existing sanitizer. Never add a "raw" or "skip-sanitize" mode.
  Log lines carry IPs, hostnames, ASNs, community strings, and occasionally credentials.
- This is a **public MIT repo published to PyPI**. Nothing internal, customer-identifying, or
  employer-specific may appear in code, tests, fixtures, docs, or commit messages.
- Test fixtures must use RFC 5737 / RFC 3849 documentation addresses and obviously fake
  hostnames - never real captured device output.
- Keep `CHANGELOG.md` current; releases are cut from it via `release.yml`.
- Public API changes need a version bump and a CHANGELOG entry in the same PR.

## Pull requests

- Title in Conventional Commits form.
- Body covers: what changed, why, blast radius, and a test plan as a checklist.
