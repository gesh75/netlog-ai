# netlog-ai

AI-powered network log analyzer with LLM-assisted root-cause analysis for Junos, EOS, and FRR. Runs against a local Docker Model Runner or Anthropic Claude, and sanitizes log content before it reaches any model. MIT licensed, published to PyPI.

**Stack.** Python >=3.10, packaged via `pyproject.toml`. Docker + docker-compose. JS front end.

**Layout.** `src/` package, `demo/`, `scripts/`, `tests/`, `docs/`

## Build and test

```bash
python -m pip install --upgrade pip
pip install -e '.[dev]' || { pip install -e .; pip install pytest pytest-cov ruff; }
python -m pytest -q
```

Run the tests before proposing a change is done. If you cannot run them, say so explicitly
rather than claiming the change is verified.

## Engineering conventions (non-negotiable)

- **Type hints on every function signature.** No bare `def f(x):`.
- **async/await for all I/O.** Never block the event loop with sync network or disk calls.
- **Immutable data.** Return new objects; do not mutate arguments in place.
- **Tests first.** Write the failing test, watch it fail, then implement. Target 80%+ coverage.
- **Small files.** 200-400 lines typical, 800 hard max. Extract modules rather than growing a file.
- **Small functions.** Under 50 lines. Nesting no deeper than 4 levels - use early returns.
- **Handle every error explicitly.** Never swallow an exception silently. Log context server-side,
  return a friendly message user-side.
- **Validate at boundaries.** Never trust user input, API responses, or file contents.
- **No hardcoded secrets, ever.** Environment variables or a secret manager only. No credentials
  in code, comments, logs, tests, or fixtures.
- **Conventional Commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`.
  Imperative mood, lower case, no trailing period. Do **not** add `Co-authored-by` trailers.

## Before you propose a change

1. Read the surrounding code and match its idiom, naming, and comment density.
2. Prefer a battle-tested library over hand-rolled utility code.
3. If you touch auth, user input, DB queries, file paths, or external calls, re-read the
   security rules above before finishing.

## Public repo + published package - extra care

- **Sanitize before LLM is the core guarantee.** Any new code path that sends log content to a
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
- Summarise the whole commit range, not just the last commit.
