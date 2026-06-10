# Contributing

Thanks for your interest in netlog-ai. The short version:

## Setup

```bash
git clone https://github.com/gesh75/netlog-ai.git
cd netlog-ai
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,all]"
```

## Before you open a PR

```bash
ruff check src/ tests/   # must be clean
pytest                   # full suite must pass
```

Both run in CI (Python 3.10–3.12) on every PR — see `.github/workflows/ci.yml`.

## Guidelines

- **Commits:** conventional format — `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`.
- **Tests:** new behavior ships with tests. Bug fixes ship with a regression test.
- **Sanitize-before-LLM:** any new code path that sends text to an LLM provider
  must route configs through `sanitize()` first. This is the project's core
  privacy guarantee — PRs that bypass it will be rejected.
- **Samples:** never commit real device configs. Use RFC 5737/3849 documentation
  prefixes, private ASNs (64512–65534), and pseudonymized hostnames.

## Reporting issues

Use [GitHub Issues](https://github.com/gesh75/netlog-ai/issues). For suspected
security issues (e.g. a sanitization bypass), please mark the issue clearly.
