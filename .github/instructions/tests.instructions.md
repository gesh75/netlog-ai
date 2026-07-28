---
applyTo: "tests/**"
---

# Tests

- pytest only. No `unittest.TestCase` classes in new code.
- Name tests `test_<unit>_<scenario>_<expected>` so failures read as sentences.
- Prefer fixtures over setup/teardown methods; prefer `@pytest.mark.parametrize` over loops.
- Every bug fix starts with a regression test that fails before the fix.
- Cover the error paths, not just the happy path: bad input, network failure, empty result,
  boundary values.
- Never hit the live network. Mock at the client boundary with `respx`, `responses`,
  or `monkeypatch`.
- Tests must be order-independent and safe to run with `pytest -n auto`.
- No secrets or real credentials in fixtures - use obviously fake values.
