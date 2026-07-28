---
applyTo: "**/*.py"
---

# Python

- Target the repo's declared `requires-python`. Do not use syntax newer than that.
- Full type annotations, including return types. Use `from __future__ import annotations`
  where it keeps signatures readable.
- Prefer `pathlib.Path` over `os.path`, f-strings over `%`/`.format()`,
  `dataclasses`/`pydantic` over ad-hoc dicts for structured data.
- Use `httpx.AsyncClient` (or the repo's existing async client) for HTTP. Never `requests`
  inside async code.
- Exceptions: raise specific types, never bare `except:`. `except Exception` requires a
  logged reason and a comment explaining why it is safe to continue.
- Immutability: return new lists/dicts/dataclasses rather than mutating inputs.
  `dataclasses.replace()` and `{**old, "k": v}` are preferred over in-place edits.
- Logging: module-level `logger = logging.getLogger(__name__)`. Never `print()` in library code.
  Never log secrets, tokens, or personally identifying data.
- Run `ruff check --fix` and `ruff format` on anything you touch.
