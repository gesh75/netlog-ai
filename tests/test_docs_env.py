"""Every environment variable read in src/ must be documented in docs/ENVIRONMENT.md.

Undocumented knobs (several of them security-relevant, e.g. DOCKER_EXEC_FALLBACK,
which defaults to true) were found missing in review. This keeps the page honest.

Detection is textual so it also covers code inside generated-script templates:
  1. a string literal passed as the first argument to ``os.environ.get/setdefault/pop``,
     ``os.environ[...]``, ``os.getenv``, an alias such as ``e("NAME")``, or any helper whose
     name contains ``env`` (``_env_float("NAME", ...)``, ``_int_env(...)``, ``_env_flag(...)``);
  2. any string literal shaped like a project variable (``AI_LOG_ANALYZER_*``, ``NETLOG_*``,
     ``LLM_*``) so names kept in module constants are also caught.
Dynamic names built at runtime are covered by DYNAMIC_NAMES below.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "ai_log_analyzer"
DOC = ROOT / "docs" / "ENVIRONMENT.md"
ENV_EXAMPLE = ROOT / ".env.example"

# Names that are read by src/ but intentionally undocumented (internal or test-only).
ALLOWLIST: frozenset[str] = frozenset()

# Built at runtime (f-strings / prefixes), so the literal scan cannot see them.
DYNAMIC_NAMES = (
    "AI_LOG_ANALYZER_VIEWER_TOKENS",
    "AI_LOG_ANALYZER_OPERATOR_TOKENS",
    "AI_LOG_ANALYZER_ADMIN_TOKENS",
    "LLM_MAX_PROMPT_CHARS_<PROVIDER>",
    "NETLOG_SOURCE_<id>_<KEY>",
)

_NAME = r"([A-Z][A-Z0-9_]{2,})"
_CALL_RE = re.compile(
    r"(?:environ\.get|environ\.setdefault|environ\.pop|environ\s*\[|getenv|\b\w*env\w*|\be)"
    r"\s*[(\[]\s*[\"']" + _NAME + r"[\"']",
    re.IGNORECASE,
)
_PROJECT_LITERAL_RE = re.compile(r"[\"']((?:AI_LOG_ANALYZER|NETLOG|LLM)_[A-Z0-9_]*[A-Z0-9])[\"']")


def _source_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def env_names_in_src() -> dict[str, str]:
    """name -> first 'file:line' that reads it."""
    found: dict[str, str] = {}
    for path in _source_files():
        text = path.read_text(encoding="utf-8")
        for regex in (_CALL_RE, _PROJECT_LITERAL_RE):
            for m in regex.finditer(text):
                name = m.group(1)
                # The case-insensitive call matcher can capture mixed-case literals
                # (e.g. a dict key passed to `.get_env_thing`); env vars are upper-case.
                if name != name.upper():
                    continue
                line = text.count("\n", 0, m.start()) + 1
                found.setdefault(name, f"{path.relative_to(ROOT)}:{line}")
    return found


def test_scanner_sees_known_variables():
    """Guard the guard: if the regexes rot, the main test would pass vacuously."""
    names = env_names_in_src()
    for expected in (
        "LLM_PROVIDER",             # os.environ.get, module-level dict
        "AI_LOG_ANALYZER_DEDUP",    # _env_flag helper
        "AI_LOG_ANALYZER_TRIAGE_COOLDOWN_S",  # _env_float helper
        "AI_LOG_ANALYZER_TRIAGE_SINKS",       # aliased e("...") / multi-line call
        "NET_PASS",                 # inside a generated-script template
        "DOCKER_EXEC_FALLBACK",
    ):
        assert expected in names, f"scanner no longer detects {expected}"
    assert len(names) >= 60


def test_every_env_var_read_in_src_is_documented():
    doc = DOC.read_text(encoding="utf-8")
    missing = {
        name: where
        for name, where in env_names_in_src().items()
        if name not in ALLOWLIST and f"`{name}`" not in doc and f"`{name}" not in doc
    }
    assert not missing, (
        "environment variables read in src/ but missing from docs/ENVIRONMENT.md "
        f"(add a row, or allowlist an internal-only name): {missing}"
    )


@pytest.mark.parametrize("name", DYNAMIC_NAMES)
def test_dynamic_names_are_documented(name):
    assert f"`{name}`" in DOC.read_text(encoding="utf-8")


def test_env_example_mentions_every_documented_security_toggle():
    """The security-relevant defaults must be visible where operators copy config from."""
    example = ENV_EXAMPLE.read_text(encoding="utf-8")
    for name in ("DOCKER_EXEC_FALLBACK", "NETBOX_TOKEN", "AI_LOG_ANALYZER_REQUIRE_AUTH",
                 "NETLOG_MCP_TRANSPORT", "LLM_ALLOW_CLOUD_FALLBACK"):
        assert name in example, f".env.example does not mention {name}"


def test_env_example_has_no_real_looking_secrets():
    """Placeholders only: any value assigned to a secret-ish key must be empty or an
    obvious placeholder, and long random-looking strings are rejected."""
    secretish = re.compile(r"(TOKEN|PASSWORD|PASS|API_KEY|SECRET|PSEUDONYM_KEY)S?=(.*)$")
    for raw in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = raw.lstrip("# ").strip()
        m = secretish.search(line.split()[0] if line.split() else "")
        if not m:
            continue
        value = m.group(2).strip()
        assert not re.fullmatch(r"[A-Za-z0-9+/_\-]{24,}", value), f"real-looking secret: {raw!r}"
