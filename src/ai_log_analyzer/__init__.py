"""AI Log Analyzer — classify network syslog, deep-analyze with LLM, score health.

Auto-loads .env files (in priority order) BEFORE any submodule reads os.environ,
so llm.py's module-level _state picks up ANTHROPIC_API_KEY, OLLAMA_MODEL, etc.

Env search order:
    1. <project>/.env              — lab-local override
    2. ~/.env                      — user-wide secrets
    3. ../DCN_Network_Tool/.env    — sibling tool (reuse existing lab key)
    4. ../DCN_AI_Intelligence/.env — sibling intelligence tool

Set AI_LOG_ANALYZER_DEBUG=1 to trace which .env files were loaded.
"""
from __future__ import annotations

# ── Version (single source of truth = pyproject.toml metadata) ───────────────
from importlib.metadata import (
    PackageNotFoundError as _PkgNFE,
    version as _pkg_version,
)

try:
    __version__: str = _pkg_version("ai-log-analyzer")
except _PkgNFE:
    __version__ = "0.2.0"  # fallback for non-installed / editable dev checkouts


# ── Env bootstrap (MUST run before submodule imports) ────────────────────────
def _load_env_files() -> None:
    """Discover and load .env files in priority order.

    - Uses override=False so already-set env vars are never clobbered.
    - Isolated in a function so no private names leak into the module namespace.
    - Set AI_LOG_ANALYZER_DEBUG=1 to print which files were loaded.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return  # python-dotenv not installed — silently skip

    import os
    import warnings
    from pathlib import Path

    try:
        pkg_dir = Path(__file__).resolve().parent       # …/src/ai_log_analyzer/
        proj_dir = pkg_dir.parent.parent                # …/AI_Log_Analyzer/
        root_dir = proj_dir.parent                      # workspace root (sibling tools)

        candidates: tuple[Path, ...] = (
            proj_dir / ".env",
            Path.home() / ".env",
            root_dir / "DCN_Network_Tool" / ".env",
            root_dir / "DCN_AI_Intelligence" / ".env",
        )

        loaded: list[str] = []
        for p in candidates:
            if p.is_file():
                load_dotenv(p, override=False)
                loaded.append(str(p))

        if os.getenv("AI_LOG_ANALYZER_DEBUG"):
            print(f"[ai_log_analyzer] .env sources loaded: {loaded or ['(none)']}")

    except Exception as exc:  # OSError, PermissionError, parse errors, etc.
        warnings.warn(
            f"ai_log_analyzer: .env auto-load failed — {exc}",
            RuntimeWarning,
            stacklevel=2,
        )


_load_env_files()
del _load_env_files  # keep the public namespace clean


# ── Public API ───────────────────────────────────────────────────────────────
from ai_log_analyzer.classifier import (  # noqa: E402
    ClassifiedEvent,
    LogEvent,
    classify_events,
)
from ai_log_analyzer.analyzer import (  # noqa: E402
    AnalysisResult,
    analyze,
    build_action_items,
    health_score,
)

__all__: list[str] = [
    # classifier
    "classify_events",
    "LogEvent",
    "ClassifiedEvent",
    # analyzer
    "analyze",
    "AnalysisResult",
    "build_action_items",
    "health_score",
    # metadata
    "__version__",
]

# Development-time completeness guard (stripped when Python runs with -O)
if __debug__:
    _missing = [n for n in __all__ if n not in globals()]
    if _missing:
        raise ImportError(
            f"ai_log_analyzer.__all__ declares undefined names: {_missing}"
        )
    del _missing
