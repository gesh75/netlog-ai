"""Setup wizard: validators, generated config, prompt flow, CLI wiring."""
from __future__ import annotations

import stat

import pytest

from ai_log_analyzer import cli, init_wizard
from ai_log_analyzer.init_wizard import (
    InitConfig,
    render_env,
    run_init,
    validate_alpha,
    validate_cidr_list,
    validate_host,
    validate_keep,
    validate_path,
    validate_port,
    validate_token,
    validate_url,
    write_config,
)

pytestmark = pytest.mark.unit

_ENV_VARS = (
    "ANALYZER_HOST", "ANALYZER_PORT", "AI_LOG_ANALYZER_STATE_DB",
    "AI_LOG_ANALYZER_SYSLOG_ALLOW", "AI_LOG_ANALYZER_SNMP_COMMUNITY",
    "LLM_PROVIDER", "OLLAMA_URL", "OLLAMA_MODEL", "OPENAI_API_KEY",
    "AI_LOG_ANALYZER_EMBEDDINGS", "AI_LOG_ANALYZER_EMBEDDING_MODEL",
    "AI_LOG_ANALYZER_RAG_HYBRID_ALPHA", "AI_LOG_ANALYZER_TRIAGE_WORKER",
    "AI_LOG_ANALYZER_API_TOKEN", "NETLOG_SOURCE_syslog_BIND",
    "NETLOG_SOURCE_syslog_PORT", "NETLOG_SOURCE_traps_TYPE",
    "NETLOG_SOURCE_traps_PORT",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


# ── Validators ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", ["1", "6060", "65535"])
def test_validate_port_accepts(raw):
    assert validate_port(raw) == int(raw)


@pytest.mark.parametrize("raw", ["0", "65536", "-1", "abc", "6.5", ""])
def test_validate_port_rejects(raw):
    with pytest.raises(ValueError):
        validate_port(raw)


@pytest.mark.parametrize("raw", ["127.0.0.1", "0.0.0.0", "localhost", "core-01.example.com", "::1"])
def test_validate_host_accepts(raw):
    assert validate_host(raw) == raw


@pytest.mark.parametrize("raw", ["", "256.0.0.1", "-bad-", "a b", "host_name!"])
def test_validate_host_rejects(raw):
    with pytest.raises(ValueError):
        validate_host(raw)


@pytest.mark.parametrize("raw", ["http://localhost:11434", "https://api.openai.com/v1"])
def test_validate_url_accepts(raw):
    assert validate_url(raw) == raw


@pytest.mark.parametrize("raw", ["localhost:11434", "ftp://x", "http://", ""])
def test_validate_url_rejects(raw):
    with pytest.raises(ValueError):
        validate_url(raw)


def test_validate_path_accepts_existing_parent(tmp_path):
    assert validate_path(str(tmp_path / "sub" / "state.db"))


def test_validate_path_rejects_a_directory(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        validate_path(str(tmp_path))


@pytest.mark.parametrize("raw,expected", [
    ("", ""), ("10.0.0.0/8", "10.0.0.0/8"), ("192.0.2.10, 10.0.0.0/8", "192.0.2.10,10.0.0.0/8"),
])
def test_validate_cidr_list(raw, expected):
    assert validate_cidr_list(raw) == expected


@pytest.mark.parametrize("raw", ["999.0.0.1", "10.0.0.0/33", "not-an-ip"])
def test_validate_cidr_list_rejects(raw):
    with pytest.raises(ValueError):
        validate_cidr_list(raw)


@pytest.mark.parametrize("raw", ["0", "0.5", "1", "1.0"])
def test_validate_alpha_accepts(raw):
    assert validate_alpha(raw) == float(raw)


@pytest.mark.parametrize("raw", ["-0.1", "1.1", "abc"])
def test_validate_alpha_rejects(raw):
    with pytest.raises(ValueError):
        validate_alpha(raw)


def test_validate_keep_and_token():
    assert validate_keep("7") == 7
    with pytest.raises(ValueError):
        validate_keep("0")
    assert validate_token("a" * 16) == "a" * 16
    assert validate_token("") == ""
    with pytest.raises(ValueError):
        validate_token("short")


# ── Rendered config ──────────────────────────────────────────────────────────

def test_render_env_defaults_cover_the_essentials():
    text = render_env(InitConfig(state_db="/tmp/x/state.db", port=6071))
    for line in (
        "ANALYZER_HOST=127.0.0.1", "ANALYZER_PORT=6071",
        "AI_LOG_ANALYZER_STATE_DB=/tmp/x/state.db",
        "NETLOG_SOURCE_syslog_TYPE=syslog", "NETLOG_SOURCE_syslog_PORT=5514",
        "LLM_PROVIDER=ollama", "OLLAMA_URL=http://localhost:11434",
        "AI_LOG_ANALYZER_EMBEDDINGS=auto", "AI_LOG_ANALYZER_EMBEDDING_MODEL=nomic-embed-text",
        "AI_LOG_ANALYZER_RAG_HYBRID_ALPHA=0.5",
        "0 3 * * * netlog-ai backup --keep 7",
    ):
        assert line in text
    assert "NETLOG_SOURCE_traps_TYPE" not in text          # SNMP off by default
    assert "AI_LOG_ANALYZER_API_TOKEN" not in text         # no token by default


def test_render_env_snmp_and_cloud_provider():
    cfg = InitConfig(snmp_enabled=True, snmp_port=55162, snmp_community="trapsecret",
                     llm_provider="openai", cloud_api_key="sk-test-dummy-key",
                     embeddings_enabled=False, triage_enabled=True, api_token="t" * 16)
    text = render_env(cfg)
    for line in (
        "NETLOG_SOURCE_traps_TYPE=snmp", "NETLOG_SOURCE_traps_PORT=55162",
        "NETLOG_SOURCE_traps_COMMUNITY=trapsecret",
        "LLM_PROVIDER=openai", "OPENAI_API_KEY=sk-test-dummy-key",
        "AI_LOG_ANALYZER_EMBEDDINGS=0", "AI_LOG_ANALYZER_TRIAGE_WORKER=true",
        "AI_LOG_ANALYZER_API_TOKEN=" + "t" * 16,
    ):
        assert line in text
    assert "OLLAMA_URL" not in text


def test_render_env_cloud_provider_without_key_is_a_comment_not_a_secret():
    text = render_env(InitConfig(llm_provider="claude"))
    assert "ANTHROPIC_API_KEY=" not in text.replace("# ANTHROPIC_API_KEY=", "")
    assert "# ANTHROPIC_API_KEY=" in text
    assert "sk-" not in text


def test_rendered_env_parses_as_dotenv(tmp_path):
    from dotenv import dotenv_values

    cfg = InitConfig(snmp_enabled=True, llm_provider="grok", cloud_api_key="xai-test-dummy")
    path = tmp_path / ".env"
    path.write_text(render_env(cfg), encoding="utf-8")
    values = dotenv_values(path)
    assert values["ANALYZER_PORT"] == "6060"
    assert values["NETLOG_SOURCE_traps_TYPE"] == "snmp"
    assert values["XAI_API_KEY"] == "xai-test-dummy"
    assert values["LLM_PROVIDER"] == "grok"


# ── Writing (non-destructive) ────────────────────────────────────────────────

def test_write_config_refuses_to_overwrite_without_force(tmp_path):
    target = tmp_path / ".env"
    target.write_text("ORIGINAL=1\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_config(target, "NEW=1\n", force=False)
    assert target.read_text(encoding="utf-8") == "ORIGINAL=1\n"
    assert write_config(target, "NEW=1\n", force=True).read_text(encoding="utf-8") == "NEW=1\n"


def test_write_config_asks_before_overwriting(tmp_path):
    target = tmp_path / ".env"
    target.write_text("ORIGINAL=1\n", encoding="utf-8")
    answers = iter(["n", "y"])
    confirm = lambda prompt: next(answers) == "y"  # noqa: E731
    with pytest.raises(FileExistsError):
        write_config(target, "NEW=1\n", force=False, confirm=confirm)
    write_config(target, "NEW=1\n", force=False, confirm=confirm)
    assert target.read_text(encoding="utf-8") == "NEW=1\n"


def test_write_config_chmod_0600_when_a_secret_is_present(tmp_path):
    secret = write_config(tmp_path / "a.env", "OPENAI_API_KEY=sk-test\n", force=False)
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    plain = write_config(tmp_path / "b.env", "LLM_PROVIDER=ollama\n", force=False)
    assert stat.S_IMODE(plain.stat().st_mode) != 0o600


# ── Non-interactive run ──────────────────────────────────────────────────────

def test_run_init_non_interactive_writes_config_and_next_steps(tmp_path, capsys):
    out = tmp_path / ".env"
    printed: list[str] = []
    rc = run_init(out, non_interactive=True, force=False,
                  overrides={"port": 6071, "state_db": str(tmp_path / "state.db"),
                             "snmp_enabled": True, "snmp_port": 55162},
                  print_fn=printed.append)
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "ANALYZER_PORT=6071" in text and "NETLOG_SOURCE_traps_PORT=55162" in text
    joined = "\n".join(printed)
    assert "curl http://127.0.0.1:6071/api/health" in joined
    assert "0 3 * * * netlog-ai backup --keep 7" in joined
    assert "metrics_path: /api/metrics" in joined
    assert "netlog-ai doctor" in joined
    # Step numbers are sequential with no gaps (SNMP on adds one step).
    numbers = [int(line.split(".")[0]) for line in joined.splitlines()
               if line.startswith("  ") and line[2].isdigit() and ". " in line[:6]]
    assert numbers == list(range(1, len(numbers) + 1))


def test_run_init_non_interactive_refuses_existing_file_without_force(tmp_path):
    out = tmp_path / ".env"
    out.write_text("ORIGINAL=1\n", encoding="utf-8")
    assert run_init(out, non_interactive=True, force=False, print_fn=lambda _: None) == 1
    assert out.read_text(encoding="utf-8") == "ORIGINAL=1\n"
    assert run_init(out, non_interactive=True, force=True, print_fn=lambda _: None) == 0
    assert "ORIGINAL" not in out.read_text(encoding="utf-8")


def test_run_init_bad_override_is_exit_2_and_writes_nothing(tmp_path):
    out = tmp_path / ".env"
    rc = run_init(out, non_interactive=True, force=False,
                  overrides={"port": 99999}, print_fn=lambda _: None)
    assert rc == 2
    assert not out.exists()


def test_run_init_warns_for_cloud_provider_without_key(tmp_path):
    printed: list[str] = []
    rc = run_init(tmp_path / ".env", non_interactive=True, force=False,
                  overrides={"llm_provider": "openai"}, print_fn=printed.append)
    assert rc == 0
    assert any("OPENAI_API_KEY is not set" in line for line in printed)


def test_from_env_picks_up_existing_settings(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    monkeypatch.setenv("ANALYZER_PORT", "6061")
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", "/srv/state.db")
    cfg = InitConfig.from_env()
    assert (cfg.llm_provider, cfg.cloud_api_key) == ("openai", "sk-from-env")
    assert (cfg.port, cfg.state_db) == (6061, "/srv/state.db")


def test_from_env_unknown_provider_falls_back_to_ollama(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "not-a-provider")
    assert InitConfig.from_env().llm_provider == "ollama"


# ── Interactive prompt flow (mocked input) ───────────────────────────────────

class _FakeInput:
    """Answers in order; records the prompts shown."""

    def __init__(self, answers: list[str]):
        self._answers = iter(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        return next(self._answers)


def test_prompt_flow_accepts_defaults_and_writes_config(tmp_path):
    # One Enter per question (state_db, host, port, syslog y/n, bind, port,
    # allow, snmp y/n, provider, ollama url, ollama model, cloud fallback,
    # embeddings y/n, model, alpha, triage y/n, backup keep, api token).
    answers = ["", "", "", "y", "", "", "", "n", "ollama", "", "", "n",
               "y", "", "", "n", "", ""]
    fake = _FakeInput(answers)
    printed: list[str] = []
    out = tmp_path / ".env"
    rc = run_init(out, non_interactive=False, force=False,
                  input_fn=fake, print_fn=printed.append)
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "LLM_PROVIDER=ollama" in text and "NETLOG_SOURCE_syslog_PORT=5514" in text
    assert "NETLOG_SOURCE_traps_TYPE" not in text
    assert any("curl http://127.0.0.1:6060/api/health" in line for line in printed)
    assert any("State database path" in p for p in fake.prompts)
    assert any("LLM provider" in p for p in fake.prompts)


def test_prompt_flow_openai_key_and_custom_values(tmp_path):
    answers = [
        "/tmp/x/state.db", "127.0.0.1", "6072",      # state db, host, port
        "n",                                              # syslog off
        "y", "0.0.0.0", "55162", "public",                # snmp on, bind, port, community
        "openai", "sk-test-dummy-openai-key",              # provider, api key
        "n",                                              # embeddings off
        "y", "14",                                        # triage on, keep 14
        "",                                               # no api token
    ]
    fake = _FakeInput(answers)
    out = tmp_path / ".env"
    rc = run_init(out, non_interactive=False, force=False,
                  input_fn=fake, print_fn=lambda _: None)
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=sk-test-dummy-openai-key" in text
    assert "NETLOG_SOURCE_syslog_TYPE" not in text
    assert "NETLOG_SOURCE_traps_PORT=55162" in text
    assert "AI_LOG_ANALYZER_EMBEDDINGS=0" in text
    assert "AI_LOG_ANALYZER_TRIAGE_WORKER=true" in text
    assert "0 3 * * * netlog-ai backup --keep 14" in text
    assert stat.S_IMODE(out.stat().st_mode) == 0o600     # a secret was written


def test_prompt_flow_reprompts_on_invalid_port_then_accepts(tmp_path):
    answers = ["", "", "abc", "6073", "n", "n", "ollama", "", "", "n", "n", "n", "", ""]
    fake = _FakeInput(answers)
    printed: list[str] = []
    out = tmp_path / ".env"
    rc = run_init(out, non_interactive=False, force=False,
                  input_fn=fake, print_fn=printed.append)
    assert rc == 0
    assert "ANALYZER_PORT=6073" in out.read_text(encoding="utf-8")
    assert any("invalid" in line for line in printed)


def test_prompt_flow_eof_keeps_defaults(tmp_path):
    def _eof(prompt: str = "") -> str:
        raise EOFError

    out = tmp_path / ".env"
    rc = run_init(out, non_interactive=False, force=False,
                  input_fn=_eof, print_fn=lambda _: None)
    assert rc == 0
    assert "ANALYZER_PORT=6060" in out.read_text(encoding="utf-8")


# ── CLI wiring ───────────────────────────────────────────────────────────────

def test_cli_init_non_interactive(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.argv", ["netlog-ai", "init", "--non-interactive",
                                     "--output", str(tmp_path / ".env"),
                                     "--port", "6071", "--no-snmp"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "ANALYZER_PORT=6071" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert "curl http://127.0.0.1:6071/api/health" in capsys.readouterr().out


def test_cli_init_bad_port_is_exit_2(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.argv", ["netlog-ai", "init", "--non-interactive",
                                     "--output", str(tmp_path / ".env"), "--port", "99999"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert not (tmp_path / ".env").exists()
    assert "invalid configuration" in capsys.readouterr().out


def test_cli_init_help(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["netlog-ai", "init", "--help"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "--non-interactive" in capsys.readouterr().out


def test_next_steps_mentions_metrics_scrape():
    text = init_wizard.next_steps(InitConfig(port=6060), "/tmp/x/.env")
    assert "metrics_path: /api/metrics" in text
    assert "targets: ['127.0.0.1:6060']" in text
    assert "grafana/netlog-ai.json" in text
    assert "curl http://127.0.0.1:6060/api/health" in text
