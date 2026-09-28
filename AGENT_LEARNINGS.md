# AGENT_LEARNINGS.md

Repo-only lessons for netlog-ai. Cross-repo lessons stay in `~/.cursor/AGENT_LEARNINGS.md`.

## Entries

### [2026-09-25] [env] The src-layout .env path was already the repo root
- **Mistake:** Replacing `pkg_dir.parent.parent` with `pkg_dir.parents[1]` and treating it as the reason `.env` did not load.
- **Avoid:** Committing that edit. Both expressions resolve to the repo root (`/Users/georgigaydarov/Projects/netlog-ai`).
- **Instead:** Check the serve process. `ps eww -p <listener>` must show `AI_LOG_ANALYZER_INCIDENT_STORE`. A `.env` on disk does nothing for a process that started without it.

### [2026-09-25] [journal] No action items means nothing is stored
- **Mistake:** Two analyzes of `de-fra-core-01` with tail 40 left `incidents.jsonl` unchanged and the brief had no `Repeat:` line.
- **Avoid:** Treating a score of 100 as proof the journal ran. That tail had 34 events and 0 action items, so `record()` returned 0.
- **Instead:** Use tail 500 on `de-fra-core-01`. A ranked BGP peer-down item is what gets appended. The second run in 7 days prints `Repeat: de-fra-core-01 routing N times in 7 days`. July rows stay outside the window.

### [2026-09-25] [journal] Fixture proof rows stay out of the live journal
- **Mistake:** Posting the five test-suite lines (AP down, 802.1X, DHCP, WAN failover, VPN) through the live `/api/analyze` appended them to `~/.cache/netlog-ai/incidents.jsonl`.
- **Avoid:** Leaving those hosts in the 7-day window.
- **Instead:** Snapshot the file, run the proof, then write the previous lines back. Say in the reply that the lines were fixtures, not a router log.

### [2026-09-25] [syslog] The Listen button binds on source create
- **Mistake:** Expecting the button label alone to open UDP 5514.
- **Avoid:** Stopping after the toast text.
- **Instead:** `POST /api/sources` with `type: syslog` and `extra.port: 5514` binds immediately (`SyslogListenerSource.__init__`). Confirm with `lsof -nP -iUDP:5514` and `POST /api/sources/lab-syslog/test` returning `{"ok":true}`.

### [2026-09-25] [serve] Exit 143 is the previous UI
- **Mistake:** Reading exit 143 on an old `ai_log_analyzer.cli serve` as a crash of the current UI.
- **Avoid:** Restarting again because a killed process reported 143.
- **Instead:** `curl -sS http://127.0.0.1:6060/api/health`. Version `0.7.0` and `"ok":true` means the replacement is up. Interpreter is `.venv/bin/python3.14`, not `.venv/bin/python`.
