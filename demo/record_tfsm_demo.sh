#!/usr/bin/env bash
# Record the tfsm_fire demo as a webm video.
#
# Pipeline:  asciinema rec → .cast file → agg renders frames → ffmpeg → .webm + .gif
#
# Run:  cd 04_Scripts_Tools/netlog-ai && bash demo/record_tfsm_demo.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

CAST="$HERE/tfsm_demo.cast"
GIF="$HERE/tfsm_demo.gif"
WEBM="$HERE/tfsm_demo.webm"

# Make a self-driving shell script that asciinema will replay.
DRIVER="$(mktemp -t netlog-tfsm-XXXX.sh)"
trap 'rm -f "$DRIVER"' EXIT

cat >"$DRIVER" <<'SH'
#!/usr/bin/env bash
# This script is recorded by asciinema. Each `echo` / sleep mimics a live demo
# narrator — natural pauses, visible commands, no surprises.
typeit() {
    # Type a command character-by-character so the recording looks live.
    local cmd="$1"
    for (( i=0; i<${#cmd}; i++ )); do
        printf '%s' "${cmd:$i:1}"
        sleep 0.025
    done
    printf '\n'
}

clear
echo -e "\033[1;36m# netlog-ai · NEW: tfsm_fire auto-detect parser\033[0m"
echo -e "\033[2m# scottpeterman/tfsm_fire wired in as a fallback parser\033[0m"
sleep 1
echo

# ─── proof of install ─────────────────────────────────────────────────────────
typeit ".venv/bin/pip show tfsm-fire | head -3"
.venv/bin/pip show tfsm-fire | head -3
sleep 1.5
echo

# ─── the driver script ────────────────────────────────────────────────────────
echo -e "\033[2m# Pasting any device output through one function:\033[0m"
sleep 0.4
typeit ".venv/bin/python demo/tfsm_demo.py"
.venv/bin/python demo/tfsm_demo.py
sleep 2
echo

# ─── tests ────────────────────────────────────────────────────────────────────
echo -e "\033[2m# 11 unit tests — real templates against canned device output:\033[0m"
sleep 0.4
typeit ".venv/bin/python -m pytest tests/test_tfsm_auto.py -q --no-header --tb=no"
.venv/bin/python -m pytest tests/test_tfsm_auto.py -q --no-header --tb=no
sleep 2
echo

# ─── close card ───────────────────────────────────────────────────────────────
echo -e "\033[1;32m✓ Shipped → gesh75/netlog-ai · commit 31bd3f7\033[0m"
echo -e "\033[2m  Docs:  docs/TFSM_AUTO_PARSER.md\033[0m"
sleep 2
SH

chmod +x "$DRIVER"

echo "▶ Recording asciinema cast to $CAST"
rm -f "$CAST"
asciinema rec \
    --command "bash $DRIVER" \
    --rows 32 --cols 120 \
    --idle-time-limit 2.5 \
    --quiet \
    "$CAST"

echo "▶ Rendering GIF with agg → $GIF"
agg --cols 120 --rows 32 \
    --font-size 16 \
    --theme monokai \
    --speed 1.0 \
    "$CAST" "$GIF"

echo "▶ Converting GIF → WebM via ffmpeg → $WEBM"
ffmpeg -y -loglevel error \
    -i "$GIF" \
    -c:v libvpx-vp9 -b:v 0 -crf 32 -row-mt 1 \
    -pix_fmt yuv420p \
    "$WEBM"

echo
echo "✅  Done."
ls -lh "$CAST" "$GIF" "$WEBM"
