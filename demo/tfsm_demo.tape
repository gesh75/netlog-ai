# VHS tape — records netlog-ai's new tfsm_fire auto-detect parser in action.
#
# Run:  cd 04_Scripts_Tools/netlog-ai && vhs demo/tfsm_demo.tape
#
# Produces:
#   demo/tfsm_demo.mp4   — 1280×800, ~45s, suitable for LinkedIn/YouTube
#   demo/tfsm_demo.gif   — same content, GIF for README embedding

Output demo/tfsm_demo.mp4
Output demo/tfsm_demo.gif

# Visual settings — large readable font, dark theme matches the repo's existing demos.
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1280
Set Height 800
Set Padding 24
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0

# Hide the cd; just position the shell at netlog-ai root.
Hide
Type "clear" Enter
Show

# ─── ACT 1 · framing ──────────────────────────────────────────────────────────
Type "# netlog-ai · NEW: tfsm_fire auto-detect parser"
Sleep 800ms
Enter
Type "# scottpeterman/tfsm_fire wired in as a fallback parser"
Sleep 800ms
Enter
Sleep 600ms

# ─── ACT 2 · install proof ────────────────────────────────────────────────────
Type ".venv/bin/pip show tfsm-fire | head -3"
Sleep 300ms
Enter
Sleep 1200ms

# ─── ACT 3 · the driver script ────────────────────────────────────────────────
Type "# Pasting any device output through one function:"
Sleep 500ms
Enter
Sleep 400ms
Type ".venv/bin/python demo/tfsm_demo.py"
Sleep 300ms
Enter
Sleep 5500ms      # let the driver print all four sections

# ─── ACT 4 · proof of tests ───────────────────────────────────────────────────
Type "# 11 unit tests — real templates against canned device output:"
Sleep 500ms
Enter
Sleep 400ms
Type ".venv/bin/python -m pytest tests/test_tfsm_auto.py -q --no-header --tb=no"
Sleep 300ms
Enter
Sleep 3500ms      # ~1s test run plus pause to read

# ─── ACT 5 · close card ───────────────────────────────────────────────────────
Type "# Shipped → gesh75/netlog-ai · commit 31bd3f7"
Enter
Type "# Docs:  docs/TFSM_AUTO_PARSER.md"
Enter
Sleep 2500ms
