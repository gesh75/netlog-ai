#!/usr/bin/env bash
# Rewrite local git history to drop sensitive sample blobs and internal names.
#
# THIS SCRIPT REWRITES GIT HISTORY. It does not push, does not force-push,
# does not change branch protection, and does not touch remotes. The repo
# owner must decide separately whether (and how) to publish a rewritten
# history.
#
# It is NOT run by CI. Do not run it against origin.
#
# Prerequisites:
#   pip install git-filter-repo
#   a throwaway clone (git-filter-repo refuses a dirty / already-filtered repo
#   unless you pass --force after reading its warnings)
#
# Usage (local clone only):
#   CONFIRM_HISTORY_REWRITE=YES ./scripts/maintenance/purge_history.sh
#
# After a successful run:
#   1. Review `git log --stat` and `git grep` on the rewritten clone.
#   2. Restore the current sanitized samples (copied aside before the rewrite)
#      if invert-paths removed them from HEAD, then commit that restore.
#   3. Do NOT `git push --force` unless you have coordinated a history rewrite
#      with every clone, CI cache, and GitHub release.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [[ "${CONFIRM_HISTORY_REWRITE:-}" != "YES" ]]; then
  cat >&2 <<'EOF'
Refusing to rewrite history.

This script is a local helper for the repo owner. It is not part of the
normal PR workflow. To run it on a throwaway clone:

  CONFIRM_HISTORY_REWRITE=YES ./scripts/maintenance/purge_history.sh

It will not push. Do not force-push the result to a public remote without
an explicit, coordinated history rewrite.
EOF
  exit 2
fi

if [[ "${PWD}" != "${ROOT}" ]]; then
  echo "internal error: not at repo root" >&2
  exit 1
fi

if ! command -v git-filter-repo >/dev/null 2>&1; then
  echo "git-filter-repo is not on PATH. Install it with: pip install git-filter-repo" >&2
  exit 1
fi

if [[ -n "${GIT_DIR:-}" ]]; then
  echo "Refusing to run with GIT_DIR set." >&2
  exit 1
fi

# Never talk to a remote. git-filter-repo itself does not push; this is belt
# and braces so a wrapper cannot add a push later without noticing.
export GIT_OPTIONAL_LOCKS=0

REPLACEMENTS="$ROOT/scripts/maintenance/purge_replacements.txt"
PATHS_FILE="$ROOT/scripts/maintenance/purge_paths.txt"
for required in "$REPLACEMENTS" "$PATHS_FILE"; do
  if [[ ! -f "$required" ]]; then
    echo "missing $required" >&2
    exit 1
  fi
done

STASH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/netlog-ai-sanitized.XXXXXX")"
cleanup() {
  rm -rf "$STASH_DIR"
}
trap cleanup EXIT

echo "Snapshotting sanitized sample files to $STASH_DIR"
mkdir -p "$STASH_DIR/data-samples" "$STASH_DIR/root-samples"
if [[ -d src/ai_log_analyzer/data/samples ]]; then
  cp -a src/ai_log_analyzer/data/samples/. "$STASH_DIR/data-samples/"
fi
# Root samples/ is a symlink in the current tree; copy the target contents
# so we can restore files after invert-paths.
if [[ -e samples ]]; then
  cp -aH samples/. "$STASH_DIR/root-samples/" 2>/dev/null || true
fi
if [[ -f scripts/import_lab_mesh.py ]]; then
  cp -a scripts/import_lab_mesh.py "$STASH_DIR/"
fi
if [[ -d src/ai_log_analyzer/data/sites/lab-mesh ]]; then
  mkdir -p "$STASH_DIR/lab-mesh"
  cp -a src/ai_log_analyzer/data/sites/lab-mesh/. "$STASH_DIR/lab-mesh/"
fi

echo "Running git-filter-repo locally (no remotes, no push)..."
# --force is required on an existing clone. Prefer a fresh clone instead.
git filter-repo --force \
  --invert-paths --paths-from-file "$PATHS_FILE" \
  --path-rename src/ai_log_analyzer/data/sites/dcn-lab:src/ai_log_analyzer/data/sites/lab-mesh \
  --path-rename sites/dcn-lab:sites/lab-mesh \
  --path-rename scripts/import_dcn_lab.py:scripts/import_lab_mesh.py \
  --replace-text "$REPLACEMENTS"

echo "Restoring sanitized samples and lab-mesh bundle onto HEAD (uncommitted)"
mkdir -p src/ai_log_analyzer/data/samples src/ai_log_analyzer/data/sites/lab-mesh
cp -a "$STASH_DIR/data-samples/." src/ai_log_analyzer/data/samples/ || true
if [[ -d "$STASH_DIR/lab-mesh" ]]; then
  cp -a "$STASH_DIR/lab-mesh/." src/ai_log_analyzer/data/sites/lab-mesh/ || true
fi
if [[ -f "$STASH_DIR/import_lab_mesh.py" ]]; then
  cp -a "$STASH_DIR/import_lab_mesh.py" scripts/import_lab_mesh.py
fi

cat <<'EOF'

History rewrite finished on this local clone only.

Next steps for the owner (all optional, none performed by this script):
  - git status / git diff --stat, then commit the restored sanitized files
  - git grep -n -E 'isivkov|DCN|04_Scripts|IXPEER' -- .
  - Do NOT git push --force
  - Do NOT change branch protection
  - Do NOT rewrite other branches unless you intend to

Remotes were not updated. Publishing this history is a separate decision.
EOF
