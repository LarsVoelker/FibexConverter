#!/bin/bash

# Install all project dependencies into the active virtual environment.
#
# For testing FLYNC variants, the `flync` package can be replaced by a
# GitHub source using uv's pip-mode `--overrides`:
#
#   tools/update_depends.sh --flync-branch main
#
# Only `flync` is swapped; all other dependencies come from `uv sync`.

set -euo pipefail

FLYNC_GIT_URL="https://github.com/Technica-Engineering/FLYNC.git"
FLYNC_BRANCH="main"
USE_FLYNC_GIT=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Install all project dependencies (pinned FLYNC from PyPI by default).

Options:
  --flync-git <URL>      FLYNC git repository URL
                         (default: ${FLYNC_GIT_URL})
  --flync-branch <REF>   FLYNC git branch/tag/rev to use
                         (default: ${FLYNC_BRANCH})
  -h, --help             Show this help and exit

Examples:
  $(basename "$0")
      Sync all dependencies, using the pinned FLYNC from PyPI.

  $(basename "$0") --flync-branch main
      Sync all dependencies, then install FLYNC from the main branch.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --flync-git)
            FLYNC_GIT_URL="${2:-}"
            if [[ -z "${FLYNC_GIT_URL}" ]]; then
                echo "Error: --flync-git requires a URL" >&2
                exit 1
            fi
            USE_FLYNC_GIT=1
            shift 2
            ;;
        --flync-branch)
            FLYNC_BRANCH="${2:-}"
            if [[ -z "${FLYNC_BRANCH}" ]]; then
                echo "Error: --flync-branch requires a ref" >&2
                exit 1
            fi
            USE_FLYNC_GIT=1
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# Use the project virtual environment (existing project convention).
if [[ ! -f .venv/bin/activate ]]; then
    echo "Error: .venv/bin/activate not found. Create the venv first." >&2
    exit 1
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Syncing all project dependencies (uv sync)"
uv sync --all-groups --all-extras

if [[ "${USE_FLYNC_GIT}" -eq 1 ]]; then
    override_file="$(mktemp)"
    trap 'rm -f "$override_file"' EXIT

    flync_source="${FLYNC_GIT_URL}@${FLYNC_BRANCH}"
    echo "==> Installing FLYNC from ${flync_source}"
    printf 'flync @ git+%s\n' "${flync_source}" > "$override_file"

    uv pip install --overrides "$override_file" --reinstall-package flync flync
fi
