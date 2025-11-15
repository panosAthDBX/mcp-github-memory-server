#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install_macos.sh [options]

Builds and installs the gitmem CLI, then updates the Codex MCP configuration
to point at the git-backed working tree.

Options:
  --backend-root <path>    Absolute or relative path to the git-backed working tree.
                           Defaults to <repo>/tmp/gitmem-github.
  --config-name <name>     Entry name to use inside ~/.codex/mcps.json (default: gitmem).
  --device-branch <name>   Sets GITMEM_DEVICE_BRANCH in Codex config.
                           Defaults to devices/<hostname>.
  --remote-name <name>     Sets GITMEM_REMOTE_NAME in Codex config (default: sync).
  --features <list>        Comma-separated cargo feature list passed through to cargo install.
                           (optional)
  -h, --help               Show this help and exit.
EOF
}

if [[ "${1-}" == "-h" || "${1-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer targets macOS only." >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
DEFAULT_ROOT="${REPO_ROOT}/tmp/gitmem-github"

BACKEND_ROOT="${DEFAULT_ROOT}"
CONFIG_NAME="gitmem"
DEVICE_BRANCH="devices/$(hostname -s)"
REMOTE_NAME="sync"
FEATURE_LIST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-root)
      shift
      [[ $# -gt 0 ]] || { echo "--backend-root requires a value" >&2; exit 1; }
      BACKEND_ROOT="$1"
      ;;
    --backend-root=*)
      BACKEND_ROOT="${1#*=}"
      ;;
    --config-name)
      shift
      [[ $# -gt 0 ]] || { echo "--config-name requires a value" >&2; exit 1; }
      CONFIG_NAME="$1"
      ;;
    --config-name=*)
      CONFIG_NAME="${1#*=}"
      ;;
    --device-branch)
      shift
      [[ $# -gt 0 ]] || { echo "--device-branch requires a value" >&2; exit 1; }
      DEVICE_BRANCH="$1"
      ;;
    --device-branch=*)
      DEVICE_BRANCH="${1#*=}"
      ;;
    --remote-name)
      shift
      [[ $# -gt 0 ]] || { echo "--remote-name requires a value" >&2; exit 1; }
      REMOTE_NAME="$1"
      ;;
    --remote-name=*)
      REMOTE_NAME="${1#*=}"
      ;;
    --features)
      shift
      [[ $# -gt 0 ]] || { echo "--features requires a value" >&2; exit 1; }
      FEATURE_LIST="$1"
      ;;
    --features=*)
      FEATURE_LIST="${1#*=}"
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

command -v cargo >/dev/null 2>&1 || {
  echo "cargo is required but was not found in PATH." >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required but was not found in PATH." >&2
  exit 1
}

BACKEND_ROOT_ABS=$(cd "${BACKEND_ROOT}" 2>/dev/null && pwd || true)
if [[ -z "${BACKEND_ROOT_ABS}" ]]; then
  mkdir -p "${BACKEND_ROOT}"
  BACKEND_ROOT_ABS=$(cd "${BACKEND_ROOT}" && pwd)
  if [[ ! -d "${BACKEND_ROOT_ABS}/.git" ]]; then
    echo "Initializing git repository at ${BACKEND_ROOT_ABS}"
    (cd "${BACKEND_ROOT_ABS}" && git init >/dev/null)
  fi
else
  if [[ ! -d "${BACKEND_ROOT_ABS}/.git" ]]; then
    echo "Warning: ${BACKEND_ROOT_ABS} is not a git repository." >&2
  fi
fi

echo "Installing gitmem CLI via cargo install..."
CARGO_ARGS=(install --path "${REPO_ROOT}/crates/cli" --force)
if [[ -n "${FEATURE_LIST}" ]]; then
  CARGO_ARGS+=(--features "${FEATURE_LIST}")
fi
cargo "${CARGO_ARGS[@]}"

CARGO_HOME_DIR="${CARGO_HOME:-${HOME}/.cargo}"
GITMEM_BIN="${CARGO_HOME_DIR}/bin/gitmem"

if [[ ! -x "${GITMEM_BIN}" ]]; then
  echo "Expected gitmem binary at ${GITMEM_BIN}, but it was not found." >&2
  exit 1
fi

CONFIG_DIR="${HOME}/.codex"
CONFIG_FILE="${CONFIG_DIR}/mcps.json"
mkdir -p "${CONFIG_DIR}"

GITMEM_CONFIG_FILE="${CONFIG_FILE}" \
GITMEM_CONFIG_NAME="${CONFIG_NAME}" \
GITMEM_BIN_PATH="${GITMEM_BIN}" \
GITMEM_BACKEND_ROOT="${BACKEND_ROOT_ABS}" \
GITMEM_DEVICE_BRANCH="${DEVICE_BRANCH}" \
GITMEM_REMOTE_NAME="${REMOTE_NAME}" \
python3 <<'PY'
import json
import os
from pathlib import Path

config_path = Path(os.environ["GITMEM_CONFIG_FILE"])
config_path.parent.mkdir(parents=True, exist_ok=True)

try:
    data = json.loads(config_path.read_text())
except FileNotFoundError:
    data = {"mcpServers": {}}
except json.JSONDecodeError:
    data = {"mcpServers": {}}

if "mcpServers" not in data or not isinstance(data["mcpServers"], dict):
    data["mcpServers"] = {}

config_name = os.environ["GITMEM_CONFIG_NAME"]
binary = os.environ["GITMEM_BIN_PATH"]
root = os.environ["GITMEM_BACKEND_ROOT"]
device_branch = os.environ.get("GITMEM_DEVICE_BRANCH", "")
remote_name = os.environ.get("GITMEM_REMOTE_NAME", "")

entry = {
    "command": binary,
    "args": [
        "serve",
        "--backend",
        "github",
        "--root",
        root
    ],
    "env": {}
}

if device_branch:
    entry["env"]["GITMEM_DEVICE_BRANCH"] = device_branch
if remote_name:
    entry["env"]["GITMEM_REMOTE_NAME"] = remote_name

data["mcpServers"][config_name] = entry

config_path.write_text(json.dumps(data, indent=2) + "\n")
PY

echo "Updated Codex configuration at ${CONFIG_FILE} with entry '${CONFIG_NAME}'."
echo "gitmem binary installed at ${GITMEM_BIN}."
echo "Working tree configured at ${BACKEND_ROOT_ABS}."

echo "Next steps:"
echo "  - Ensure the repository at ${BACKEND_ROOT_ABS} has the correct remote and device branch." \
     "(e.g. git remote add sync <url>; git push -u sync ${DEVICE_BRANCH})."
echo "  - Restart Codex CLI if it was running to pick up the new MCP server."
