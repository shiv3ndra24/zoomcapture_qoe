#!/usr/bin/env bash
#
# run.sh  —  run the ALREADY-BUILT zoom-capture binary.
#            (does NOT build; use ./build.sh for that)
#
# Usage:   ./run.sh
#
set -euo pipefail

BIN_NAME="zoom_capture"
PROFILE="release"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BIN_PATH="${WORKSPACE_ROOT}/target/${PROFILE}/${BIN_NAME}"
CONFIG_PATH="${SCRIPT_DIR}/config.toml"

echo "==================================================="
echo " RUN  ${BIN_NAME}"
echo "   binary : ${BIN_PATH}"
echo "   config : ${CONFIG_PATH}"
echo "==================================================="

if [[ ! -x "${BIN_PATH}" ]]; then
    echo "ERROR: binary not found (or not executable):"
    echo "       ${BIN_PATH}"
    echo "Build it first:   ./build.sh"
    exit 1
fi

if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "ERROR: config file not found:"
    echo "       ${CONFIG_PATH}"
    exit 1
fi

exec sudo -E "${BIN_PATH}" -c "${CONFIG_PATH}"
