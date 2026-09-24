#!/usr/bin/env bash
#
# build.sh  —  build the zoom-capture binary, then start it.
#
# Usage:   ./build.sh
#
set -euo pipefail

BIN_NAME="zoom_capture"
PROFILE="release"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==================================================="
echo " BUILD  ${BIN_NAME}  (${PROFILE})"
echo "   crate dir : ${SCRIPT_DIR}"
echo "==================================================="

cd "${SCRIPT_DIR}"

if [[ "${PROFILE}" == "release" ]]; then
    cargo build --release --bin "${BIN_NAME}"
else
    cargo build --bin "${BIN_NAME}"
fi

echo
echo "==> Build finished OK."
echo

exec "${SCRIPT_DIR}/run.sh"
