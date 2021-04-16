#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

# all command failures are fatal
set -e

if [ "x${DEBUG_CI}" != "x" ]; then
  set -x
fi

WORKSPACE=`dirname $GITHUB_WORKSPACE`

echo "Workspace: $WORKSPACE"

source $GITHUB_WORKSPACE/.ci/download-deps.sh

get_deps "$WORKSPACE"

export PYTHON=python3
export LD_LIBRARY_PATH=/usr/local/lib/
export PATH=/root/.local/bin/:/ibmtpm974/src:$PATH

echo "echo changing to $GITHUB_WORKSPACE"
# Change to the the travis build dir
cd $GITHUB_WORKSPACE
