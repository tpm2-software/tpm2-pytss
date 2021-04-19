#!/usr/bin/env sh
# SPDX-License-Identifier: BSD-2
set -e

sphinx-build -W -b html docs pages
