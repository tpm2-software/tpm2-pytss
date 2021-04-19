#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3

#
# This script is configured to run as part of the sphinx build
# through API events registered in conf.py.
# This script runs on event build-finished.
#
# This would be better served by handling the events
# html-collect-page --> for add .nojekyll
# html-page-context --> for fixing the span's done with sed.
#
# For the case of time, we just left this script as is and run it as a
# post sphinx build command event :-p
#

set -eo pipefail

find pages/ -name \*.html -exec \
  sed -i 's/<span class="gp">\&gt;\&gt;\&gt; <\/span>//g' {} \;
touch pages/.nojekyll

exit 0
