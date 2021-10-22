#!/usr/bin/env bash
set -ex

if [ -d "${HOME}/.local/bin" ]; then
  export PATH="${HOME}/.local/bin:${PATH}"
fi

SRC_ROOT=${SRC_ROOT:-"${PWD}"}
PYTHON=${PYTHON:-"python3"}

function run_publish_pkg() {
  if [ "x${GITHUB_ACTIONS}" != "xtrue" ]; then
    echo "Did not detect github actions, exiting."
    exit 1
  fi

  if [[ "x${GITHUB_REF}" != "xrefs/tags/"* ]]; then
    echo "Did not detect TAG, got ${GITHUB_REF}."
    echo "exiting."
    exit 1
  fi

  git status
  git reset --hard HEAD
  git clean -xdf

  pypi_version=$(python -c 'import json, urllib.request; print(json.loads(urllib.request.urlopen("https://pypi.org/pypi/tpm2-pytss/json").read())["info"]["version"])')
  tag=${GITHUB_REF/refs\/tags\//}
  if [ "x${tag}" == "x${pypi_version}" ]; then
    echo "Git Tag is same as PyPI version: ${tag} == ${pypi_version}"
    echo "Nothing to do, exiting."
    exit 0
  fi
  python setup.py sdist
  python -m twine upload dist/*
}

function run_test() {

  python3 setup.py sdist && python3 setup.py bdist

  python3 -m pytest -n $(nproc) --cov=tpm2_pytss -v

  if [ -n "${ENABLE_COVERAGE}" ]; then
    python3 -m codecov
  fi

  # verify that package is sane on a user install that is not editable
  git clean -fdx
  python3 -m pip install --user .
  # can't be in a directory that has the package as a folder, Python tries to use that
  # over whats installed.
  pushd /tmp
  python3 -c 'import tpm2_pytss'
  popd
}

function run_whitespace() {
  export whitespace=$(mktemp -u)
  function rmtempfile () {
    rm -f "$whitespace"
  }
  trap rmtempfile EXIT
  find . -type f -name '*.py' -exec grep -EHn " +$" {} \; 2>&1 > "$whitespace"
  lines=$(wc -l < "$whitespace")
  if [ "$lines" -ne 0 ]; then
    echo "Trailing whitespace found" >&2
    cat "${whitespace}" >&2
    exit 1
  fi
}

function run_style() {
  "${PYTHON}" -m black --diff --check "${SRC_ROOT}"
}

if [ "x${TEST}" != "x" ]; then
  run_test
elif [ "x${WHITESPACE}" != "x" ]; then
  run_whitespace
elif [ "x${STYLE}" != "x" ]; then
  run_style
elif [ "x${PUBLISH_PKG}" != "x" ]; then
  run_publish_pkg
fi
