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
  # get the dependencies from setup.cfg and install them
  python3 -c "import configparser; c = configparser.ConfigParser(); c.read('setup.cfg'); print(c['options']['install_requires'])" | \
	  xargs pip install
  python3 -c "import configparser; c = configparser.ConfigParser(); c.read('setup.cfg'); print(c['options']['setup_requires'])" | \
	  xargs pip install


  python setup.py sdist
  python -m twine upload dist/*
}

function run_from_tmp() {
  local status=0

  # can't be in a directory that has the package as a folder, Python tries to
  # use that over what's installed.
  pushd /tmp || return "$?"
  "$@" || status="$?"
  popd || return "$?"

  return "${status}"
}

function build_test_artifacts() {
  # installs the deps so sdist and bdist work.
  python3 -m pip install wheel $(./scripts/get_deps.py) || return "$?"

  python3 setup.py sdist || return "$?"
  python3 setup.py bdist || return "$?"
}

function check_user_install() {
  local runner="$1"

  git clean -fdx || return "$?"
  python3 -m pip install --user . || return "$?"
  run_from_tmp "${runner}" python3 -c 'import tpm2_pytss' || return "$?"
}

function check_wheel_install() {
  local runner="$1"
  shift

  git clean -fdx || return "$?"
  python3 -m pip uninstall --yes tpm2-pytss || return "$?"
  python3 -Bm build --no-isolation || return "$?"
  python3 -m installer --destdir=installation dist/*.whl || return "$?"

  local site_packages
  site_packages=$(realpath $(find . -type d -name site-packages)) || return "$?"
  export PYTHONPATH="${site_packages}"

  local totest
  totest=$(realpath test/test_esapi.py) || return "$?"

  run_from_tmp "${runner}" python3 -c 'import tpm2_pytss' || return "$?"
  run_from_tmp "${runner}" "$@" "${totest}" -k test_get_random || return "$?"
}

function run_test() {

  build_test_artifacts

  python3 -m pytest -n $(nproc) --cov=tpm2_pytss -v

  if [ -n "${ENABLE_COVERAGE}" ]; then
    python3 -m coverage xml -o /tmp/coverage.xml
  fi

  function run_command() {
    "$@"
  }

  check_user_install run_command
  check_wheel_install run_command pytest
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

function run_lint() {
  ruff check "${SRC_ROOT}"
}

function run_valgrind() {
  local valgrind_log_dir="${VALGRIND_LOG_DIR:-/tmp/tpm2-pytss-valgrind}"
  local valgrind_error_exitcode="${VALGRIND_ERROR_EXITCODE:-42}"
  local valgrind_errors_for_leak_kinds="${VALGRIND_ERRORS_FOR_LEAK_KINDS:-definite}"
  local pytest_args=()
  local valgrind_args=(
    --tool=memcheck
    --leak-check=full
    --show-leak-kinds=all
    --errors-for-leak-kinds="${valgrind_errors_for_leak_kinds}"
    --error-exitcode="${valgrind_error_exitcode}"
    --track-origins=yes
    --expensive-definedness-checks=yes
    --num-callers=40
    --trace-children="${VALGRIND_TRACE_CHILDREN:-no}"
    --log-file="${valgrind_log_dir}/tpm2-pytss-valgrind.%p.log"
  )

  if [ -n "${VALGRIND_PYTEST_ARGS:-}" ]; then
    pytest_args=(${VALGRIND_PYTEST_ARGS})
  fi

  if [ -n "${VALGRIND_EXTRA_ARGS:-}" ]; then
    valgrind_args+=(${VALGRIND_EXTRA_ARGS})
  fi

  mkdir -p "${valgrind_log_dir}"
  find "${valgrind_log_dir}" -type f -name '*.log' -delete

  function print_valgrind_summary() {
    find "${valgrind_log_dir}" -type f -name '*.log' -print -exec grep -Hn -E \
      'LEAK SUMMARY|definitely lost|indirectly lost|possibly lost|still reachable|ERROR SUMMARY' \
      {} \; || true
  }

  function run_memcheck() {
    set +e
    PYTHONMALLOC=malloc valgrind "${valgrind_args[@]}" "$@"
    local valgrind_status="$?"
    set -e

    if [ "${valgrind_status}" -ne 0 ]; then
      print_valgrind_summary
    fi

    return "${valgrind_status}"
  }

  # Match the normal test setup/build flow, but run the Python code under
  # Valgrind without xdist or coverage so Memcheck observes one process.
  build_test_artifacts

  run_memcheck python3 -m pytest -v "${pytest_args[@]}" || return "$?"

  check_user_install run_memcheck
  check_wheel_install run_memcheck python3 -m pytest

  print_valgrind_summary
}

if [ "x${TEST}" != "x" ]; then
  run_test
elif [ "x${WHITESPACE}" != "x" ]; then
  run_whitespace
elif [ "x${STYLE}" != "x" ]; then
  run_style
elif [ "x${PUBLISH_PKG}" != "x" ]; then
  run_publish_pkg
elif [ "x${LINT}" != "x" ]; then
  run_lint
elif [ "x${VALGRIND}" != "x" ]; then
  run_valgrind
fi
