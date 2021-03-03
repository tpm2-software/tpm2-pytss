#!/usr/bin/env bash
set -ex

if [ -d "${HOME}/.local/bin" ]; then
  export PATH="${HOME}/.local/bin:${PATH}"
fi

SRC_ROOT=${SRC_ROOT:-"${PWD}"}
PYTHON=${PYTHON:-"python3.7"}

TEMP_DIRS=()

function run_test() {

  docker run --rm \
    -u $(id -u):$(id -g) \
    -v "${PWD}:/workspace/tpm2-pytss" \
    --env-file .ci/docker.env \
    tpm2software/tpm2-tss-python \
    /bin/bash -c 'python3 setup.py sdist && python3 setup.py bdist'

  docker run --rm \
    -u $(id -u):$(id -g) \
    -v "${PWD}:/workspace/tpm2-pytss" \
    --env-file .ci/docker.env \
    tpm2software/tpm2-tss-python \
    /bin/bash -c '/workspace/tpm2-pytss/.ci/docker.run'

  if [ "x${CODECOV_TOKEN}" != "x" ]; then
    "${PYTHON}" -m codecov
  fi

  if [ "x${GITHUB_ACTIONS}" != "xtrue" ]; then
    return
  fi

  if [ "x${GITHUB_REF}" == "xrefs/heads/master" ] || [ "x${GITHUB_REF}" == *"xrefs/tags/"* ]; then
    git status
    git reset --hard HEAD
    git clean -fdx
    "${PYTHON}" -m dffml service dev release .
  fi
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
  "${PYTHON}" -m black --check "${SRC_ROOT}"
}

function run_docs() {
  export GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

  cd "${SRC_ROOT}"

  docker run --rm \
    -u $(id -u):$(id -g) \
    -v "${PWD}:/workspace/tpm2-pytss" \
    --env-file .ci/docker.env \
    tpm2software/tpm2-tss-python \
    /bin/bash -c 'virtualenv .venv && . .venv/bin/activate && . .ci/docker-prelude.sh && python3 -m pip install -e .[dev]'

  # Make master docs
  master_docs="$(mktemp -d)"
  TEMP_DIRS+=("${master_docs}")
  rm -rf pages
  docker run --rm \
    -u $(id -u):$(id -g) \
    -v "${PWD}:/workspace/tpm2-pytss" \
    --env-file .ci/docker.env \
    tpm2software/tpm2-tss-python \
    /bin/bash -c '. .venv/bin/activate && ./scripts/docs.sh'
  mv pages "${master_docs}/html"

  # Make last release docs
  release_docs="$(mktemp -d)"
  TEMP_DIRS+=("${release_docs}")
  rm -rf pages
  git clean -fdx
  git checkout $(git describe --abbrev=0 --tags --match '*.*.*')
  git clean -fdx
  git reset --hard HEAD

  docker run --rm \
    -u $(id -u):$(id -g) \
    -v "${PWD}:/workspace/tpm2-pytss" \
    --env-file .ci/docker.env \
    tpm2software/tpm2-tss-python \
    /bin/bash -c 'virtualenv .venv && . .venv/bin/activate && . .ci/docker-prelude.sh && python3 -m pip install -e .[dev]'

  docker run --rm \
    -u $(id -u):$(id -g) \
    -v "${PWD}:/workspace/tpm2-pytss" \
    --env-file .ci/docker.env \
    tpm2software/tpm2-tss-python \
    /bin/bash -c '. .venv/bin/activate && ./scripts/docs.sh'

  mv pages "${release_docs}/html"

  git clone https://github.com/tpm2-software/tpm2-pytss -b gh-pages \
    "${release_docs}/old-gh-pages-branch"

  mv "${release_docs}/old-gh-pages-branch/.git" "${release_docs}/html/"
  mv "${master_docs}/html" "${release_docs}/html/master"

  cd "${release_docs}/html"

  git config user.name 'John Andersen'
  git config user.email 'johnandersenpdx@gmail.com'

  git add -A
  git commit -sam "docs: $(date)"

  if [ "x${GITHUB_ACTIONS}" == "xtrue" ] && [ "x${GITHUB_REF}" != "xrefs/heads/master" ]; then
    return
  fi

  ssh_key_dir="$(mktemp -d)"
  TEMP_DIRS+=("${ssh_key_dir}")
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  "${PYTHON}" -c "import pathlib, base64, os; keyfile = pathlib.Path(\"${ssh_key_dir}/github_tpm2_pytss\").absolute(); keyfile.write_bytes(b''); keyfile.chmod(0o600); keyfile.write_bytes(base64.b32decode(os.environ['GITHUB_PAGES_KEY']))"
  ssh-keygen -y -f "${ssh_key_dir}/github_tpm2_pytss" > "${ssh_key_dir}/github_tpm2_pytss.pub"
  export GIT_SSH_COMMAND="${GIT_SSH_COMMAND} -o IdentityFile=${ssh_key_dir}/github_tpm2_pytss"

  git remote set-url origin git@github.com:tpm2-software/tpm2-pytss
  git push -f

  cd -

  git reset --hard HEAD
  git checkout master
}

function cleanup_temp_dirs() {
  if [ "x${NO_RM_TEMP}" != "x" ]; then
    return
  fi
  for temp_dir in ${TEMP_DIRS[@]}; do
    rm -rf "${temp_dir}"
  done
}

# Clean up temporary directories on exit
trap cleanup_temp_dirs EXIT

if [ "x${TEST}" != "x" ]; then
  run_test
elif [ "x${WHITESPACE}" != "x" ]; then
  run_whitespace
elif [ "x${STYLE}" != "x" ]; then
  run_style
elif [ "x${DOCS}" != "x" ]; then
  run_docs
fi
