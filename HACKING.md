# Cloning

You need to clone recursive so that you will get the siwg interface files as a
submodule.

```console
$ git clone https://github.com/tpm2-software/tpm2-pytss
```

# Python dependencies

Make sure you have the latest version of build utilities installed

```console
$ pip install -U pip setuptools wheel
```

Install python dependencies by appending `[dev]` to the install command

```console
$ pip install -e .[dev]
```

# Style

Install following linters:
 * `black` version `19.10b0`
 * `isort`

```
$ pip install -U black==19.10b0 isort
```

From the root of the repo

```
$ .ci/linters.sh .
```

# Testing

## Running

```console
$ python -m pytest -n $(nproc) --cov=tpm2_pytss -v
```

## Docker

```console
$ rm -rf build
$ git clean -Xf || true
$ docker build -t tpm2software/tpm2-tss-python -f .ci/Dockerfile.tpm2-tss-python .
$ docker run --rm \
  -u $(id -u):$(id -g) \
  -v "${PWD}:/workspace/tpm2-pytss" \
  --env-file .ci/docker.env \
  tpm2software/tpm2-tss-python \
  /bin/bash -c '/workspace/tpm2-pytss/.ci/docker.run'
```

## Environment Variables

- NONE

# Documentation

Build the docs by running the Sphinx HTML builder on the `docs/` directory.

You can also invoke `./scripts/docs.sh`
