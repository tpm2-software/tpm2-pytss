# Cloning

You need to clone recursive so that you will get the siwg interface files as a
submodule.

```console
$ git clone --recursive https://github.com/tpm2-software/tpm2-pytss
```

# Style

Install `black` version `19.10b0`

```
$ pip install -U black==19.10b0
```

From the root of the repo

```
$ black .
```

# Testing

## Running

```console
$ python -m unittest discover -v
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

- `SIM_RUNNING`
  - If set to anything this tells `util.simulator` that you want it to use the
    simulator that's already running instead of trying to start a new one.

- `PYESYS_TCTI`
  - Default: `mssim`
  - Set this to the name of the TCTI you want to use. For example `device`,
    `mssim`, `tabrmd`.

- `PYESYS_TCTI_CONFIG`
  - Default: `None`
  - Set this to the config string to be passed to the init function of the TCTI.

# Documentation

Build the docs by running the Sphinx HTML builder on the `docs/` directory.

You can also invoke `./scripts/docs.sh`
