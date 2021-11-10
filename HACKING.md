# Cloning

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
$ python -m pytest -n $(nproc) --cov=tpm2_pytss -v
```

## Environment Variables

- NONE

# Documentation

Build the docs by running the Sphinx HTML builder on the `docs/` directory.

You can also invoke `./scripts/docs.sh`
