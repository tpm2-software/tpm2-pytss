import site
import sys
from setuptools import setup

# workaround bug https://github.com/pypa/pip/issues/7953
site.ENABLE_USER_SITE = "--user" in sys.argv[1:]

setup(use_scm_version=True, cffi_modules=["scripts/libesys_build.py:ffibuilder"])
