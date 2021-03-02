import os
import site
import sys
import shlex
import pathlib
from subprocess import check_output
from setuptools import setup, Extension

# workaround bug https://github.com/pypa/pip/issues/7953
site.ENABLE_USER_SITE = "--user" in sys.argv[1:]

ORG = "tpm2-software"
NAME = "tpm2-pytss"
DESCRIPTION = "TPM 2.0 TSS Bindings for Python"
URL = "https://github.com/tpm2-software/tpm2-pytss"
MAINTAINER_NAME = "William Roberts"
MAINTAINER_EMAIL = "william.c.roberts@intel.com"
SETUP_REQUIRES = ["cffi>=1.0.0"]
INSTALL_REQUIRES = SETUP_REQUIRES

VERSION = check_output("git describe --always --tags --dirty".split(),).decode()

SELF_PATH = os.path.dirname(os.path.realpath(__file__))

README = pathlib.Path(SELF_PATH, "README.md").read_text()


class PkgConfigNeededExtension(Extension):
    """
    By creating a subclass of Extension and using the :py:func:property builtin
    we can make it so that pkg-config doesn't get called unless the user
    attempts to build from source. Otherwise we'd run into issues installing the
    built binary on systems that don't have pkg-config.
    """

    def __init__(self, *args, pkg_config_cflags=None, pkg_config_libs=None, **kwargs):
        # Default to empty array if not given
        if pkg_config_cflags is None:
            pkg_config_cflags = []
        if pkg_config_libs is None:
            pkg_config_libs = []
        self.pkg_config_cflags = pkg_config_cflags
        self.pkg_config_libs = pkg_config_libs
        # Will be populated by respective non-underscore setters
        self._libraries = []
        self._include_dirs = []
        self._library_dirs = []
        self._swig_opts = []
        super().__init__(*args, **kwargs)

    @property
    def cc_include_dirs(self):
        if not self.pkg_config_cflags:
            return []
        return shlex.split(
            check_output(
                ["pkg-config", "--cflags"] + self.pkg_config_cflags,
                env=dict(os.environ, PKG_CONFIG_ALLOW_SYSTEM_CFLAGS="1"),
            ).decode()
        )

    @property
    def cc_libraries(self):
        if not self.pkg_config_libs:
            return []
        return shlex.split(
            check_output(["pkg-config", "--libs"] + self.pkg_config_libs).decode()
        )

    def _strip_leading(self, number, iterable):
        """
        Strips number characters from the begining of each string in iterable.
        """
        return list(map(lambda string: string[number:], iterable))

    def _subset_startswith(self, prefix, iterable):
        """
        Subset of list where each element starts with prefix.
        """
        return list(filter(lambda option: option.startswith(prefix), iterable))

    def _strip_only_startswith(self, prefix, iterable):
        """
        Subset of list where each element starts with prefix, where prefix has
        now been removed.
        """
        return self._strip_leading(
            len(prefix), self._subset_startswith(prefix, iterable)
        )

    @property
    def include_dirs(self):
        return (
            self._strip_only_startswith("-I", self.cc_include_dirs) + self._include_dirs
        )

    @include_dirs.setter
    def include_dirs(self, value):
        self._include_dirs = value

    @property
    def libraries(self):
        return self._strip_only_startswith("-l", self.cc_libraries) + self._libraries

    @libraries.setter
    def libraries(self, value):
        self._libraries = value

    @property
    def library_dirs(self):
        return self._strip_only_startswith("-L", self.cc_libraries) + self._library_dirs

    @library_dirs.setter
    def library_dirs(self, value):
        self._library_dirs = value

    @property
    def swig_opts(self):
        return self._subset_startswith("-I", self.cc_include_dirs) + self._swig_opts

    @swig_opts.setter
    def swig_opts(self, value):
        self._swig_opts = value


from setuptools import setup

setup(
    name="tpm2_pytss",
    version=VERSION,
    description=DESCRIPTION,
    url=URL,
    author=MAINTAINER_NAME,
    setup_requires=SETUP_REQUIRES,
    cffi_modules=["scripts/libesys_build.py:ffibuilder"],
    install_requires=INSTALL_REQUIRES,
)
