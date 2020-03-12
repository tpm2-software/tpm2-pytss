import os
import ast
import stat
import glob
import json
import shlex
import shutil
import pathlib
from io import open
from subprocess import check_output
from setuptools.command.build_ext import build_ext
from setuptools import find_packages, setup, Extension

ORG = "tpm2-software"
NAME = "tpm2-pytss"
DESCRIPTION = "TPM 2.0 TSS Bindings for Python"
AUTHOR_NAME = "John Andersen"
AUTHOR_EMAIL = "john.s.andersen@intel.com"
INSTALL_REQUIRES = []

IMPORT_NAME = NAME.replace("-", "_")

SELF_PATH = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(SELF_PATH, IMPORT_NAME, "version.py"), "r") as f:
    for line in f:
        if line.startswith("VERSION"):
            VERSION = ast.literal_eval(line.strip().split("=")[-1].strip())
            break

README = pathlib.Path(SELF_PATH, "README.md").read_text()


def build_config():
    """
    When building the project we create the file config.json. The settings in
    config.json are pulled from environment variables at build time. This allows
    the package maintainer within a distro to set values within config.json
    equal to their counterparts used via ./configure when building TPM2-TSS.
    """
    config = {"sysconfdir": os.environ.get("SYSCONFDIR", "/etc")}
    return config


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


class BuildExtThenCopySWIGPy(build_ext):
    def run(self):
        super().run()
        # Build the config.json file, ensure it ends with a newline
        config_json = pathlib.Path(SELF_PATH, IMPORT_NAME, "config.json")
        config_json.write_text(
            json.dumps(build_config(), sort_keys=True, indent=4) + "\n"
        )
        # SWIG 4 Support
        for fixfile in ["esys_binding.py", "fapi_binding.py"]:
            binding_path = pathlib.Path(SELF_PATH, IMPORT_NAME, fixfile)
            binding = binding_path.read_text()
            if not "python_property = property" in binding:
                binding = binding.replace("= property(", "= python_property(")
                binding = "python_property = property\n" + binding
                binding_path.write_text(binding)
        # This is needed because test copies the binding files into IMPORT_NAME
        # but build does not. Making this necessary for working with the package
        # installed in development mode.
        for src in glob.glob(
            os.path.join(SELF_PATH, "build", "lib.*", "**", "*.so"), recursive=True
        ):
            dst = os.path.join(SELF_PATH, IMPORT_NAME, os.path.basename(src))
            print("{} -> {}".format(src, dst))
            shutil.copyfile(src, dst)
            os.chmod(
                dst,
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IXOTH,
            )


setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=README,
    long_description_content_type="text/markdown",
    author=AUTHOR_NAME,
    author_email=AUTHOR_EMAIL,
    maintainer=AUTHOR_NAME,
    maintainer_email=AUTHOR_EMAIL,
    url="https://github.com/{}/{}".format(ORG, NAME),
    license="MIT",
    keywords=["tpm2", "security"],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    install_requires=INSTALL_REQUIRES,
    extras_require={
        "dev": [
            "coverage",
            "codecov",
            "sphinx",
            "sphinxcontrib-asyncio",
            "black",
            "sphinx_rtd_theme",
        ],
    },
    packages=find_packages(),
    ext_modules=[
        PkgConfigNeededExtension(
            "{}._esys_binding".format(IMPORT_NAME),
            [os.path.join(IMPORT_NAME, "swig", "esys_binding.i")],
            pkg_config_cflags=["tss2-esys", "tss2-rc", "tss2-tctildr"],
            pkg_config_libs=["tss2-esys", "tss2-rc", "tss2-tctildr"],
            swig_opts=["-py3", "-outdir", IMPORT_NAME],
        ),
        PkgConfigNeededExtension(
            "{}._fapi_binding".format(IMPORT_NAME),
            [os.path.join(IMPORT_NAME, "swig", "fapi_binding.i")],
            pkg_config_cflags=["tss2-fapi", "tss2-rc", "tss2-tctildr"],
            pkg_config_libs=["tss2-fapi", "tss2-rc", "tss2-tctildr"],
            swig_opts=["-py3", "-outdir", IMPORT_NAME],
        ),
    ],
    py_modules=[IMPORT_NAME],
    cmdclass={"build_ext": BuildExtThenCopySWIGPy},
    include_package_data=True,
    zip_safe=False,
)
