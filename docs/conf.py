# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
import datetime
import subprocess

from setuptools_scm import get_version

from sphinx.util import logging

logger = logging.getLogger(__name__)

if os.environ.get("READTHEDOCS", False):
    import git

    logger.info("READTHEDOCS DETECTED")
    cwd = os.getcwd()
    repo = git.Repo(cwd, search_parent_directories=True)
    root = repo.git.rev_parse("--show-toplevel")
    logger.info(f"Adding to PATH: {root}")
    sys.path.insert(0, root)
    l = os.listdir(root)
    logger.info(f"Root ls: {l}")

logger.info("Mocking tpm2_pytss._libtpm2_pytss")
from unittest.mock import MagicMock


class MyMagicMock(MagicMock):
    def __repr__(self):
        name = self._extract_mock_name()
        name = name.replace("mock.lib.", "")
        if name.startswith("ESYS_TR_"):
            end = name.replace("ESYS_TR_", "")
            name = "ESYS_TR." + end

        return name


sys.modules["tpm2_pytss._libtpm2_pytss"] = MyMagicMock()

import tpm2_pytss

# -- Project information -----------------------------------------------------

project = "tpm2-pytss"
author = "tpm2-software"
copyright = f"2019 - {datetime.datetime.today().year}, {author}"

# The short X.Y version
version = get_version(root="..", relative_to=__file__)

# The full version, including alpha/beta/rc tags
release = get_version(root="..", relative_to=__file__)


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.autosectionlabel",
    "myst_parser",
]

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

# Autodoc settings
autodoc_typehints = "none"

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

autosectionlabel_prefix_document = True
autosectionlabel_maxdepth = 1

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "alabaster"

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
# The Read the Docs theme is available from
# - https://github.com/snide/sphinx_rtd_theme
# - https://pypi.python.org/pypi/sphinx_rtd_theme
# - python-sphinx-rtd-theme package (on Debian)
try:
    import sphinx_rtd_theme

    html_theme = "sphinx_rtd_theme"
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
except ImportError:
    sys.stderr.write(
        "Warning: The Sphinx 'sphinx_rtd_theme' HTML theme was not found. Make sure you have the theme installed to produce pretty HTML output. Falling back to the default theme.\n"
    )

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# -- Extension configuration -------------------------------------------------

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


def builder_finished_handler(app, exception):
    if exception is None:
        os.environ["SPHINX_OUTDIR"] = app.outdir
        script = os.path.join(app.confdir, "sphinx-finished.sh")
        subprocess.check_call(script, shell=True)


#
# Hook the setup of readthedocs so we can hook into events as defined in:
# - https://www.sphinx-doc.org/en/master/extdev/appapi.html
#
def setup(app):
    app.connect("build-finished", builder_finished_handler)
