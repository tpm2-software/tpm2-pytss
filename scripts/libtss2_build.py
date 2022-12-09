from cffi import FFI

ffibuilder = FFI()

import os
import pkgconfig
import sys


libraries = ["tss2-esys", "tss2-tctildr", "tss2-rc", "tss2-mu"]

if not pkgconfig.installed("tss2-esys", ">=2.4.0"):
    raise RuntimeError("Require tss2-esapi to be installed and at least version 2.4.0")

# Needs some missing marshal routines like Tss2_MU_TPMU_ENCRYPTED_SECRET_Marshal
if not pkgconfig.installed("tss2-mu", ">=2.4.0"):
    raise RuntimeError("Require tss2-mu 2.4.0 or greater to be installed")

if not pkgconfig.exists("tss2-tctildr"):
    raise RuntimeError("Require tss2-tctildr to be installed")

if not pkgconfig.exists("tss2-rc"):
    raise RuntimeError("Require tss2-rc to be installed")

# FAPI must be version 3.0.0 or greater to work, else strip it.
build_fapi = pkgconfig.installed("tss2-fapi", ">=3.0.0")
if build_fapi:
    libraries.append("tss2-fapi")

build_policy = pkgconfig.exists("tss2-policy")
if build_policy:
    libraries.append("tss2-policy")

build_tcti_spi_helper = pkgconfig.exists("tss2-tcti-spi-helper")
if build_tcti_spi_helper:
    libraries.append("tss2-tcti-spi-helper")

# Set up the search path so we find prepare_header and other modules
PATH = os.path.dirname(__file__) if len(os.path.dirname(__file__)) > 0 else os.getcwd()
if not os.path.isabs(PATH):
    PATH = os.path.join(os.getcwd(), PATH)

print("adding path: {}".format(PATH))
sys.path.insert(0, PATH)
from prepare_headers import prepare

os.environ["PKG_CONFIG_ALLOW_SYSTEM_CFLAGS"] = "1"
libs = " ".join(libraries)
paths = pkgconfig.parse(libs)

found_dir = None
for hd in paths["include_dirs"]:
    full_path = os.path.join(hd, "tss2", "tss2_common.h")
    if os.path.isfile(full_path):
        found_dir = hd
        break
if found_dir is None:
    sys.exit("Could not find esys headers in {}".format(paths["include_dirs"]))

# strip tss2 prefix
prepare(
    found_dir,
    "libesys.h",
    build_fapi=build_fapi,
    build_policy=build_policy,
    build_tcti_spi_helper=build_tcti_spi_helper,
)

ffibuilder.cdef(open("libesys.h").read())

source = """
    /* the C header of the library */
    #include <tss2/tss2_esys.h>
    #include <tss2/tss2_tcti.h>
    #include <tss2/tss2_tctildr.h>
    #include <tss2/tss2_rc.h>
    #include <tss2/tss2_mu.h>

    /*
     * Add the structure for the Python TCTI which is the TCTI structure and void *
     * for the pyobject representing the object instance. We add it here and to
     * prepare headers so CFFI knows about it (prepare_headers) and here so
     * C code knows about it.
     */
    typedef struct PYTCTI_CONTEXT PYTCTI_CONTEXT;
    struct PYTCTI_CONTEXT {
        TSS2_TCTI_CONTEXT_COMMON_V2 common;
        void *thiz;
    };
"""

if build_fapi:
    source += "    #include <tss2/tss2_fapi.h>\n"
if build_policy:
    source += "    #include <tss2/tss2_policy.h>\n"
if build_tcti_spi_helper:
    source += "    #include <tss2/tss2_tcti_spi_helper.h>"
# so it is often just the "#include".
ffibuilder.set_source(
    "tpm2_pytss._libtpm2_pytss",
    source,
    libraries=paths["libraries"],
    library_dirs=paths["library_dirs"],
    include_dirs=paths["include_dirs"],
)  # library name, for the linker

if __name__ == "__main__":
    ffibuilder.compile(verbose=True, debug=True)
