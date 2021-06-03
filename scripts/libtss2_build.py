from cffi import FFI

ffibuilder = FFI()

import importlib.util
import os
import pkgconfig
import re
import sys

# import tpm2_pytss.constants
constants_spec = importlib.util.spec_from_file_location(
    "tpm2_pytss.constants", "tpm2_pytss/constants.py"
)
constants = importlib.util.module_from_spec(constants_spec)
constants_spec.loader.exec_module(constants)


def get_include_paths(library_names):
    if not isinstance(library_names, list):
        library_names = [library_names]

    # find search paths for libraries and header via pkg-config
    header_dirs = set()

    # for manually installed packages, env var PKG_CONFIG_PATH might need to be changed
    for library_name in library_names:
        os.environ["PKG_CONFIG_ALLOW_SYSTEM_CFLAGS"] = "1"
        cflags = pkgconfig.cflags(library_name)
        header_dirs.update(re.findall(r"(?<=-I)\S+", cflags))

    return header_dirs


libraries = ["tss2-esys", "tss2-tctildr", "tss2-fapi", "tss2-rc", "tss2-mu"]

# Set up the search path so we find prepare_header and other modules
PATH = os.path.dirname(__file__) if len(os.path.dirname(__file__)) > 0 else os.getcwd()
if not os.path.isabs(PATH):
    PATH = os.path.join(os.getcwd(), PATH)

print("adding path: {}".format(PATH))
sys.path.insert(0, PATH)
from prepare_headers import prepare

tss2_header_dirs = get_include_paths(libraries)

found_dir = None
for hd in tss2_header_dirs:
    full_path = os.path.join(hd, "tss2")
    if os.path.isdir(full_path):
        found_dir = hd
        break
if found_dir is None:
    sys.exit("Could not find esys headers in {}".format(tss2_header_dirs))

# strip tss2 prefix
prepare(found_dir, "libesys.h")

ffibuilder.cdef(
    open("libesys.h").read()
    + "".join(
        f"""
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_AUTH]}{i}(
        char     const *objectPath,
        char     const *description,
        char    const **auth,
        void           *userData);
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_BRANCH]}{i}(
        char     const *objectPath,
        char     const *description,
        char    const **branchNames,
        size_t          numBranches,
        size_t         *selectedBranch,
        void           *userData);
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_SIGN]}{i}(
        char     const *objectPath,
        char     const *description,
        char     const *publicKey,
        char     const *publicKeyHint,
        uint32_t        hashAlg,
        uint8_t  const *dataToSign,
        size_t          dataToSignSize,
        uint8_t const **signature,
        size_t         *signatureSize,
        void           *userData);
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_POLICYACTION]}{i}(
        char     const *objectPath,
        char     const *action,
        void           *userData);
"""
        for i in range(0, constants.CALLBACK_COUNT)
    )
)

# so it is often just the "#include".
ffibuilder.set_source(
    "tpm2_pytss._libtpm2_pytss",
    """
     /* the C header of the library */
     #include <tss2/tss2_esys.h>
     #include <tss2/tss2_tctildr.h>
     #include <tss2/tss2_fapi.h>
     #include <tss2/tss2_rc.h>
     #include <tss2/tss2_mu.h>
""",
    libraries=libraries,
)  # library name, for the linker

if __name__ == "__main__":
    ffibuilder.compile(verbose=True, debug=True)
