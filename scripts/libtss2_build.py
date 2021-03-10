from cffi import FFI

ffibuilder = FFI()

import os
import pkgconfig
import re
import sys


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


libraries = ["tss2-esys", "tss2-tctildr", "tss2-fapi"]

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

ffibuilder.cdef(open("libesys.h").read())

# so it is often just the "#include".
ffibuilder.set_source(
    "tpm2_pytss._libtpm2_pytss",
    """
     /* the C header of the library */
     #include <tss2/tss2_esys.h>
     #include <tss2/tss2_tctildr.h>
     #include <tss2/tss2_fapi.h>
""",
    libraries=libraries,
)  # library name, for the linker

if __name__ == "__main__":
    ffibuilder.compile(verbose=True, debug=True)
