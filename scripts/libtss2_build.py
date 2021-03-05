from cffi import FFI

ffibuilder = FFI()

import os
import sys

# Set up the search path so we find prepare_header and other modules
PATH = os.path.dirname(__file__) if len(os.path.dirname(__file__)) > 0 else os.getcwd()
if not os.path.isabs(PATH):
    PATH = os.path.join(os.getcwd(), PATH)

print("adding path: {}".format(PATH))
sys.path.insert(0, PATH)
from prepare_headers import prepare

# XXX For now just hardcode this, but we probably want to look at how to reuse the
# pkgconfig extension.
#
# Generate a massaged header file for cffi bindings
#

tss2_header_dirs = [
    "/usr/include",
    "/usr/local/include",
]

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
    "tpm2_pytss.pyesys._libesys",
    """
     /* the C header of the library */
     #include <tss2/tss2_esys.h>
     #include <tss2/tss2_tctildr.h>
""",
    debug=True,
    libraries=["tss2-esys", "tss2-tctildr"],
)  # library name, for the linker

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
