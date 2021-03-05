"""
SPDX-License-Identifier: BSD-3
"""

from ._libtpm2_pytss import ffi
from .TSS2_Exception import TSS2_Exception


def _chkrc(rc):
    if rc != 0:
        raise TSS2_Exception(f"TSS2 Library call failed with: 0x{rc:X}")


#### Utilities ####


def TPM2B_unpack(x):
    return ffi.unpack(x.buffer, x.size)


def TPM2B_pack(x, t="DIGEST"):
    if t.startswith("TPM2B_"):
        t = t[6:]
    r = ffi.new("TPM2B_{0} *".format(t))
    r.size = len(x)
    ffi.memmove(r.buffer, x, len(x))
    return r
