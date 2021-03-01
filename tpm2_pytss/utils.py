"""
SPDX-License-Identifier: BSD-3
"""

from ._libesys import ffi,lib

def _chkrc(rc):
    if rc != 0:
        raise Exception(rc >> 16, rc & 0xffff)

#### Utilities ####

def TPM2B_unpack(x):
    return ffi.unpack(x.buffer, x.size)

def TPM2B_pack(x, t='DIGEST'):
    if t.startswith("TPM2B_"):
        t = t[6:]
    r = ffi.new("TPM2B_{0} *".format(t))
    r.size = len(x)
    ffi.memmove(r.buffer, x, len(x))
    return r