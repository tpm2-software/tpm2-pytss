"""
SPDX-License-Identifier: BSD-3
"""

from ._libtpm2_pytss import ffi
from .TSS2_Exception import TSS2_Exception


def _chkrc(rc):
    if rc != 0:
        raise TSS2_Exception(rc)


def to_bytes_or_null(value, allow_null=True, encoding=None):
    """Convert to cdata input.

    None:  ffi.NULL (if allow_null == True)
    bytes: bytes
    str:   str.encode()
    """
    if value is None:
        if allow_null:
            return ffi.NULL
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode(encoding=encoding)
    raise RuntimeError("Cannot convert value into bytes/null-pointer")


#### Utilities ####


def TPM2B_unpack(x):
    b = ffi.unpack(x.buffer, x.size)
    if isinstance(b, list):
        b = bytes(b)

    return b


def TPM2B_pack(x, t="DIGEST"):
    if t.startswith("TPM2B_"):
        t = t[6:]
    r = ffi.new("TPM2B_{0} *".format(t))
    r.size = len(x)
    ffi.memmove(r.buffer, x, len(x))
    return r


def TPML_unpack(x, field_name):

    return [TPM2B_unpack(getattr(x, field_name)[i]) for i in range(0, x.count)]


def CLASS_INT_ATTRS_from_string(cls, str_value):
    """
    Given a class, lookup int attributes by name and return that attribute value.
    :param cls: The class to search.
    :param str_value: The key for the attribute in the class.
    """

    friendly = {
        key: value for (key, value) in vars(cls).items() if isinstance(value, int)
    }
    return friendly[str_value.upper()]
