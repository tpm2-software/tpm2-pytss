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


def TPM2B_unpack(x, n="buffer"):
    d = x.__getattribute__(n)
    b = ffi.unpack(d, x.size)
    if isinstance(b, list):
        b = bytes(b)

    return b


def TPM2B_pack(x, t="DIGEST"):
    if t.startswith("TPM2B_"):
        t = t[6:]
    r = ffi.new("TPM2B_{0} *".format(t))
    if x is None:
        return r
    if isinstance(x, str):
        x = x.encode()
    r.size = len(x)
    ffi.memmove(r.buffer, x, len(x))
    return r


def CLASS_INT_ATTRS_from_string(cls, str_value, fixup_map=None):
    """
    Given a class, lookup int attributes by name and return that attribute value.
    :param cls: The class to search.
    :param str_value: The key for the attribute in the class.
    """

    friendly = {
        key.upper(): value
        for (key, value) in vars(cls).items()
        if isinstance(value, int)
    }

    if fixup_map is not None and str_value.upper() in fixup_map:
        str_value = fixup_map[str_value.upper()]

    return friendly[str_value.upper()]


def cpointer_to_ctype(x):
    tipe = ffi.typeof(x)
    if tipe.kind == "pointer":
        tipe = tipe.item
    return tipe


def fixup_cdata_kwargs(this, _cdata, kwargs):

    # folks may call this routine without a keyword argument which means it may
    # end up in _cdata, so we want to try and work this out
    null_cdata = _cdata == None
    unknown = None
    try:
        # is _cdata actual ffi data?
        ffi.typeof(_cdata)
    except TypeError:
        # No, its some type of pyton data, so clear it from _cdata and call init
        unknown = _cdata
        _cdata = None

        if _cdata is None:
            _cdata = ffi.new(f"{this.__class__.__name__} *")

    # if it's unknown, find the field it's destined for. This is easy for TPML_
    # and TPM2B_ types because their is only one field.
    if unknown is not None:
        tipe = cpointer_to_ctype(_cdata)

        # ignore the field that is size or count, and get the one for the data
        size_field_name = "size" if "TPM2B_" in tipe.cname else "count"
        field_name = next((v[0] for v in tipe.fields if v[0] != size_field_name), None)

        if len(kwargs) != 0:
            raise RuntimeError(
                f"Ambigous call, try using key {field_name} in parameters"
            )

        kwargs[field_name] = unknown
    elif len(kwargs) == 0:
        return (_cdata, {})
    elif not null_cdata and len(kwargs) != 1:
        raise RuntimeError(f"Expected at most one key value pair, got: {len(kwargs)}")

    return (_cdata, kwargs)
