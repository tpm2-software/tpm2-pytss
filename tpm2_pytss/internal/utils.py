# SPDX-License-Identifier: BSD-2
import logging
import sys
from typing import List

import pkgconfig

from .._libtpm2_pytss import ffi, lib
from ..TSS2_Exception import TSS2_Exception

logger = logging.getLogger(__name__)

# Peek into the loaded modules, if mock is loaded, set __MOCK__ to True, else False
__MOCK__ = "unittest.mock" in sys.modules


def _chkrc(rc, acceptable=None):
    if acceptable is None:
        acceptable = []
    elif isinstance(acceptable, int):
        acceptable = [acceptable]
    acceptable += [lib.TPM2_RC_SUCCESS]
    if rc not in acceptable:
        raise TSS2_Exception(rc)


def _to_bytes_or_null(value, allow_null=True, encoding=None):
    """Convert to cdata input.

    None:  ffi.NULL (if allow_null == True)
    bytes: bytes
    str:   str.encode()
    """
    if encoding is None:
        encoding = "utf-8"
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


def _CLASS_INT_ATTRS_from_string(cls, str_value, fixup_map=None):
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


def _cpointer_to_ctype(x):
    tipe = ffi.typeof(x)
    if tipe.kind == "pointer":
        tipe = tipe.item
    return tipe


def _fixup_cdata_kwargs(this, _cdata, kwargs):

    # folks may call this routine without a keyword argument which means it may
    # end up in _cdata, so we want to try and work this out
    unknown = None
    try:
        # is _cdata actual ffi data?
        ffi.typeof(_cdata)
    except (TypeError, ffi.error):
        # No, its some type of Python data
        # Is it the same instance and a coy constructor call?
        # ie TPMS_ECC_POINT(TPMS_ECC_POINT(x=... , y=...))
        if isinstance(_cdata, type(this)):
            pyobj = _cdata
            _cdata = ffi.new(f"{this.__class__.__name__} *", pyobj._cdata[0])
        else:
            # Its not a copy constructor, so it must be for a subfield,
            # so clear it from _cdata and call init
            unknown = _cdata
            _cdata = ffi.new(f"{this.__class__.__name__} *")

    # if it's unknown, find the field it's destined for. This is easy for TPML_
    # and TPM2B_ types because their is only one field.
    if unknown is not None:
        tipe = _cpointer_to_ctype(_cdata)

        # ignore the field that is size or count, and get the one for the data
        size_field_name = "size" if "TPM2B_" in tipe.cname else "count"
        field_name = next((v[0] for v in tipe.fields if v[0] != size_field_name), None)

        if len(kwargs) != 0:
            raise RuntimeError(
                f"Ambiguous call, try using key {field_name} in parameters"
            )

        if hasattr(unknown, "_cdata"):
            a = _cpointer_to_ctype(getattr(_cdata, field_name))
            b = _cpointer_to_ctype(unknown._cdata)
            if a != b:
                expected = _fixup_classname(tipe)
                got = _fixup_classname(b)
                raise TypeError(
                    f"Expected initialization from type {expected}, got {got}"
                )

        kwargs[field_name] = unknown
    elif len(kwargs) == 0:
        return (_cdata, {})

    return (_cdata, kwargs)


def _ref_parent(data, parent):
    tipe = ffi.typeof(parent)
    if tipe.kind != "pointer":
        return data

    def deconstructor(ptr):
        parent

    return ffi.gc(data, deconstructor)


def _convert_to_python_native(global_map, data, parent=None):

    if not isinstance(data, ffi.CData):
        return data

    if parent is not None:
        data = _ref_parent(data, parent)

    tipe = ffi.typeof(data)

    # Native arrays, like uint8_t[4] we don't wrap. We just let the underlying
    # data type handle it.
    if tipe.kind == "array" and tipe.cname.startswith("uint"):
        return data

    # if it's not a struct or union, we don't wrap it and thus we don't
    # know what to do with it.
    if tipe.kind != "struct" and tipe.kind != "union":
        raise TypeError(f'Not struct or union, got: "{tipe.kind}"')

    clsname = _fixup_classname(tipe)
    subclass = global_map[clsname]
    obj = subclass(_cdata=data)
    return obj


def _fixup_classname(tipe):
    # Some versions of tpm2-tss had anonymous structs, so the kind will be struct
    # but the name will not contain it
    if tipe.cname.startswith(tipe.kind):
        return tipe.cname[len(tipe.kind) + 1 :]

    return tipe.cname


def _mock_bail():
    return __MOCK__


def _get_dptr(dptr, free_func):
    return ffi.gc(dptr[0], free_func)


def _check_friendly_int(friendly, varname, clazz):

    if not isinstance(friendly, int):
        raise TypeError(f"expected {varname} to be type int, got {type(friendly)}")

    if not clazz.contains(friendly):
        raise ValueError(
            f"expected {varname} value of {friendly} in class {str(clazz)}, however it's not found."
        )


def is_bug_fixed(
    fixed_in=None, backports: List[str] = None, lib: str = "tss2-fapi"
) -> bool:
    """Use pkg-config to determine if a bug was fixed in the currently installed tpm2-tss version."""
    if fixed_in and pkgconfig.installed(lib, f">= {fixed_in}"):
        return True

    try:
        version = pkgconfig.modversion(lib)
    except pkgconfig.pkgconfig.PackageNotFoundError:
        return False

    version = version.split("-")[0]
    vers_major, vers_minor, vers_patch = (int(s) for s in version.split("."))

    if backports is None:
        backports = []
    for backport in backports:
        backp_major, backp_minor, backp_patch = (int(s) for s in backport.split("."))

        if vers_major == backp_major and vers_minor == backp_minor:
            return vers_patch >= backp_patch

    return False


def _check_bug_fixed(
    details,
    fixed_in=None,
    backports: List[str] = None,
    lib: str = "tss2-fapi",
    error: bool = False,
) -> None:
    """Emit a warning or exception if there is an unfixed bug in the currently installed tpm2-tss version."""
    if not is_bug_fixed(fixed_in=fixed_in, backports=backports, lib=lib):
        version = pkgconfig.modversion(lib)
        message = f"This API call {'is' if error else 'may be'} affected by a bug in {lib} version {version}: {details}\nPlease use >= {fixed_in}. Backports exist for {backports}."

        if error:
            raise RuntimeError(message)

        logger.warning(message)
