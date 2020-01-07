# SPDX-License-Identifier: MIT
# Copyright (c) 2019 Intel Corporation
import inspect
from functools import wraps
from typing import Optional, Callable, List, Any

from .esys_binding import (
    Tss2_RC_Decode,
    TPM2_RC_FMT1,
    TPM2_RC_P,
    TPM2_RC_S,
    TPM2_RC_N_MASK,
)


class TPM2Error(Exception):
    def __init__(self, rc: int):
        super(TPM2Error, self).__init__(Tss2_RC_Decode(rc))
        self.rc = rc
        self.handle = 0
        self.parameter = 0
        self.session = 0
        self.error = 0
        if self.rc & TPM2_RC_FMT1:
            self._parse_fmt1()
        else:
            self.error = self.rc

    def _parse_fmt1(self):
        self.error = TPM2_RC_FMT1 + (self.rc & 0x3F)

        if self.rc & TPM2_RC_P:
            self.parameter = (self.rc & TPM2_RC_N_MASK) >> 8
        elif self.rc & TPM2_RC_S:
            self.session = ((self.rc - TPM2_RC_S) & TPM2_RC_N_MASK) >> 8
        else:
            self.handle = (self.rc & TPM2_RC_N_MASK) >> 8


def raise_tpm2_error(func):
    """
    Decorator to wrap TPM2 functions so that non-zero return values trigger
    errors.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        rc = func(*args, **kwargs)
        if isinstance(rc, int) and rc != 0:
            raise TPM2Error(rc)
        return rc

    return wrapper


def raise_tpm2_mu_error(func):
    """
    Decorator to wrap TPM2 MU functions so that non-zero return code values trigger
    errors.
    """

    @wraps(func)
    def mu_wrapper(*args, **kwargs):
        rc, offset = func(*args, **kwargs)
        if isinstance(rc, int) and rc != 0:
            raise TPM2Error(rc)
        return rc, offset

    return mu_wrapper


def wrap_funcs(
    src,
    *,
    dst: Optional[List[Any]] = None,
    cond: Optional[Callable[[Callable], bool]] = None,
    wrapperfunc=raise_tpm2_error
):
    """
    Wrap the functions within the given module with a decorator so that if they
    return integer values that are non-zero an error will be thrown.
    """
    if dst is None:
        dst = [src]
    for key, func in inspect.getmembers(src):
        if inspect.isfunction(func) and (cond is None or cond(key, func)):
            wrapped = wrapperfunc(func)
            for module in dst:
                setattr(module, key, wrapped)
    return dst[0]
