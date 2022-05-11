# SPDX-License-Identifier: BSD-2


from ._libtpm2_pytss import lib
from .internal.constants import CALLBACK_BASE_NAME, CALLBACK_COUNT, CallbackType


class Callback:
    """C callback function and its name."""

    def __init__(self, name: str):
        self.name = name
        self.c_function = getattr(lib, self.name)
        self.free = True


callbacks = {
    CallbackType.FAPI_AUTH: {
        Callback(f"{CALLBACK_BASE_NAME[CallbackType.FAPI_AUTH]}{i}")
        for i in range(0, CALLBACK_COUNT)
    },
    CallbackType.FAPI_BRANCH: {
        Callback(f"{CALLBACK_BASE_NAME[CallbackType.FAPI_BRANCH]}{i}")
        for i in range(0, CALLBACK_COUNT)
    },
    CallbackType.FAPI_SIGN: {
        Callback(f"{CALLBACK_BASE_NAME[CallbackType.FAPI_SIGN]}{i}")
        for i in range(0, CALLBACK_COUNT)
    },
    CallbackType.FAPI_POLICYACTION: {
        Callback(f"{CALLBACK_BASE_NAME[CallbackType.FAPI_POLICYACTION]}{i}")
        for i in range(0, CALLBACK_COUNT)
    },
}


def get_callback(callback_type: CallbackType) -> Callback:
    """Returns the name of a callback and locks it."""
    callback = next(cb for cb in callbacks[callback_type] if cb.free)
    callback.free = False
    return callback


def unlock_callback(callback_type: CallbackType, name: str) -> None:
    """Unlocks the callback."""
    callback = next(cb for cb in callbacks[callback_type] if cb.name is name)
    callback.free = True
