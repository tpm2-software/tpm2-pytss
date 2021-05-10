"""
SPDX-License-Identifier: BSD-2
"""


from ._libtpm2_pytss import lib
from .constants import CallbackType, CALLBACK_BASE_NAME, CALLBACK_COUNT


class Callback:
    """C callback function and its name."""

    def __init__(self, name):
        self.name = name
        self.c_function = getattr(lib, self.name)
        self.free = True


callbacks = {
    CallbackType.FAPI_AUTH: {
        Callback(f"{CALLBACK_BASE_NAME[CallbackType.FAPI_AUTH]}{i}")
        for i in range(0, CALLBACK_COUNT)
    }
}


def get_callback(callback_type: CallbackType):
    """Returns the name of a callback and locks it."""
    callback = next(cb for cb in callbacks[callback_type] if cb.free)
    callback.free = False
    return callback


def unlock_callback(callback_type: CallbackType, name):
    """Unlocks the callback."""
    callback = next(cb for cb in callbacks[callback_type] if cb.name is name)
    callback.free = True
