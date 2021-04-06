"""
SPDX-License-Identifier: BSD-3
"""

from enum import Enum, auto


class CallbackType(Enum):
    """Kinds of c callbacks. Typically, their signature differs."""

    FAPI_AUTH = auto()


CALLBACK_COUNT = 10


CALLBACK_BASE_NAME = {CallbackType.FAPI_AUTH: "_auth_callback_wrapper_"}
