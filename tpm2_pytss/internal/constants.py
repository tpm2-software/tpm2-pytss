# SPDX-License-Identifier: BSD-2

from enum import Enum, auto


class CallbackType(Enum):
    """Kinds of c callbacks. Typically, their signature differs."""

    FAPI_AUTH = auto()
    FAPI_BRANCH = auto()
    FAPI_SIGN = auto()
    FAPI_POLICYACTION = auto()


CALLBACK_COUNT = 10


CALLBACK_BASE_NAME = {
    CallbackType.FAPI_AUTH: "_auth_callback_wrapper_",
    CallbackType.FAPI_BRANCH: "_branch_callback_wrapper_",
    CallbackType.FAPI_SIGN: "_sign_callback_wrapper_",
    CallbackType.FAPI_POLICYACTION: "_policyaction_callback_wrapper_",
}
