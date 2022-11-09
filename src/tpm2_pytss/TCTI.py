# SPDX-License-Identifier: BSD-2

from ._libtpm2_pytss import ffi

from .internal.utils import _chkrc


class TCTI:
    def __init__(self, ctx):
        self._v1 = ffi.cast("TSS2_TCTI_CONTEXT_COMMON_V1 *", ctx)
        if self._v1.version == 2:
            self._v2 = ffi.cast("TSS2_TCTI_CONTEXT_COMMON_V2 *", ctx)
        else:
            self._v2 = None
        self._ctx = ctx

    @property
    def _tcti_context(self):
        return self._ctx

    @property
    def magic(self):
        return self._v1.magic

    @property
    def version(self):
        return self._v1.version

    def _common_checks(self, method, version=1):

        if self._v1.version < 1:
            raise TSS2_Exception(TSS2_RC.TCTI_RC_ABI_MISMATCH)

        sub_struct = getattr(self, f"_v{version}")
        got_method = getattr(sub_struct, method)

        if got_method == ffi.NULL:
            raise TSS2_Exception(TSS2_RC.TCTI_RC_NOT_IMPLEMENTED)

    def transmit(self, command):
        self._common_checks("transmit")

        cmd = ffi.new("uint8_t []", command)
        clen = len(command)
        _chkrc(self._v1.transmit(self._ctx, clen, cmd))

    def receive(self, size=-1, timeout=-1):
        self._common_checks("receive")

        if size == -1:
            size = 4096
        resp = ffi.new("uint8_t []", b"\x00" * size)
        rsize = ffi.new("size_t *", size)
        _chkrc(self._v1.receive(self._ctx, rsize, resp, timeout))
        return bytes(ffi.buffer(resp, rsize[0]))

    def finalize(self):
        if self._v1.finalize != ffi.NULL:
            self._v1.finalize(self._ctx)

    def cancel(self):
        self._common_checks("cancel")

        _chkrc(self._v1.cancel(self._ctx))

    def get_poll_handles(self):
        self._common_checks("getPollHandles")

        nhandles = ffi.new("size_t *", 0)
        _chkrc(self._v1.getPollHandles(self._ctx, ffi.NULL, nhandles))
        if nhandles[0] == 0:
            return ()
        handles = ffi.new("TSS2_TCTI_POLL_HANDLE []", nhandles[0])
        _chkrc(self._v1.getPollHandles(self._ctx, handles, nhandles))
        rh = []
        for i in range(0, nhandles[0]):
            rh.append(handles[i])
        return tuple(rh)

    def set_locality(self, locality):
        self._common_checks("setLocality")
        _chkrc(self._v1.setLocality(self._ctx, locality))

    def make_sticky(self, handle, sticky):
        self._common_checks("makeSticky", version=2)

        hptr = ffi.new("TPM2_HANDLE *", handle)
        _chkrc(self._v2.makeSticky(self._ctx, hptr, sticky))
        return hptr[0]
