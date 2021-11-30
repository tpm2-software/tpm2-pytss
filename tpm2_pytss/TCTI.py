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

    def transmit(self, command):
        cmd = ffi.new("uint8_t []", command)
        clen = len(command)
        _chkrc(self._v1.transmit(self._ctx, clen, cmd))

    def receive(self, size=-1, timeout=-1):
        if size == -1:
            size = 4096
        resp = ffi.new("uint8_t []", b"\x00" * size)
        rsize = ffi.new("size_t *", size)
        _chkrc(self._v1.receive(self._ctx, rsize, resp, timeout))
        return bytes(ffi.buffer(resp, rsize[0]))

    def finalize(self):
        self._v1.finalize(self._ctx)

    def cancel(self):
        _chkrc(self._v1.cancel(self._ctx))

    def get_poll_handles(self):
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
        _chkrc(self._v1.setLocality(self._ctx, locality))

    def make_sticky(self, handle, sticky):
        if self._v2 is None:
            raise RuntimeError("unsupported by TCTI API version")
        hptr = ffi.new("TPM2_HANDLE *", handle)
        _chkrc(self._v2.makeSticky(self._ctx, hptr, sticky))
        return hptr[0]
