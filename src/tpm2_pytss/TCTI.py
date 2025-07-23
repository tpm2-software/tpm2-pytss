# SPDX-License-Identifier: BSD-2

from ._libtpm2_pytss import ffi, lib

from .internal.utils import _chkrc
from .constants import TSS2_RC, TPM2_RC
from .TSS2_Exception import TSS2_Exception

import os
from typing import Optional, Tuple, Union


class PollData(object):
    """Initialize a PollData object with OS specific details.

    Initialize a PollData object that holds all OS specific state and metadata information
    for using in the platforms specific asynchronous IO "polling" system. For Linux this
    is Poll, Windows is WaitForSingleObject or other interfaces. Only posix systems currently
    support the events attribute. The system is identified by `os.name`.

    Args:
        fd (int): The File Descriptor(fd) for posix systems or Opque Handle for other systems.
        events (int): The event mask, only for posix systems.

    Returns:
        An instance of the PollData class.
    """

    def __init__(self, fd: int = -1, events: int = -1):
        self._fd = fd
        self._events = events

    @property
    def fd(self) -> int:
        """Gets the File Descriptor or Handle for the asynch I/O wait event.

        Returns:
            The fd or handle.
        """
        return self._fd

    @property
    def handle(self) -> int:
        """Gets the File Descriptor or Handle for the asynch I/O wait event.

        Same as attribute fd.

        Returns:
            The fd or handle.
        """
        return self._fd

    @property
    def events(self) -> int:
        """Gets the Event Mask for the asynch I/O wait event. Suitable for poll.

        Returns:
            The poll event mask.

        Raises:
            NotImplementedError if os.name does not equal "posix".
        """
        if os.name != "posix":
            raise NotImplementedError(
                f"Non POSIX os detected, pollin events not supported, got: {os.name}"
            )
        return self._events


def common_checks(version=1, null_ok=False):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            def camel_case(s):
                from re import sub

                s = sub(r"(_|-)+", " ", s).title().replace(" ", "")
                return "".join([s[0].lower(), s[1:]])

            if self._v1.version < 1:
                raise TSS2_Exception(TSS2_RC.TCTI_RC_ABI_MISMATCH)

            sub_struct = getattr(self, f"_v{version}")
            if sub_struct is None:
                raise TSS2_Exception(TSS2_RC.TCTI_RC_NOT_IMPLEMENTED)

            method = func.__name__
            method = camel_case(method)
            got_method = getattr(sub_struct, method)
            if not null_ok and got_method == ffi.NULL:
                raise TSS2_Exception(TSS2_RC.TCTI_RC_NOT_IMPLEMENTED)

            try:
                self._clear_exceptions()
                return func(self, *args, **kwargs)
            except Exception as e:
                e = self._get_current_exception(e)
                self._clear_exceptions()
                raise e

        return wrapper

    return decorator


class TCTI:
    """Initialize a TCTI object.

    Initialize a TCTI from a NATIVE instantiated TCTI.

    Args:
        ctx (ffi.CData): A TSS2_TCTI_CONTEXT * variable. This would be returned from a TCTIs
            initialize or TCTILdr routine.

    Returns:
        An instance of a TCTI.
    """

    def __init__(self, ctx: ffi.CData):
        self._v1 = ffi.cast("TSS2_TCTI_CONTEXT_COMMON_V1 *", ctx)
        if self._v1.version == 2:
            self._v2 = ffi.cast("TSS2_TCTI_CONTEXT_COMMON_V2 *", ctx)
        else:
            self._v2 = None
        self._ctx = ctx
        # record the last exception so we can throw across the C boundry without
        # everything becoming an unknown TSS2_Exception(TSS2_RC.TCTI_RC_GENERAL_FAILURE)
        # Normal TCTIs cannot make use of this, by Python TCTIs can. Add it to the base class
        # for subordinate TCTIs to use. This way the TCTI fn calls return the most helpful
        # error.
        self._last_exception = None

    def _set_last_exception(self, exc):
        self._last_exception = exc

    @property
    def _tcti_context(self):
        return self._ctx

    @property
    def magic(self) -> bytes:
        """Returns the MAGIC string of the TCTI.

        Returns:
            The magic byte string.
        """

        # uint64_t in C land by default or let subclass control it
        magic_len = getattr(self, "_magic_len", 8)
        return self._v1.magic.to_bytes(magic_len, "big")

    @property
    def version(self) -> int:
        """Returns the VERSION number of the TCTI.

        This is the TCTI interface version NOT the release
        version of the TCTI. Ie if it implements version 1
        or version 2 of the spec.

        Returns:
            The TCTI version number.
        """

        return self._v1.version

    def _clear_exceptions(self):
        self._last_exception = None

    def _get_current_exception(self, e: Exception):
        x = self._last_exception
        return x if x is not None else e

    @common_checks()
    def transmit(self, command: bytes) -> None:
        """Transmits bytes to the TPM.

        Args:
            command (bytes): The bytes to transmit to the TPM.

        Returns:
            The TCTI version number.

        Raises:
            TSS2_Exception - Underlying TCTI errors
            Exception - Underlying Python TCTIs can return anything.
        """

        cmd = ffi.new("uint8_t []", command)
        clen = len(command)
        _chkrc(self._v1.transmit(self._ctx, clen, cmd))

    @common_checks()
    def receive(self, size: int = 4096, timeout: int = -1) -> bytes:
        """Receives bytes from the TPM.

        Args:
            size (int): The maximum expected response size. Defaults to 4096.
                Negative values infer the default.
            timeout (int): The maximum time to wait for a response in milliseconds.
                Defaults to -1 which will wait indefinitely.

        Returns:
            The TPM response as bytes.

        Raises:
            TSS2_Exception - Underlying TCTI errors
            Exception - Underlying Python TCTIs can return anything.
        """

        if size < 0:
            size = 4096

        resp = ffi.new("uint8_t []", b"\x00" * size)
        rsize = ffi.new("size_t *", size)
        _chkrc(self._v1.receive(self._ctx, rsize, resp, timeout))

        return bytes(ffi.buffer(resp, rsize[0]))

    @common_checks(null_ok=True)
    def finalize(self):
        """Cleans up a TCTI's state and resources."""

        if self._v1.finalize != ffi.NULL:
            self._v1.finalize(self._ctx)
            if self._last_exception:
                e = self._last_exception
                self._clear_exceptions()
                raise e

    @common_checks()
    def cancel(self) -> None:
        """Cancels a current transmit with the TPM.

        Some TCTIs may support the ability to cancel the current
        I/O Operation with the TPM.

        Raises:
            TSS2_Exception - Underlying TCTI errors
            Exception - Underlying Python TCTIs can return anything.
        """

        _chkrc(self._v1.cancel(self._ctx))

    @common_checks()
    def get_poll_handles(self) -> Tuple[PollData]:
        """Gets the poll handles from the TPM.

        Returns:
            A tuple of PollData objects.

        Raises:
            TSS2_Exception - Underlying TCTI errors
            Exception - Underlying Python TCTIs can return anything.
        """

        nhandles = ffi.new("size_t *", 0)
        _chkrc(self._v1.getPollHandles(self._ctx, ffi.NULL, nhandles))
        if nhandles[0] == 0:
            return ()
        handles = ffi.new("TSS2_TCTI_POLL_HANDLE []", nhandles[0])
        _chkrc(self._v1.getPollHandles(self._ctx, handles, nhandles))
        rh = []
        for i in range(0, nhandles[0]):
            if os.name == "posix":
                pd = PollData(handles[i].fd, handles[i].events)
            else:
                pd = PollData(handles[i])
            rh.append(pd)
        return tuple(rh)

    @common_checks()
    def set_locality(self, locality: int) -> None:
        """Sets the locality of the current TCTI connection with the TPM.

        Locality is a value that specifies to the TPM whom is making the
        request. Ie firmware, OS, userspace, etc. For TCTIs and
        TPMs that support this, this interface allows one to set the
        locality.

        Args:
            locality (int): The locality value as an integer.

        Raises:
            TSS2_Exception - Underlying TCTI errors
            Exception - Underlying Python TCTIs can return anything.
        """

        _chkrc(self._v1.setLocality(self._ctx, locality))

    @common_checks(version=2)
    def make_sticky(self, handle: int, sticky: Union[bool, int]) -> None:
        """Makes an object specified by handle not be flushed by a resource manager.

        Resource Managers (RM) MAY flush transient objects when the client disconnects.
        Thus this object would need to be re-established later, eg TPM2_Load command,
        this allows RMs that support the ability to mark this object as non-flushable.

        Raises:
            TSS2_Exception - Underlying TCTI errors
            Exception - Underlying Python TCTIs can return anything.
        """

        hptr = ffi.new("TPM2_HANDLE *", handle)
        _chkrc(self._v2.makeSticky(self._ctx, hptr, sticky))
        return hptr[0]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()


# Global callbacks
@ffi.def_extern()
def _tcti_transmit_wrapper(ctx, size, command):
    pi = PyTCTI._cffi_cast(ctx)
    if not hasattr(pi, "do_transmit"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        pi.do_transmit(bytes(ffi.buffer(command, size)))
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        pi._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_receive_wrapper(ctx, size, response, timeout):

    # Let the allocator know how much we need.
    pi = PyTCTI._cffi_cast(ctx)
    if response == ffi.NULL:
        size[0] = pi._max_size
        return TPM2_RC.SUCCESS

    if not hasattr(pi, "do_receive"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        resp = pi.do_receive(timeout)
        max_size = size[0]
        if len(resp) > max_size:
            raise TSS2_Exception(TSS2_RC.TCTI_RC_INSUFFICIENT_BUFFER)

        size[0] = len(resp)
        ffi.memmove(response, resp, len(resp))
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        pi._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_cancel_wrapper(ctx):
    pi = PyTCTI._cffi_cast(ctx)
    if not hasattr(pi, "do_cancel"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        pi.do_cancel()
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        pi._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_get_pollfds_wrapper(ctx, handles, cnt):
    pi = PyTCTI._cffi_cast(ctx)
    if not hasattr(pi, "do_get_poll_handles"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        # Populate a cache so Python implementors don't have to be called
        # for size and then fd's. FDs should be stable.
        if pi._poll_handle_cache is None:
            pi._poll_handle_cache = pi.do_get_poll_handles()
            # Support callers returning None or list
            if pi._poll_handle_cache is None:
                pi._poll_handle_cache = ()

        # caller wants size for allocation
        if handles == ffi.NULL:
            cnt[0] = len(pi._poll_handle_cache)
        elif cnt[0] < len(pi._poll_handle_cache):
            raise TSS2_RC.TCTI_RC_INSUFFICIENT_BUFFER
        else:
            cnt[0] = len(pi._poll_handle_cache)
            # Enumerate didn't work here
            for i in range(0, cnt[0]):
                pd = pi._poll_handle_cache[i]
                # convert platform agnostic into CData
                if os.name == "posix":
                    handles[i].fd = pd.fd
                    handles[i].events = pd.events
                else:
                    handles[i] = pd.handle
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        pi._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_set_locality_wrapper(ctx, locality):
    pi = PyTCTI._cffi_cast(ctx)
    if not hasattr(pi, "do_set_locality"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        pi.do_set_locality(locality)
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        pi._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_make_sticky_wrapper(ctx, handle, sticky):
    pi = PyTCTI._cffi_cast(ctx)
    if not hasattr(pi, "do_make_sticky"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        pi.do_make_sticky(handle, bool(sticky))
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        pi._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_finalize_wrapper(ctx):
    pi = PyTCTI._cffi_cast(ctx)
    if not hasattr(pi, "do_finalize"):
        return

    try:
        pi.do_finalize()
    except Exception as e:
        pi._set_last_exception(e)


class PyTCTI(TCTI):
    """Subclass for implementing a TCTI in Python.

    Extend this object and implement the following methods:
        - def do_transmit(self, command: bytes) -> None
            This method transmits a command buffer to the TPM. This method IS REQUIRED.

        - def do_receive(self, timeout: int) -> bytes:
            This method receives a response from the TPM and returns it. This method IS REQUIRED

        - def do_cancel(self) -> None:
             Cancels an I/O operation with the TPM. This method is OPTIONAL.

        - def do_get_poll_handles(self) -> Optional[Tuple[PollData]]:
             Retrieves PollData objects from the TCTI used for async I/O. This method is OPTIONAL.

        - def do_set_locality(self, locality: int) -> None:
             Sets the locality in which to communicate with the TPM. This method is OPTIONAL.

        - def do_make_sticky(self, handle: int, is_sticky: bool) -> None:
             Makes a handle sticky to persist across client exits with an RM. This method is OPTIONAL.

        - def do_finalize(self) -> None:
             Finalizes a TCTI, this is analogous to close on a file. This method is OPTIONAL.

    Note:
        All methods may throw exceptions as needed.

    Args:
        max_size (int): The size of the response buffer for callers to allocate. Defaults to 4096.
        magic (bytes): The magic value for the TCTI, may aid in debugging. Max length is 8, defaults to b"PYTCTI\x00\x00"

    Returns:
        An instance of the PyTCTI class. It's unusable as is, users should extend it.
    """

    def __init__(self, max_size: int = 4096, magic: bytes = b"PYTCTI\x00\x00"):
        # PYTCTI ASCII FOR MAGIC: echo -n "5059544354490000" | xxd -r -cdata

        if len(magic) > 8:
            raise ValueError(f"Expected magic to be at most 8 bytes, got: {len(magic)}")

        cdata = self._cdata = ffi.new("PYTCTI_CONTEXT *")
        self._max_size = max_size
        self._poll_handle_cache = None
        self._magic_len = len(magic)
        cdata.common.v1.version = 2
        cdata.common.v1.magic = int.from_bytes(magic, "big")
        cdata.common.v1.transmit = lib._tcti_transmit_wrapper
        cdata.common.v1.receive = lib._tcti_receive_wrapper
        cdata.common.v1.cancel = lib._tcti_cancel_wrapper
        cdata.common.v1.getPollHandles = lib._tcti_get_pollfds_wrapper
        cdata.common.v1.setLocality = lib._tcti_set_locality_wrapper
        cdata.common.makeSticky = lib._tcti_make_sticky_wrapper
        cdata.common.v1.finalize = lib._tcti_finalize_wrapper

        # Keep a pointer to this object in the TCTI Context to use later
        # This is how we multiplex N objects through a set of static
        # callbacks. Assign it to an object instance variable to prevent
        # it from getting GC
        cdata.thiz = self._thiz = ffi.new_handle(self)

        opaque = ffi.cast("TSS2_TCTI_CONTEXT *", cdata)
        super().__init__(opaque)

    @staticmethod
    def _cffi_cast(ctx):
        ctx = ffi.cast("PYTCTI_CONTEXT *", ctx)
        return ffi.from_handle(ctx.thiz)

    def do_transmit(self, command: bytes) -> None:
        """This method transmits a command buffer to the TPM. This method IS REQUIRED.

        Args:
            command (bytes): The bytes to send to the TPM.

        Raises:
            NotImplementedError: If a subclass has not implemented this.
            Exception: Implementations are free to raise any Exception. Exceptions are retained
            across the native boundary.
        """

        raise NotImplementedError("Subclass needs to implement do_transmit")

    def do_receive(self, timeout: int) -> bytes:
        """This method receives a response from the TPM and returns it. This method IS REQUIRED.

        Args:
            timeout (int): The timeout in milliseconds to wait for the TPM. Negative values mean
                wait indefinitely.

        Raises:
            NotImplementedError: If a subclass has not implemented this.
            Exception: Implementations are free to raise any Exception. Exceptions are retained
            across the native boundary.
        """

        raise NotImplementedError("Subclass needs to implement do_receive")

    def do_cancel(self) -> None:
        """Cancels an I/O operation with the TPM. This method is OPTIONAL.

        Raises:
            Exception: Implementations are free to raise any Exception. Exceptions are retained
            across the native boundary.
        """
        pass

    def do_get_poll_handles(self) -> Optional[Tuple[PollData]]:
        """Retrieves PollData objects from the TCTI used for async I/O. This method is OPTIONAL.

        Returns:
            The tuple of PollData handles or None.

        Raises:
            Exception: Implementations are free to raise any Exception. Exceptions are retained
            across the native boundary.
        """
        pass

    def do_set_locality(self, locality: int) -> None:
        """Sets the locality in which to communicate with the TPM. This method is OPTIONAL.

        Args:
            locality(int): The locality of communication with the TPM.

        Raises:
            Exception: Implementations are free to raise any Exception. Exceptions are retained
            across the native boundary.
        """
        pass

    def do_make_sticky(self, handle: int, is_sticky: bool) -> None:
        """Makes a handle sticky to persist across client exits with a Resource Manager. This method is OPTIONAL.

        Note: A sticky object is one a RM doesn't flush when the client closes their connection.

        Args:
            handle(int): The TPM handle to make sticky.
            is_sticky(bool): True to make sticky, False to make it not sticky.

        Raises:
            Exception: Implementations are free to raise any Exception. Exceptions are retained
            across the native boundary.
        """
        pass

    def do_finalize(self) -> None:
        """Finalizes a TCTI, this is analogous to close on a file. This method is OPTIONAL.

        Note: Native TCTIs do not return anything and thus cannot raise any errors. Python
        TCTIs MAY raise exceptions across this interface.

        Raises:
            Exception: Implementations are free to raise any Exception. Exceptions are retained
            across the native boundary.
        """
        pass
