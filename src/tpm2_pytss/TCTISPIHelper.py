# SPDX-License-Identifier: BSD-2

from .internal.utils import _chkrc, _lib_version_atleast
from ._libtpm2_pytss import ffi, lib
from .constants import TSS2_RC, TPM2_RC
from .TSS2_Exception import TSS2_Exception
from .TCTI import TCTI

if not _lib_version_atleast("tss2-tcti-spi-helper", "0.0.0"):
    raise NotImplementedError("Package tss2-tcti-spi-helper not present")


@ffi.def_extern()
def _tcti_spi_helper_sleep_ms(userdata, milliseconds):
    thiz = TCTISPIHelper._cffi_cast(userdata)
    if not hasattr(thiz, "on_sleep_ms"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        thiz.on_sleep_ms(milliseconds)
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        thiz._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_spi_helper_start_timeout(userdata, milliseconds):
    thiz = TCTISPIHelper._cffi_cast(userdata)
    if not hasattr(thiz, "on_start_timeout"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        thiz.on_start_timeout(milliseconds)
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        thiz._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_spi_helper_timeout_expired(userdata, is_time_expired) -> bool:

    thiz = TCTISPIHelper._cffi_cast(userdata)
    if not hasattr(thiz, "on_timeout_expired"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        result = thiz.on_timeout_expired()
        is_time_expired[0] = result
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        thiz._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_spi_helper_spi_acquire(userdata):
    thiz = TCTISPIHelper._cffi_cast(userdata)
    if not hasattr(thiz, "on_start_timeout"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        thiz.on_spi_acquire()
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        thiz._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_spi_helper_spi_release(userdata):
    thiz = TCTISPIHelper._cffi_cast(userdata)
    if not hasattr(thiz, "on_spi_release"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        thiz.on_spi_release()
    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        thiz._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_spi_helper_spi_transfer(userdata, data_out, data_in, cnt):
    thiz = TCTISPIHelper._cffi_cast(userdata)
    if not hasattr(thiz, "on_spi_transfer"):
        return TSS2_RC.TCTI_RC_NOT_IMPLEMENTED
    try:
        # setup for the transaction
        dout = None if data_out == ffi.NULL else bytes(ffi.buffer(data_out, cnt))

        # call for transaction
        data_got = thiz.on_spi_transfer(dout)

        # handle response should None be OK?
        if data_got is None and data_in != ffi.NULL:
            raise RuntimeError("Response data CANNOT be None")
        elif data_got is None and data_in == ffi.NULL:
            return TPM2_RC.SUCCESS

        # current interface is hardcoded to full duplex, so input
        # must equal output
        if len(data_got) != cnt:
            raise ValueError(
                f"Transactions is expected to be {cnt} bytes, got {len(data_got)} bytes"
            )

        # copy the data
        raw_data_got = ffi.from_buffer(data_got)
        ffi.memmove(data_in, raw_data_got, len(data_got))

    except Exception as e:
        rc = e.rc if isinstance(e, TSS2_Exception) else TSS2_RC.TCTI_RC_GENERAL_FAILURE
        thiz._set_last_exception(e)
        return rc

    return TPM2_RC.SUCCESS


@ffi.def_extern()
def _tcti_spi_helper_finalize(userdata):
    thiz = TCTISPIHelper._cffi_cast(userdata)
    if hasattr(thiz, "on_finalize"):
        thiz.on_finalize(thiz)


class TCTISPIHelper(TCTI):
    """The  TCTI for interacting with SPI devices.

    Users should *extend* a TCTISPIHelper object and implement the following callbacks:

    All Users:
      - on_sleep_ms
      - on_start_timeout
      - on_timeout_expired
      - on_spi_transfer

    with_wait_state=true:
      - on_spi_acquire
      - on_spi_release

    Optional:
      - on_finalize

    Args:
        with_wait_state (bool): True if you intend to use wait states. Defaults to False.
    """

    def __init__(self, with_wait_state=False):
        self._with_wait_state = with_wait_state

        size = ffi.new("size_t *")
        self._callbacks = ffi.new("TSS2_TCTI_SPI_HELPER_PLATFORM *")
        self._callbacks.sleep_ms = lib._tcti_spi_helper_sleep_ms
        self._callbacks.start_timeout = lib._tcti_spi_helper_start_timeout
        self._callbacks.timeout_expired = lib._tcti_spi_helper_timeout_expired
        self._callbacks.spi_transfer = lib._tcti_spi_helper_spi_transfer
        self._callbacks.finalize = lib._tcti_spi_helper_finalize
        self._callbacks.user_data = self._thiz = ffi.new_handle(self)

        missing_implementation = []
        if self._with_wait_state:
            self._callbacks.spi_acquire = lib._tcti_spi_helper_spi_acquire
            self._callbacks.spi_release = lib._tcti_spi_helper_spi_release
            if "TCTISPIHelper.on_spi_acquire" in str(self.on_spi_acquire):
                missing_implementation.append("on_spi_acquire")

            if "TCTISPIHelper.on_spi_release" in str(self.on_spi_release):
                missing_implementation.append("on_spi_release")

        if "TCTISPIHelper.on_spi_transfer" in str(self.on_spi_transfer):
            missing_implementation.append("on_spi_transfer")

        if "TCTISPIHelper.on_timeout_expired" in str(self.on_timeout_expired):
            missing_implementation.append("on_timeout_expired")

        if "TCTISPIHelper.on_start_timeout" in str(self.on_start_timeout):
            missing_implementation.append("on_start_timeout")

        if "TCTISPIHelper.on_sleep_ms" in str(self.on_sleep_ms):
            missing_implementation.append("on_sleep_ms")

        if len(missing_implementation) > 0:
            raise NotImplementedError(
                f"Subclasses must implement {','.join(missing_implementation)}"
            )

        _chkrc(lib.Tss2_Tcti_Spi_Helper_Init(ffi.NULL, size, self._callbacks))

        self._tcti_mem = ffi.new(f"uint8_t [{size[0]}]")
        self._opaque_tcti_ctx = ffi.cast("TSS2_TCTI_CONTEXT *", self._tcti_mem)

        try:
            self._clear_exceptions()
            _chkrc(
                lib.Tss2_Tcti_Spi_Helper_Init(
                    self._opaque_tcti_ctx, size, self._callbacks
                )
            )
        except Exception as e:
            e = self._get_current_exception(e)
            self._clear_exceptions()
            raise e

        super().__init__(self._opaque_tcti_ctx)

    @property
    def waitstate(self):
        """Gets the wait state property.

        Returns(bool):
            True if this TCTI implements wait states, false otherwise.
        """
        return self._with_wait_state

    @staticmethod
    def _cffi_cast(userdata):
        return ffi.from_handle(userdata)

    def on_sleep_ms(self, milliseconds: int) -> None:
        """Sleeps for a specified amount of time in millisecons.

        This callback is REQUIRED.
        No errors may occur across this boundary.

        Args:
            milliseconds(int): The time to sleep.
        """
        pass

    def on_start_timeout(self, milliseconds: int) -> None:
        """Called when a timeout is occurring with the sleep duration in millisecons.

        This callback is REQUIRED.
        No errors may occur across this boundary.

        Args:
            milliseconds(int): The time to sleep.
        """
        pass

    def on_timeout_expired(self) -> bool:
        """Called to determine if a timeout is expired.

        This callback is REQUIRED.
        No errors may occur across this boundary.
        """
        pass

    def on_spi_transfer(self, data_in: bytes) -> bytes:
        """Called to transfer data across the SPI bus.

        This callback is REQUIRED.
        No errors may occur across this boundary.

        Args:
            data_in(bytes): The data to send.

        Returns(bytes):
            The bytes to send.

        Raises:
            TSS2_Exception: if an error occurs and the RC is returned to the
                native TCTI.
        """

    def on_finalize(self) -> None:
        """Called when the TCTI is finalized.

        This callback is OPTIONAL.
        No errors may occur across this boundary.
        """
        pass

    def on_spi_acquire(self) -> None:
        """Called when the SPI bus needs to be acquired for wait states.

        This callback is REQUIRED for WAIT STATES.
        No errors may occur across this boundary.
        """
        pass

    def on_spi_release(self) -> None:
        """Called when the SPI bus needs to be released for wait states.

        This callback is REQUIRED for WAIT STATES.
        No errors may occur across this boundary.
        """
        pass
