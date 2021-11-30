# SPDX-License-Identifier: BSD-2

from ._libtpm2_pytss import lib, ffi
from .TCTI import TCTI
from .internal.utils import _chkrc


class TCTILdr(TCTI):
    def __init__(self, name=None, conf=None):

        self._ctx_pp = ffi.new("TSS2_TCTI_CONTEXT **")

        if name is None:
            name = ffi.NULL
        elif isinstance(name, str):
            name = name.encode()

        if conf is None:
            conf = ffi.NULL
        elif isinstance(conf, str):
            conf = conf.encode()

        if not isinstance(name, (bytes, type(ffi.NULL))):
            raise TypeError(f"name must be of type bytes, got {type(name)}")

        if not isinstance(conf, (bytes, type(ffi.NULL))):
            raise TypeError(f"conf must be of type bytes, got {type(name)}")

        _chkrc(lib.Tss2_TctiLdr_Initialize_Ex(name, conf, self._ctx_pp))
        super().__init__(self._ctx_pp[0])

        self._name = name.decode() if name else ""
        self._conf = conf.decode() if conf else ""

    def __enter__(self):
        return self

    def __exit__(self, _type, value, traceback):
        self.close()

    def close(self):
        lib.Tss2_TctiLdr_Finalize(self._ctx_pp)
        self._ctx = ffi.NULL

    @classmethod
    def parse(cls, tcti_name_conf: str):

        chunks = tcti_name_conf.split(":", 1)
        if len(chunks) > 2:
            raise RuntimeError(f"Expected only 1 : in TCTI str, got {len(chunks)}")
        name = chunks[0]
        conf = chunks[1] if len(chunks) == 2 else None

        return cls(name, conf)

    @property
    def name(self):
        return self._name

    @property
    def conf(self):
        return self._conf

    @property
    def name_conf(self):
        return f"{self.name}:{self.conf}" if self.conf else self.name

    def __str__(self):
        return self.name_conf
