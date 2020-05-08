from typing import Optional

from .binding import ESYSBinding
from .util.retry import retry_tcti_loop, retry_tcti_catch


class TCTIContext:
    """
    >>> v = esys.TSS2_ABI_VERSION()
    >>> v.tssCreator = 1
    >>> v.tssFamily = 2
    >>> v.tssLevel = 1
    >>> v.tssVersion = 108
    >>> tcti = esys.TCTI.load("mssim")
    >>> with self.tcti(config=self.tcti_config) as tctx:
    ...     ctxp = esys.new_ctx_ptr()
    ...     esys.Esys_Initialize(ctxp, tctx.ctxp, v)
    """

    def __init__(self, parent, config: str, retry: int = 1):
        self.parent = parent
        self.config = config
        self.retry = retry
        # Context pointer and context pointer pointer
        self.ctxp = None
        self.ctxpp = None

    def __enter__(self):
        ctxpp = ESYSBinding.tcti_ctx_ptr_ptr()
        ctxpp.__enter__()
        # Attempt TCTI connection
        for retry in retry_tcti_loop(max_tries=self.retry):
            with retry_tcti_catch(retry):
                ESYSBinding.Tss2_TctiLdr_Initialize_Ex(
                    self.NAME, self.config, ctxpp.ptr
                )
        # Don't set property until after init succeeds to avoid memory leaks (gc
        # should cleanup if no other references exists when exception is thrown)
        self.ctxp = ctxpp.value
        self.ctxpp = ctxpp
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.ctxpp.__exit__(exc_type, exc_value, traceback)
        self.ctxpp = None
        self.ctxp = None


class TCTI:

    CONTEXT = TCTIContext

    def __call__(
        self, *, config: Optional[str] = None, retry: Optional[int] = 1
    ) -> "TCTIContext":
        return self.CONTEXT(self, config, retry)

    @classmethod
    def _load(cls, name):
        """
        Attemps to load the .so for a tcti given its name. Returns a subclass of
        TCTI.
        """
        return type(
            "{}TCTI".format(name.upper()),
            (cls,),
            {
                "NAME": name,
                "CONTEXT": type(
                    "{}TCTIContext".format(name.upper()), (cls.CONTEXT,), {"NAME": name}
                ),
            },
        )

    @classmethod
    def load(cls, name):
        """
        Attemps to load the .so for a tcti given its name. Returns the
        instantiation of a subclass of TCTI.
        """
        return cls._load(name)()
