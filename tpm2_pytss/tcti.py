from typing import Optional

from .binding import ESYSBinding
from .util.retry import retry_tcti_loop, retry_tcti_catch


class TCTIContextNotReentrant(Exception):
    """
    Raised when a connection has already been created
    """


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

    def __init__(self, parent, config: str, retry: int = 50):
        self.parent = parent
        self.config = config
        self.retry = retry
        # Context pointer and context pointer pointer
        self.ctxpp = None

    def __enter__(self):
        if self.ctxpp is not None:
            raise TCTIContextNotReentrant("Already entered")
        self.ctxpp = ESYSBinding.tcti_ctx_ptr_ptr()
        # Attempt TCTI connection
        for retry in retry_tcti_loop(max_tries=self.retry):
            with retry_tcti_catch(retry):
                ESYSBinding.Tss2_TctiLdr_Initialize_Ex(
                    self.NAME, self.config, self.ctxpp.ptr
                )
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.ctxpp = None

    @property
    def ctxp(self):
        return self.ctxpp.value


class TCTI:

    CONTEXT = TCTIContext

    def __call__(self, *, config: str, retry: Optional[int] = 50) -> "TCTIContext":
        return self.CONTEXT(self, config, retry=retry)

    @classmethod
    def _load(cls, name):
        """
        Attemps to load the .so for a tcti given its name. Returns a subclass of
        TCTI.
        """
        return type(
            "{}TCTI".format(name.title()),
            (cls,),
            {
                "NAME": name,
                "CONTEXT": type(
                    "{}TCTIContext".format(name.title()), (cls.CONTEXT,), {"NAME": name}
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
