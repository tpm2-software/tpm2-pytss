from .internal.crypto import (
    _kdfa,
    _get_digest,
    _symdef_to_crypt,
    _secret_to_seed,
    _generate_seed,
    _decrypt,
    _encrypt,
    _check_hmac,
    _hmac,
    _get_digest_size,
)
from .types import *
from .ESAPI import ESAPI
from .constants import (
    ESYS_TR,
    TPM2_CAP,
    TPM2_PT_NV,
    TPM2_ECC,
    TPM2_PT,
    TPM2_RH,
)
from .internal.templates import _ek
from .TSS2_Exception import TSS2_Exception
from cryptography.hazmat.primitives import constant_time as ct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Optional, Tuple, Callable, List

import secrets


def make_credential(
    public: TPM2B_PUBLIC, credential: bytes, name: TPM2B_NAME
) -> Tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET]:
    """Encrypts credential for use with activate_credential

    Args:
        public (TPMT_PUBLIC): The public area of the activation key
        credential (bytes): The credential to be encrypted
        name (bytes): The name of the key associated with the credential

    Returns:
        A tuple of (TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET)

    Raises:
        ValueError: If the public key type is not supported
    """
    if isinstance(public, TPM2B_PUBLIC):
        public = public.publicArea
    if isinstance(credential, bytes):
        credential = TPM2B_DIGEST(buffer=credential)
    if isinstance(name, TPM2B_SIMPLE_OBJECT):
        name = bytes(name)
    seed, enc_seed = _generate_seed(public, b"IDENTITY\x00")

    (cipher, symmode, symbits) = _symdef_to_crypt(
        public.parameters.asymDetail.symmetric
    )
    symkey = _kdfa(public.nameAlg, seed, b"STORAGE", name, b"", symbits)

    enc_cred = _encrypt(cipher, symmode, symkey, credential.marshal())

    halg = _get_digest(public.nameAlg)
    hmackey = _kdfa(public.nameAlg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8)
    outerhmac = _hmac(halg, hmackey, enc_cred, name)
    hmacdata = TPM2B_DIGEST(buffer=outerhmac).marshal()

    credblob = TPM2B_ID_OBJECT(credential=hmacdata + enc_cred)
    secret = TPM2B_ENCRYPTED_SECRET(secret=enc_seed)
    return (credblob, secret)


def credential_to_tools(
    id_object: Union[TPM2B_ID_OBJECT, bytes],
    encrypted_secret: Union[TPM2B_ENCRYPTED_SECRET, bytes],
) -> bytes:
    """
    Converts an encrypted credential and an encrypted secret to a format that TPM2-tools can handle.

    The output can be used in the credential-blob parameter of the tpm2_activatecredential command.

    Args:
        id_object: The encrypted credential area.
        encrypted_secret: The encrypted secret.

    Returns:
        A credential blob in byte form that can be used by TPM2-tools.
    """
    data = bytearray()

    # Add the header, consisting of the magic and the version.
    data.extend(int(0xBADCC0DE).to_bytes(4, "big") + int(1).to_bytes(4, "big"))

    if isinstance(id_object, bytes):
        id_object = TPM2B_ID_OBJECT(id_object)
    if isinstance(encrypted_secret, bytes):
        encrypted_secret = TPM2B_ENCRYPTED_SECRET(encrypted_secret)

    # Add the id object and encrypted secret.
    data.extend(id_object.marshal())
    data.extend(encrypted_secret.marshal())

    return bytes(data)


def tools_to_credential(
    credential_blob: bytes,
) -> Tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET]:
    """
    Convert a TPM2-tools compatible credential blob.

    Args:
        credential_blob: A TPM2-tools compatible credential blob.

    Returns:
        A tuple of (TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET)
    """
    magic = int.from_bytes(credential_blob[0:4], byteorder="big")
    if magic != 0xBADCC0DE:
        raise ValueError(f"bad magic, expected 0xBADCC0DE, got 0x{magic:X}")
    version = int.from_bytes(credential_blob[4:8], byteorder="big")
    if version != 1:
        raise ValueError(f"bad version, expected 1, got {version}")

    id_object, id_object_len = TPM2B_ID_OBJECT.unmarshal(credential_blob[8:])
    encrypted_secret, _ = TPM2B_ENCRYPTED_SECRET.unmarshal(
        credential_blob[8 + id_object_len :]
    )

    return id_object, encrypted_secret


def wrap(
    newparent: TPMT_PUBLIC,
    public: TPM2B_PUBLIC,
    sensitive: TPM2B_SENSITIVE,
    symkey: Optional[bytes] = None,
    symdef: Optional[TPMT_SYM_DEF_OBJECT] = None,
) -> Tuple[TPM2B_DATA, TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET]:
    """Wraps key under a TPM key hierarchy

    A key is wrapped following the Duplication protections of the TPM Architecture specification.
    The architecture specification is found in "Part 1: Architecture" at the following link:
    - https://trustedcomputinggroup.org/resource/tpm-library-specification/

    At the time of this writing, spec 1.59 was most recent and it was under section 23.3,
    titled "Duplication".

    Args:
        newparent (TPMT_PUBLIC): The public area of the parent
        public (TPM2B_PUBLIC): The public area of the key
        sensitive (TPM2B_SENSITIVE): The sensitive area of the key
        symkey (bytes or None):
          Symmetric key for inner encryption. Defaults to None.
          When None and symdef is defined a key will be generated based on the key size for symdef.
        symdef (TPMT_SYM_DEF_OBJECT or None):
          Symmetric algorithm to be used for inner encryption, defaults to None.
          If None no inner wrapping is performed, else this should be set to aes128CFB since that is
          what the TPM supports. To set to aes128cfb, do:
          ::

            TPMT_SYM_DEF(
              algorithm=TPM2_ALG.AES,
              keyBits=TPMU_SYM_KEY_BITS(sym=128),
              mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
            )

    Returns:
        A tuple of (TPM2B_DATA, TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET) which is the encryption key, the
        the wrapped duplicate and the encrypted seed.

    Raises:
        ValueError: If the public key type or symmetric algorithm are not supported
    """
    enckeyout = TPM2B_DATA()
    outsymseed = TPM2B_ENCRYPTED_SECRET()
    sensb = sensitive.marshal()
    name = bytes(public.get_name())
    if symdef and symdef.algorithm != TPM2_ALG.NULL:
        cipher, mode, bits = _symdef_to_crypt(symdef)
        if not symkey:
            klen = int(bits / 8)
            symkey = secrets.token_bytes(klen)
        halg = _get_digest(public.publicArea.nameAlg)
        h = hashes.Hash(halg(), backend=default_backend())
        h.update(sensb)
        h.update(name)
        innerint = TPM2B_DIGEST(buffer=h.finalize()).marshal()
        encsens = _encrypt(cipher, mode, symkey, innerint + sensb)
        enckeyout.buffer = symkey
    else:
        encsens = sensb

    seed, outsymseed.secret = _generate_seed(newparent, b"DUPLICATE\x00")
    cipher, mode, bits = _symdef_to_crypt(newparent.parameters.asymDetail.symmetric)
    outerkey = _kdfa(newparent.nameAlg, seed, b"STORAGE", name, b"", bits)
    dupsens = _encrypt(cipher, mode, outerkey, encsens)

    halg = _get_digest(newparent.nameAlg)
    hmackey = _kdfa(
        newparent.nameAlg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8
    )
    outerhmac = _hmac(halg, hmackey, dupsens, name)
    hmacdata = TPM2B_DIGEST(buffer=outerhmac).marshal()

    duplicate = TPM2B_PRIVATE(buffer=hmacdata + dupsens)

    return (enckeyout, duplicate, outsymseed)


def unwrap(
    newparentpub: TPMT_PUBLIC,
    newparentpriv: TPMT_SENSITIVE,
    public: TPM2B_PUBLIC,
    duplicate: TPM2B_PRIVATE,
    outsymseed: TPM2B_ENCRYPTED_SECRET,
    symkey: Optional[bytes] = None,
    symdef: Optional[TPMT_SYM_DEF_OBJECT] = None,
) -> TPM2B_SENSITIVE:
    """unwraps a key under a TPM key hierarchy. In essence, export key from TPM.

    This is the inverse function to the wrap() routine. This is usually performed by the TPM when importing
    objects, however, if an object is duplicated under a new parent where one has both the public and private
    keys, the object can be unwrapped.

    Args:
        newparentpub (TPMT_PUBLIC): The public area of the parent the key was duplicated/wrapped under.
        newparentpriv (TPMT_SENSITIVE): The private key of the parent the key was duplicated/wrapped under.
        public (TPM2B_PUBLIC): The public area of the key to be unwrapped.
        duplicate (TPM2B_PRIVATE): The private or wrapped key to be unwrapped.
        outsymseed (TPM2B_ENCRYPTED_SECRET): The output symmetric seed from a wrap or duplicate call.
        symkey (bytes or None):
          Symmetric key for inner encryption. Defaults to None.
          When None and symdef is defined a key will be generated based on the key size for symdef.
        symdef (TPMT_SYM_DEF_OBJECT or None):
          Symmetric algorithm to be used for inner encryption, defaults to None.
          If None no inner wrapping is performed, else this should be set to aes128CFB since that is what
          the TPM supports. To set to aes128cfb, do:
          ::

            TPMT_SYM_DEF(
              algorithm=TPM2_ALG.AES,
              keyBits=TPMU_SYM_KEY_BITS(sym=128),
              mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
            )

    Returns:
        A TPM2B_SENSITIVE which contains the raw key material.

    Raises:
        ValueError: If the public key type or symmetric algorithm are not supported
    """
    halg = _get_digest(newparentpub.nameAlg)

    seed = _secret_to_seed(newparentpriv, newparentpub, b"DUPLICATE\x00", outsymseed)
    hmackey = _kdfa(
        newparentpub.nameAlg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8
    )

    buffer = bytes(duplicate)

    hmacdata, offset = TPM2B_DIGEST.unmarshal(buffer)
    outerhmac = bytes(hmacdata)

    dupsens = buffer[offset:]
    name = bytes(public.get_name())
    _check_hmac(halg, hmackey, dupsens, name, outerhmac)

    cipher, mode, bits = _symdef_to_crypt(newparentpub.parameters.asymDetail.symmetric)
    outerkey = _kdfa(newparentpub.nameAlg, seed, b"STORAGE", name, b"", bits)

    sensb = _decrypt(cipher, mode, outerkey, dupsens)

    if symdef and symdef.algorithm != TPM2_ALG.NULL:
        if not symkey:
            raise RuntimeError(
                "Expected symkey when symdef is not None or Tsymdef.algorithm is not TPM2_ALG.NULL"
            )

        cipher, mode, bits = _symdef_to_crypt(symdef)
        halg = _get_digest(public.publicArea.nameAlg)

        # unwrap the inner encryption which is the integrity + TPM2B_SENSITIVE
        innerint_and_decsens = _decrypt(cipher, mode, symkey, sensb)
        innerint, offset = TPM2B_DIGEST.unmarshal(innerint_and_decsens)
        innerint = bytes(innerint)
        decsensb = innerint_and_decsens[offset:]

        h = hashes.Hash(halg(), backend=default_backend())
        h.update(decsensb)
        h.update(name)
        integrity = h.finalize()

        if not ct.bytes_eq(integrity, innerint):
            raise RuntimeError("Expected inner integrity to match")

        decsens = decsensb
    else:
        decsens = sensb

    s, l = TPM2B_SENSITIVE.unmarshal(decsens)
    if len(decsens) != l:
        raise RuntimeError(
            f"Expected the sensitive buffer to be size {l}, got: {len(decsens)}"
        )

    return s


class NoSuchIndex(Exception):
    """NV index is not defined exception

    Args:
        index (int): The NV index requested
    """

    def __init__(self, index):
        self.index = index

    def __str__(self):
        return f"NV index 0x{index:08x} does not exist"


class NVReadEK:
    """NV read callback to be used with create_ek_template

    Args:
        ectx (ESAPI): The ESAPI context for reading from NV areas
        auth_handle (ESYS_TR): Handle indicating the source of the authorization. Defaults to the index being read.
        session1 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.PASSWORD.
        session2 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
        session3 (ESYS_TR): A session for securing the TPM command (optional). Defaults to ESYS_TR.NONE.
    """

    def __init__(
        self,
        ectx: ESAPI,
        auth_handle: ESYS_TR = None,
        session1: ESYS_TR = ESYS_TR.PASSWORD,
        session2: ESYS_TR = ESYS_TR.NONE,
        session3: ESYS_TR = ESYS_TR.NONE,
    ):
        self._ectx = ectx
        self._auth_handle = auth_handle
        self._session1 = session1
        self._session2 = session2
        self._session3 = session3
        self._buffer_max = 512

        more = True
        while more:
            more, data = self._ectx.get_capability(
                TPM2_CAP.TPM_PROPERTIES,
                TPM2_PT.FIXED,
                4096,
                session1=session2,
                session2=session3,
            )
            props = data.data.tpmProperties
            for p in props:
                if p.property == TPM2_PT_NV.BUFFER_MAX:
                    self._buffer_max = p.value
                    more = False
                    break

    def __call__(self, index: Union[int, TPM2_RH]) -> bytes:
        try:
            nvh = self._ectx.tr_from_tpmpublic(
                index, session1=self._session2, session2=self._session3
            )
        except TSS2_Exception as e:
            if e.rc == 0x18B:
                raise NoSuchIndex(index)
            else:
                raise e
        nvpub, _ = self._ectx.nv_read_public(
            nvh, session1=self._session2, session2=self._session3
        )
        nvdata = b""
        left = nvpub.nvPublic.dataSize
        while left > 0:
            off = nvpub.nvPublic.dataSize - left
            size = self._buffer_max if left > self._buffer_max else left
            data = self._ectx.nv_read(
                nvh,
                size,
                off,
                auth_handle=self._auth_handle,
                session1=self._session1,
                session2=self._session2,
                session3=self._session3,
            )
            nvdata = nvdata + bytes(data)
            left = left - len(data)

        return nvdata


def create_ek_template(
    ektype: str, nv_read_cb: Callable[[Union[int, TPM2_RH]], bytes]
) -> Tuple[bytes, TPM2B_PUBLIC]:
    """Creates an Endorsenment Key template which when created matches the EK certificate

    The template is created according to TCG EK Credential Profile For TPM Family 2.0:
    - https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/

    Args:
        ektype (str): The endoresment key type.
        nv_read_cb (Callable[Union[int, TPM2_RH]]): The callback to use for reading NV areas.

    Note:
        nv_read_cb MUST raise a NoSuchIndex exception if the NV index isn't defined.

    Returns:
        A tuple of the certificate (can be None) and the template as a TPM2B_PUBLIC instance

    Raises:
        ValueError: If ektype is unknown or if a high range certificate is requested but not found.
    """

    en = ektype.replace("-", "_")
    if not hasattr(_ek, en):
        raise ValueError(f"unknown EK type {ektype}")
    (cert_index, template) = getattr(_ek, en)

    nonce_index = None
    if ektype in ("EK-RSA2048", "EK-ECC256"):
        nonce_index = cert_index + 1
        template_index = cert_index + 2
    else:
        template_index = cert_index + 1

    cert = None
    try:
        cert = nv_read_cb(cert_index)
    except NoSuchIndex:
        if ektype not in ("EK-RSA2048", "EK-ECC256"):
            raise ValueError(f"no certificate found for {ektype}")

    try:
        templb = nv_read_cb(template_index)
        tt, _ = TPMT_PUBLIC.unmarshal(templb)
        template = TPM2B_PUBLIC(publicArea=tt)
    except NoSuchIndex:
        # The TPM is not required to have these Indices, but we must try
        # Avoids a race on checking for NV and then reading if a delete
        # comes in
        pass

    nonce = None
    if nonce_index:
        try:
            nonce = nv_read_cb(nonce_index)
        except NoSuchIndex:
            # The TPM is not required to have these Indices, but we must try
            # Avoids a race on checking for NV and then reading if a delete
            # comes in
            pass

    if nonce and template.publicArea.type == TPM2_ALG.RSA:
        template.publicArea.unique.rsa = nonce + ((256 - len(nonce)) * b"\x00")
    elif (
        nonce
        and template.publicArea.type == TPM2_ALG.ECC
        and template.publicArea.parameters.eccDetail.curveID == TPM2_ECC.NIST_P256
    ):
        template.publicArea.unique.ecc.x = nonce + ((32 - len(nonce)) * b"\x00")
        template.publicArea.unique.ecc.y = b"\x00" * 32

    return cert, template


def unmarshal_tools_pcr_values(
    buf: bytes, selections: TPML_PCR_SELECTION
) -> Tuple[int, List[bytes]]:
    """Unmarshal PCR digests from tpm2_quote using the values format.

    Args:
        buf (bytes): content of tpm2_quote PCR output.
        selections (TPML_PCR_SELECTION): The selected PCRs.

    Returns:
        A tuple of the number of bytes consumed from buf and a list of digests.
    """
    trs = list()
    for sel in selections:
        digsize = _get_digest_size(sel.hash)
        pb = bytes(reversed(bytes(sel.pcrSelect)))
        pi = int.from_bytes(pb, "big")
        for i in range(0, sel.sizeofSelect * 8):
            if pi & (1 << i):
                trs.append(digsize)

    n = 0
    digs = list()
    for s in trs:
        dig = buf[:s]
        n += s
        digs.append(dig)
        buf = buf[s:]

    return n, digs
