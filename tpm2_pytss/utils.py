from .internal.crypto import (
    _kdfa,
    _get_digest,
    _symdef_to_crypt,
    _generate_seed,
    _encrypt,
    _hmac,
)
from .types import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Optional, Tuple

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

    enc_cred = _encrypt(cipher, symkey, credential.marshal())

    halg = _get_digest(public.nameAlg)
    hmackey = _kdfa(public.nameAlg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8)
    outerhmac = _hmac(halg, hmackey, enc_cred, name)
    hmacdata = TPM2B_DIGEST(buffer=outerhmac).marshal()

    credblob = TPM2B_ID_OBJECT(credential=hmacdata + enc_cred)
    secret = TPM2B_ENCRYPTED_SECRET(secret=enc_seed)
    return (credblob, secret)


def wrap(
    newparent: TPMT_PUBLIC,
    public: TPM2B_PUBLIC,
    sensitive: TPM2B_SENSITIVE,
    symkey: Optional[bytes] = None,
    symdef: Optional[TPMT_SYM_DEF_OBJECT] = None,
) -> Tuple[TPM2B_DATA, TPM2B_PRIVATE, TPM2B_ENCRYPTED_SECRET]:
    """Wraps key under a TPM key hierarchy

    Args:
        newparent (TPMT_PUBLIC): The public area of the parent
        public (TPM2B_PUBLIC): The public area of the key
        sensitive (TPM2B_SENSITIVE): The sensitive area of the key
        symkey (bytes or None): Symmetric key for inner encryption. Defaults to None. When None
        and symdef is defined a key will be generated based on the key size for symdef.
        symdef (TPMT_SYMDEF_OBJECT): Symmetric algorithm to be used for inner encryption. This should
        be set to aes128CFB since that is what the TPM supports:
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
        encsens = _encrypt(cipher, symkey, innerint + sensb)
        enckeyout.buffer = symkey
    else:
        encsens = sensb

    seed, outsymseed.secret = _generate_seed(newparent, b"DUPLICATE\x00")
    cipher, _, bits = _symdef_to_crypt(newparent.parameters.asymDetail.symmetric)
    outerkey = _kdfa(newparent.nameAlg, seed, b"STORAGE", name, b"", bits)
    dupsens = _encrypt(cipher, outerkey, encsens)

    halg = _get_digest(newparent.nameAlg)
    hmackey = _kdfa(
        newparent.nameAlg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8
    )
    outerhmac = _hmac(halg, hmackey, dupsens, name)
    hmacdata = TPM2B_DIGEST(buffer=outerhmac).marshal()

    duplicate = TPM2B_PRIVATE(buffer=hmacdata + dupsens)

    return (enckeyout, duplicate, outsymseed)
