from .crypto import (
    kdfa,
    kdfe,
    public_to_key,
    _get_digest,
    symdef_to_crypt,
)
from .types import *
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    generate_private_key,
)
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import modes, Cipher
from cryptography.hazmat.backends import default_backend
import secrets


def generate_rsa_seed(key, hashAlg, label):
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm {hashAlg}")
    seed = secrets.token_bytes(halg.digest_size)
    mgf = padding.MGF1(halg())
    padd = padding.OAEP(mgf, halg(), label)
    enc_seed = key.encrypt(seed, padd)
    return (seed, enc_seed)


def generate_ecc_seed(key, hashAlg, label):
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm {hashAlg}")
    ekey = generate_private_key(key.curve, default_backend())
    epubnum = ekey.public_key().public_numbers()
    plength = int(key.curve.key_size / 8)  # FIXME ceiling here
    exbytes = epubnum.x.to_bytes(plength, "big")
    eybytes = epubnum.y.to_bytes(plength, "big")
    epoint = TPMS_ECC_POINT(
        x=TPM2B_ECC_PARAMETER(buffer=exbytes), y=TPM2B_ECC_PARAMETER(buffer=eybytes)
    )
    secret = epoint.Marshal()
    shared_key = ekey.exchange(ECDH(), key)
    pubnum = key.public_numbers()
    xbytes = pubnum.x.to_bytes(plength, "big")
    seed = kdfe(hashAlg, shared_key, label, exbytes, xbytes, halg.digest_size * 8)
    return (seed, secret)


def generate_seed(public, label):
    key = public_to_key(public)
    if public.type == TPM2_ALG.RSA:
        return generate_rsa_seed(key, public.nameAlg, label)
    elif public.type == TPM2_ALG.ECC:
        return generate_ecc_seed(key, public.nameAlg, label)
    else:
        raise ValueError(f"unsupported seed algorithm {public.type}")


def hmac(halg, hmackey, enc_cred, name):
    h = HMAC(hmackey, halg(), backend=default_backend())
    h.update(enc_cred)
    h.update(name)
    return h.finalize()


def encrypt(cipher, key, data):
    iv = len(key) * b"\x00"
    ci = cipher(key)
    ciph = Cipher(ci, modes.CFB(iv), backend=default_backend())
    encr = ciph.encryptor()
    encdata = encr.update(data) + encr.finalize()
    return encdata


def MakeCredential(public, credential, name):
    if isinstance(public, TPM2B_PUBLIC):
        public = public.publicArea
    if isinstance(credential, bytes):
        credential = TPM2B_DIGEST(buffer=credential)
    if isinstance(name, TPM2B_SIMPLE_OBJECT):
        name = bytes(name)
    seed, enc_seed = generate_seed(public, b"IDENTITY\x00")

    (cipher, symmode, symbits) = symdef_to_crypt(public.parameters.asymDetail.symmetric)
    symkey = kdfa(public.nameAlg, seed, b"STORAGE", name, b"", symbits)

    enc_cred = encrypt(cipher, symkey, credential.Marshal())

    halg = _get_digest(public.nameAlg)
    hmackey = kdfa(public.nameAlg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8)
    outerhmac = hmac(halg, hmackey, enc_cred, name)
    hmacdata = TPM2B_DIGEST(buffer=outerhmac).Marshal()

    credblob = TPM2B_ID_OBJECT(credential=hmacdata + enc_cred)
    secret = TPM2B_ENCRYPTED_SECRET(secret=enc_seed)
    return (credblob, secret)
