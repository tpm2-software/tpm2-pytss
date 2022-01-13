# SPDX-License-Identifier: BSD-2

from math import ceil
from ..constants import TPM2_ALG, TPM2_ECC
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
    load_pem_public_key,
    load_der_public_key,
    load_ssh_public_key,
    load_ssh_private_key,
    Encoding,
    PublicFormat,
)
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import modes, Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
from typing import Tuple, Type
import secrets
import sys

_curvetable = (
    (TPM2_ECC.NIST_P192, ec.SECP192R1),
    (TPM2_ECC.NIST_P224, ec.SECP224R1),
    (TPM2_ECC.NIST_P256, ec.SECP256R1),
    (TPM2_ECC.NIST_P384, ec.SECP384R1),
    (TPM2_ECC.NIST_P521, ec.SECP521R1),
)

_digesttable = (
    (TPM2_ALG.SHA1, hashes.SHA1),
    (TPM2_ALG.SHA256, hashes.SHA256),
    (TPM2_ALG.SHA384, hashes.SHA384),
    (TPM2_ALG.SHA512, hashes.SHA512),
    (TPM2_ALG.SHA3_256, hashes.SHA3_256),
    (TPM2_ALG.SHA3_384, hashes.SHA3_384),
    (TPM2_ALG.SHA3_512, hashes.SHA3_512),
)

_algtable = (
    (TPM2_ALG.AES, AES),
    (TPM2_ALG.CFB, modes.CFB),
)


def _get_curveid(curve):
    for (algid, c) in _curvetable:
        if isinstance(curve, c):
            return algid
    return None


def _get_curve(curveid):
    for (algid, c) in _curvetable:
        if algid == curveid:
            return c
    return None


def _get_digest(digestid):
    for (algid, d) in _digesttable:
        if algid == digestid:
            return d
    return None


def _get_alg(alg):
    for (algid, a) in _algtable:
        if algid == alg:
            return a
    return None


def _int_to_buffer(i, b):
    s = ceil(i.bit_length() / 8)
    b.buffer = i.to_bytes(length=s, byteorder="big")


def key_from_encoding(data, password=None):
    try:
        cert = load_pem_x509_certificate(data, backend=default_backend())
        key = cert.public_key()
        return key
    except ValueError:
        pass
    try:
        key = load_pem_public_key(data, backend=default_backend())
        return key
    except ValueError:
        pass
    try:
        pkey = load_pem_private_key(data, password=password, backend=default_backend())
        key = pkey.public_key()
        return key
    except ValueError:
        pass
    try:
        key = load_ssh_public_key(data, backend=default_backend())
        return key
    except (ValueError, UnsupportedAlgorithm):
        pass
    try:
        cert = load_der_x509_certificate(data, backend=default_backend())
        key = cert.public_key()
        return key
    except ValueError:
        pass
    try:
        key = load_der_public_key(data, backend=default_backend())
        return key
    except ValueError:
        pass
    try:
        pkey = load_der_private_key(data, password=password, backend=default_backend())
        key = pkey.public_key()
        return key
    except ValueError:
        pass

    raise ValueError("Unsupported key format")


def _public_from_encoding(data, obj, password=None):
    key = key_from_encoding(data, password)
    nums = key.public_numbers()
    if isinstance(key, rsa.RSAPublicKey):
        obj.type = TPM2_ALG.RSA
        obj.parameters.rsaDetail.keyBits = key.key_size
        _int_to_buffer(nums.n, obj.unique.rsa)
        if nums.e != 65537:
            obj.parameters.rsaDetail.exponent = nums.e
        else:
            obj.parameters.rsaDetail.exponent = 0
    elif isinstance(key, ec.EllipticCurvePublicKey):
        obj.type = TPM2_ALG.ECC
        curveid = _get_curveid(key.curve)
        if curveid is None:
            raise ValueError(f"unsupported curve: {key.curve.name}")
        obj.parameters.eccDetail.curveID = curveid
        _int_to_buffer(nums.x, obj.unique.ecc.x)
        _int_to_buffer(nums.y, obj.unique.ecc.y)
    else:
        raise ValueError(f"unsupported key type: {key.__class__.__name__}")


def private_key_from_encoding(data, password=None):
    try:
        key = load_pem_private_key(data, password=password, backend=default_backend())
        return key
    except ValueError:
        pass
    try:
        key = load_ssh_private_key(data, password=password, backend=default_backend())
        return key
    except ValueError:
        pass
    try:
        key = load_der_private_key(data, password=password, backend=default_backend())
        return key
    except ValueError:
        pass

    raise ValueError("Unsupported key format")


def _private_from_encoding(data, obj, password=None):
    key = private_key_from_encoding(data, password)
    nums = key.private_numbers()
    if isinstance(key, rsa.RSAPrivateKey):
        obj.sensitiveType = TPM2_ALG.RSA
        _int_to_buffer(nums.p, obj.sensitive.rsa)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        obj.sensitiveType = TPM2_ALG.ECC
        _int_to_buffer(nums.private_value, obj.sensitive.ecc)
    else:
        raise ValueError(f"unsupported key type: {key.__class__.__name__}")


def public_to_key(obj):
    key = None
    if obj.type == TPM2_ALG.RSA:
        b = obj.unique.rsa.buffer
        n = int.from_bytes(b, byteorder="big")
        e = obj.parameters.rsaDetail.exponent
        if e == 0:
            e = 65537
        nums = rsa.RSAPublicNumbers(e, n)
        key = nums.public_key(backend=default_backend())
    elif obj.type == TPM2_ALG.ECC:
        curve = _get_curve(obj.parameters.eccDetail.curveID)
        if curve is None:
            raise ValueError(f"unsupported curve: {obj.parameters.eccDetail.curveID}")
        x = int.from_bytes(obj.unique.ecc.x, byteorder="big")
        y = int.from_bytes(obj.unique.ecc.y, byteorder="big")
        nums = ec.EllipticCurvePublicNumbers(x, y, curve())
        key = nums.public_key(backend=default_backend())
    else:
        raise ValueError(f"unsupported key type: {obj.type}")

    return key


class _MyRSAPrivateNumbers(rsa.RSAPrivateNumbers):
    def __init__(self, p: int, n: int, e: int, pubnums: rsa.RSAPublicNumbers):

        q = n // p

        d = _MyRSAPrivateNumbers._generate_d(p, q, e, n)

        dmp1 = rsa.rsa_crt_dmp1(d, p)
        dmq1 = rsa.rsa_crt_dmq1(d, q)
        iqmp = rsa.rsa_crt_iqmp(p, q)

        super().__init__(p, q, d, dmp1, dmq1, iqmp, pubnums)

    @staticmethod
    def _xgcd(a: int, b: int) -> Tuple[int, int, int]:
        """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            (q, a), b = divmod(b, a), a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return b, x0, y0

    #
    # The _modinv and _xgcd routines come from the link below. Minor modifications to add an underscore to the names as well
    # as to check the version of Python and use pow() for modular inverse (since 3.8).
    # were made. They are licensed under https://creativecommons.org/licenses/by-sa/3.0/
    # - https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm#Iterative_algorithm_3
    #
    @staticmethod
    def _modinv(a, m):

        if sys.version_info < (3, 8):
            g, x, y = _MyRSAPrivateNumbers._xgcd(a, m)
            if g != 1:
                raise Exception("modular inverse does not exist")
            else:
                return x % m
        else:
            return pow(a, -1, m)

    @staticmethod
    def _generate_d(p, q, e, n):

        # P most always be larger so we don't go negative
        if p < q:
            p, q = q, p

        phi = (p - 1) * (q - 1)
        d = _MyRSAPrivateNumbers._modinv(e, phi)

        return d


def private_to_key(private: "types.TPMT_SENSITIVE", public: "types.TPMT_PUBLIC"):
    key = None
    if private.sensitiveType == TPM2_ALG.RSA:

        p = int.from_bytes(bytes(private.sensitive.rsa), byteorder="big")
        n = int.from_bytes(bytes(public.unique.rsa), byteorder="big")
        e = (
            public.parameters.rsaDetail.exponent
            if public.parameters.rsaDetail.exponent != 0
            else 65537
        )

        key = _MyRSAPrivateNumbers(p, n, e, rsa.RSAPublicNumbers(e, n)).private_key(
            backend=default_backend()
        )
    elif private.sensitiveType == TPM2_ALG.ECC:

        curve = _get_curve(public.parameters.eccDetail.curveID)
        if curve is None:
            raise ValueError(
                f"unsupported curve: {public.parameters.eccDetail.curveID}"
            )

        p = int.from_bytes(bytes(private.sensitive.ecc), byteorder="big")
        x = int.from_bytes(bytes(public.unique.ecc.x), byteorder="big")
        y = int.from_bytes(bytes(public.unique.ecc.y), byteorder="big")

        key = ec.EllipticCurvePrivateNumbers(
            p, ec.EllipticCurvePublicNumbers(x, y, curve())
        ).private_key(backend=default_backend())
    else:
        raise ValueError(f"unsupported key type: {private.sensitiveType}")

    return key


def _public_to_pem(obj, encoding="pem"):
    encoding = encoding.lower()
    key = public_to_key(obj)
    if encoding == "pem":
        return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    elif encoding == "der":
        return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    elif encoding == "ssh":
        return key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    else:
        raise ValueError(f"unsupported encoding: {encoding}")


def _getname(obj):
    dt = _get_digest(obj.nameAlg)
    if dt is None:
        raise ValueError(f"unsupported digest algorithm: {obj.nameAlg}")
    d = hashes.Hash(dt(), backend=default_backend())
    mb = obj.marshal()
    d.update(mb)
    b = d.finalize()
    db = obj.nameAlg.to_bytes(length=2, byteorder="big")
    name = db + b
    return name


def _kdfa(hashAlg, key, label, contextU, contextV, bits):
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm: {hashAlg}")
    if bits % 8:
        raise ValueError(f"bad key length {bits}, not a multiple of 8")
    klen = int(bits / 8)
    context = contextU + contextV
    kdf = KBKDFHMAC(
        algorithm=halg(),
        mode=Mode.CounterMode,
        length=klen,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
        backend=default_backend(),
    )
    return kdf.derive(key)


def kdfe(hashAlg, z, use, partyuinfo, partyvinfo, bits):
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm: {hashAlg}")
    if bits % 8:
        raise ValueError(f"bad key length {bits}, not a multiple of 8")
    klen = int(bits / 8)
    otherinfo = use + partyuinfo + partyvinfo
    kdf = ConcatKDFHash(
        algorithm=halg(), length=klen, otherinfo=otherinfo, backend=default_backend()
    )
    return kdf.derive(z)


def _symdef_to_crypt(symdef):
    alg = _get_alg(symdef.algorithm)
    if alg is None:
        raise ValueError(f"unsupported symmetric algorithm {symdef.algorithm}")
    mode = _get_alg(symdef.mode.sym)
    if mode is None:
        raise ValueError(f"unsupported symmetric mode {symdef.mode.sym}")
    bits = symdef.keyBits.sym
    return (alg, mode, bits)


def _calculate_sym_unique(nameAlg, secret, seed):
    dt = _get_digest(nameAlg)
    if dt is None:
        raise ValueError(f"unsupported digest algorithm: {nameAlg}")
    d = hashes.Hash(dt(), backend=default_backend())
    d.update(seed)
    d.update(secret)
    return d.finalize()


def _get_digest_size(alg):
    dt = _get_digest(alg)
    if dt is None:
        raise ValueError(f"unsupported digest algorithm: {alg}")

    return dt.digest_size


def verify_signature_rsa(signature, key, data):
    dt = _get_digest(signature.signature.any.hashAlg)
    if dt is None:
        raise ValueError(
            f"unsupported digest algorithm: {signature.signature.rsapss.hash}"
        )
    mpad = None
    if signature.sigAlg == TPM2_ALG.RSASSA:
        pad = padding.PKCS1v15()
    elif signature.sigAlg == TPM2_ALG.RSAPSS:
        pad = padding.PSS(mgf=padding.MGF1(dt()), salt_length=dt.digest_size)
        mpad = padding.PSS(mgf=padding.MGF1(dt()), salt_length=padding.PSS.MAX_LENGTH)
    else:
        raise ValueError(f"unsupported RSA signature algorithm: {signature.sigAlg}")

    sig = bytes(signature.signature.rsapss.sig)
    try:
        key.verify(sig, data, pad, dt())
    except InvalidSignature:
        if mpad:
            key.verify(sig, data, mpad, dt())
        else:
            raise


def verify_signature_ecc(signature, key, data):
    dt = _get_digest(signature.signature.any.hashAlg)
    if dt is None:
        raise ValueError(
            f"unsupported digest algorithm: {signature.signature.ecdsa.hash}"
        )
    r = int.from_bytes(signature.signature.ecdsa.signatureR, byteorder="big")
    s = int.from_bytes(signature.signature.ecdsa.signatureS, byteorder="big")
    sig = encode_dss_signature(r, s)
    key.verify(sig, data, ec.ECDSA(dt()))


def verify_signature_hmac(signature, key, data):
    dt = _get_digest(signature.signature.hmac.hashAlg)
    if dt is None:
        raise ValueError(
            f"unsupported digest algorithm: {signature.signature.hmac.hashAlg}"
        )
    sh = hashes.Hash(dt(), backend=default_backend())
    sh.update(data)
    hdata = sh.finalize()
    sig = bytes(signature.signature.hmac)
    h = HMAC(key, dt(), backend=default_backend())
    h.update(hdata)
    h.verify(sig)


def _verify_signature(signature, key, data):
    if hasattr(key, "publicArea"):
        key = key.publicArea
    kt = getattr(key, "type", None)
    if kt in (TPM2_ALG.RSA, TPM2_ALG.ECC):
        key = public_to_key(key)
    if signature.sigAlg in (TPM2_ALG.RSASSA, TPM2_ALG.RSAPSS):
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError(
                f"bad key type for {signature.sigAlg}, expected RSA public key, got {key.__class__.__name__}"
            )
        verify_signature_rsa(signature, key, data)
    elif signature.sigAlg == TPM2_ALG.ECDSA:
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError(
                f"bad key type for {signature.sigAlg}, expected ECC public key, got {key.__class__.__name__}"
            )
        verify_signature_ecc(signature, key, data)
    elif signature.sigAlg == TPM2_ALG.HMAC:
        if not isinstance(key, bytes):
            raise ValueError(
                f"bad key type for {signature.sigAlg}, expected bytes, got {key.__class__.__name__}"
            )
        verify_signature_hmac(signature, key, data)
    else:
        raise ValueError(f"unsupported signature algorithm: {signature.sigAlg}")


def _generate_rsa_seed(
    key: rsa.RSAPublicKey, hashAlg: int, label: bytes
) -> Tuple[bytes, bytes]:
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm {hashAlg}")
    seed = secrets.token_bytes(halg.digest_size)
    mgf = padding.MGF1(halg())
    padd = padding.OAEP(mgf, halg(), label)
    enc_seed = key.encrypt(seed, padd)
    return (seed, enc_seed)


def _generate_ecc_seed(
    key: ec.EllipticCurvePublicKey, hashAlg: int, label: bytes
) -> Tuple[bytes, bytes]:
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm {hashAlg}")
    ekey = ec.generate_private_key(key.curve, default_backend())
    epubnum = ekey.public_key().public_numbers()
    plength = int(key.curve.key_size / 8)  # FIXME ceiling here
    exbytes = epubnum.x.to_bytes(plength, "big")
    eybytes = epubnum.y.to_bytes(plength, "big")
    # workaround marshal of TPMS_ECC_POINT
    secret = (
        len(exbytes).to_bytes(length=2, byteorder="big")
        + exbytes
        + len(eybytes).to_bytes(length=2, byteorder="big")
        + eybytes
    )
    shared_key = ekey.exchange(ec.ECDH(), key)
    pubnum = key.public_numbers()
    xbytes = pubnum.x.to_bytes(plength, "big")
    seed = kdfe(hashAlg, shared_key, label, exbytes, xbytes, halg.digest_size * 8)
    return (seed, secret)


def _generate_seed(public: "types.TPMT_PUBLIC", label: bytes) -> Tuple[bytes, bytes]:
    key = public_to_key(public)
    if public.type == TPM2_ALG.RSA:
        return _generate_rsa_seed(key, public.nameAlg, label)
    elif public.type == TPM2_ALG.ECC:
        return _generate_ecc_seed(key, public.nameAlg, label)
    else:
        raise ValueError(f"unsupported seed algorithm {public.type}")


def __rsa_secret_to_seed(key, hashAlg: int, label: bytes, outsymseed: bytes):
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm {hashAlg}")
    mgf = padding.MGF1(halg())
    padd = padding.OAEP(mgf, halg(), label)
    seed = key.decrypt(bytes(outsymseed), padd)
    return seed


def __ecc_secret_to_seed(
    key: ec.EllipticCurvePrivateKey, hashAlg: int, label: bytes, outsymseed: bytes
) -> Tuple[bytes, bytes]:
    halg = _get_digest(hashAlg)
    if halg is None:
        raise ValueError(f"unsupported digest algorithm {hashAlg}")

    # Get the peer public key (outsymseed)
    # workaround unmarshal of TPMS_ECC_POINT (we cant use types here do to cyclic deps
    xlen = int.from_bytes(outsymseed[0:2], byteorder="big")
    ylen = int.from_bytes(outsymseed[xlen + 2 : xlen + 4], byteorder="big")
    if xlen + ylen != len(outsymseed) - 4:
        raise ValueError(
            f"Expected TPMS_ECC_POINT to have two points of len {xlen + ylen}, got: {len(outsymseed)}"
        )

    exbytes = outsymseed[2 : 2 + xlen]
    eybytes = outsymseed[xlen + 4 : xlen + 4 + ylen]

    x = int.from_bytes(exbytes, byteorder="big")
    y = int.from_bytes(eybytes, byteorder="big")
    nums = ec.EllipticCurvePublicNumbers(x, y, key.curve)
    peer_public_key = nums.public_key(backend=default_backend())

    shared_key = key.exchange(ec.ECDH(), peer_public_key)

    pubnum = key.public_key().public_numbers()
    xbytes = pubnum.x.to_bytes(key.key_size // 8, "big")
    seed = kdfe(hashAlg, shared_key, label, exbytes, xbytes, halg.digest_size * 8)
    return seed


def _secret_to_seed(
    private: "types.TPMT_SENSITIVE",
    public: "types.TPMT_PUBLIC",
    label: bytes,
    outsymseed: bytes,
):
    key = private_to_key(private, public)
    if isinstance(key, rsa.RSAPrivateKey):
        return __rsa_secret_to_seed(key, public.nameAlg, label, outsymseed)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return __ecc_secret_to_seed(key, public.nameAlg, label, outsymseed)
    else:
        raise ValueError(f"unsupported seed algorithm {public.type}")


def _hmac(
    halg: hashes.HashAlgorithm, hmackey: bytes, enc_cred: bytes, name: bytes
) -> bytes:
    h = HMAC(hmackey, halg(), backend=default_backend())
    h.update(enc_cred)
    h.update(name)
    return h.finalize()


def _check_hmac(
    halg: hashes.HashAlgorithm,
    hmackey: bytes,
    enc_cred: bytes,
    name: bytes,
    expected: bytes,
):
    h = HMAC(hmackey, halg(), backend=default_backend())
    h.update(enc_cred)
    h.update(name)
    h.verify(expected)


def _encrypt(cipher: Type[AES], key: bytes, data: bytes) -> bytes:
    iv = len(key) * b"\x00"
    ci = cipher(key)
    ciph = Cipher(ci, modes.CFB(iv), backend=default_backend())
    encr = ciph.encryptor()
    encdata = encr.update(data) + encr.finalize()
    return encdata


def _decrypt(cipher: Type[AES], key: bytes, data: bytes) -> bytes:
    iv = len(key) * b"\x00"
    ci = cipher(key)
    ciph = Cipher(ci, modes.CFB(iv), backend=default_backend())
    decr = ciph.decryptor()
    plaintextdata = decr.update(data) + decr.finalize()
    return plaintextdata
