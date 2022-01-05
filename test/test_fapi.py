#!/usr/bin/python3 -u
# SPDX-License-Identifier: BSD-2
import random
import string
import sys

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PSS

from tpm2_pytss import *

from tpm2_pytss.internal.utils import is_bug_fixed

from .TSS2_BaseTest import TpmSimulator, TSS2_BaseTest

pytestmark = pytest.mark.skipif(
    "tpm2_pytss.FAPI" not in sys.modules, reason="FAPI Not Detected"
)


@pytest.fixture(scope="module")
def simulator():
    tpm = TpmSimulator.getSimulator()
    tpm.start()
    yield tpm
    tpm.close()


@pytest.fixture(scope="class")
def fapi_config_ecc(simulator):
    with FAPIConfig(
        temp_dirs=True,
        tcti=simulator.tcti_name_conf,
        ek_cert_less="yes",
        profile_name="P_ECCP256SHA256",
    ) as fapi_config:
        yield fapi_config


@pytest.fixture(scope="class")
def fapi_config_rsa(simulator):
    with FAPIConfig(
        temp_dirs=True,
        tcti=simulator.tcti_name_conf,
        ek_cert_less="yes",
        profile_name="P_RSA2048SHA256",
    ) as fapi_config:
        yield fapi_config


@pytest.fixture(scope="class")
def fapi_ecc(fapi_config_ecc):
    with FAPI() as fapi:
        fapi.provision(is_provisioned_ok=False)
        yield fapi
        fapi.delete("/")


@pytest.fixture(scope="class")
def fapi_rsa(fapi_config_rsa):
    with FAPI() as fapi:
        fapi.provision(is_provisioned_ok=False)
        yield fapi
        fapi.delete("/")


def random_uid() -> str:
    """Generate a random id which can be used e.g. for unique key names."""
    return "".join(random.choices(string.digits, k=10))


def sha256(data: bytes) -> bytes:
    """Calculate the SHA256 digest of given data."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


# TODO unprovisioned tests


@pytest.fixture(scope="class")
def init_fapi_ecc(request, fapi_ecc):
    request.cls.fapi = fapi_ecc
    request.cls.profile_name = request.cls.fapi.config.profile_name
    yield request.cls.fapi


@pytest.fixture(scope="class")
def init_fapi_rsa(request, fapi_rsa):
    request.cls.fapi = fapi_rsa
    request.cls.profile_name = request.cls.fapi.config.profile_name
    yield request.cls.fapi


class Common:
    @pytest.fixture
    def esys(self):
        with ESAPI(tcti=self.fapi.tcti) as esys:
            yield esys

    @pytest.fixture
    def cryptography_key(self):
        key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        key_public_pem = (
            key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        return key, key_public_pem

    @pytest.fixture
    def sign_key(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(path=key_path, type_="sign, exportable")
        yield key_path
        self.fapi.delete(path=key_path)

    @pytest.fixture
    def decrypt_key(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(path=key_path, type_="decrypt")
        yield key_path
        self.fapi.delete(path=key_path)

    @pytest.fixture
    def seal(self):
        profile_name = self.fapi.config.profile_name
        seal_path = f"/{profile_name}/HS/SRK/seal_{random_uid()}"
        seal_data = random_uid().encode()
        self.fapi.create_seal(path=seal_path, data=seal_data)
        yield seal_path, seal_data
        self.fapi.delete(path=seal_path)

    @pytest.fixture
    def ext_key(self, cryptography_key):
        key, key_public_pem = cryptography_key
        key_path = f"/ext/key_{random_uid()}"
        self.fapi.import_object(path=key_path, import_data=key_public_pem)
        yield key_path, key
        self.fapi.delete(path=key_path)

    @pytest.fixture
    def nv_ordinary(self):
        nv_path = f"/nv/Owner/nv_{random_uid()}"  # TODO Owner should be case insensitive (fix upstream)?
        self.fapi.create_nv(path=nv_path, size=10)
        yield nv_path
        self.fapi.delete(path=nv_path)

    @pytest.fixture
    def nv_increment(self):
        nv_path = f"/nv/Owner/nv_{random_uid()}"
        self.fapi.create_nv(path=nv_path, size=10, type_="counter")
        yield nv_path
        self.fapi.delete(path=nv_path)

    @pytest.fixture
    def nv_pcr(self):
        nv_path = f"/nv/Owner/nv_{random_uid()}"
        self.fapi.create_nv(path=nv_path, size=32, type_="pcr")
        yield nv_path
        self.fapi.delete(path=nv_path)

    @pytest.fixture
    def nv_bitfield(self):
        nv_path = f"/nv/Owner/nv_{random_uid()}"
        self.fapi.create_nv(path=nv_path, size=32, type_="bitfield")
        yield nv_path
        self.fapi.delete(path=nv_path)

    def test_provision_ok(self):
        provisioned = self.fapi.provision()
        assert provisioned is False

    def test_provision_fail(self):
        with pytest.raises(TSS2_Exception):
            self.fapi.provision(is_provisioned_ok=False)

    def test_get_random(self):
        random_bytes = self.fapi.get_random(42)
        assert type(random_bytes) == bytes
        assert len(random_bytes) == 42

    def test_get_random_zero(self):
        random_bytes = self.fapi.get_random(0)
        assert type(random_bytes) == bytes
        assert len(random_bytes) == 0

    def test_get_random_large(self):
        with pytest.raises(OverflowError):
            self.fapi.get_random(0xFFFFFFFFFFFFFFFF + 1)

    def test_get_random_negative(self):
        with pytest.raises(OverflowError):
            self.fapi.get_random(-1)

    def test_get_info(self):
        info = self.fapi.get_info()
        assert type(info) is str
        json.loads(info)
        assert "capabilities" in info

    def test_list(self):
        profile_name = self.fapi.config.profile_name
        path_list = self.fapi.list()
        assert type(path_list) is list
        assert len(path_list) > 0
        assert type(path_list[0]) is str
        assert f"/{profile_name}/HS" in path_list

    def test_list_search_path(self):
        profile_name = self.fapi.config.profile_name
        search_path = f"/{profile_name}/HE"
        path_list = self.fapi.list(search_path)
        assert type(path_list) is list
        assert len(path_list) > 0
        assert type(path_list[0]) is str
        assert all(path.startswith(search_path) for path in path_list)

    def test_list_bad_search_path(self):
        with pytest.raises(TSS2_Exception):
            self.fapi.list("/nonexistent")

    def test_create_key(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/key_{random_uid()}"
        created = self.fapi.create_key(path=key_path)
        assert created is True
        assert key_path in self.fapi.list()

    def test_create_key_double_ok(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/key_{random_uid()}"
        created = self.fapi.create_key(path=key_path)
        assert created is True
        assert key_path in self.fapi.list()

        created = self.fapi.create_key(path=key_path, exists_ok=True)
        assert created is False

    def test_create_key_double_fail(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/key_{random_uid()}"
        created = self.fapi.create_key(path=key_path)
        assert created is True
        assert key_path in self.fapi.list()

        with pytest.raises(TSS2_Exception):
            self.fapi.create_key(path=key_path)

    def test_get_esys_blob_contextload(self, esys, sign_key):
        blob_data, blob_type = self.fapi.get_esys_blob(path=sign_key)
        assert blob_type == FAPI_ESYSBLOB.CONTEXTLOAD
        esys_handle = esys.load_blob(blob_data, blob_type)
        esys.read_public(esys_handle)
        esys.flush_context(esys_handle)

    def test_get_esys_blob_bad(self, esys):
        with pytest.raises(ValueError) as e:
            esys.load_blob(None, 1234)
        assert (
            str(e.value)
            == "Expected type_ to be FAPI_ESYSBLOB.CONTEXTLOAD or FAPI_ESYSBLOB.DESERIALIZE, got 1234"
        )

    def test_get_esys_blob_deserialize(self, esys, nv_ordinary):
        blob_data, blob_type = self.fapi.get_esys_blob(path=nv_ordinary)
        assert blob_type == FAPI_ESYSBLOB.DESERIALIZE
        esys_handle = esys.load_blob(blob_data, blob_type)
        esys.nv_read_public(esys_handle)

    def test_verify(self, ext_key):
        # create signature externally
        key_path, key = ext_key
        message = b"Hello World"
        signature = key.sign(message, ec.ECDSA(hashes.SHA256()))

        # verify signature via fapi
        self.fapi.verify_signature(key_path, sha256(message), signature)

    def test_verify_fail(self, ext_key):
        key_path, key = ext_key
        with pytest.raises(TSS2_Exception):
            self.fapi.verify_signature(
                key_path, digest=b"A" * 32, signature=b"bad signature"
            )

    # TODO test encrypt with RSA profile. Needs to be provisioned separately.

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2"), reason="tpm2-tss bug, see #2028"
    )
    def test_import_key_double_ok(self, cryptography_key):
        key, key_public_pem = cryptography_key
        key_path = f"/ext/key_{random_uid()}"
        imported = self.fapi.import_object(path=key_path, import_data=key_public_pem)
        assert imported is True
        assert key_path in self.fapi.list()
        imported = self.fapi.import_object(
            path=key_path, import_data=key_public_pem, exists_ok=True
        )
        assert imported is False

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2"), reason="tpm2-tss bug, see #2028"
    )
    def test_import_key_double_fail(self, cryptography_key):
        key, key_public_pem = cryptography_key
        key_path = f"/ext/key_{random_uid()}"
        imported = self.fapi.import_object(path=key_path, import_data=key_public_pem)
        assert imported is True
        assert key_path in self.fapi.list()
        with pytest.raises(TSS2_Exception):
            self.fapi.import_object(path=key_path, import_data=key_public_pem)

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2"), reason="tpm2-tss bug, see #2028"
    )
    def test_import_policy_double_ok(self):
        policy = """
{
    "description":"Description of this policy",
    "policy":[{"type": "POLICYAUTHVALUE"}]
}
"""
        policy_path = f"/policy/policy_{random_uid()}"
        imported = self.fapi.import_object(path=policy_path, import_data=policy)
        assert imported is True
        assert policy_path in self.fapi.list()
        imported = self.fapi.import_object(
            path=policy_path, import_data=policy, exists_ok=True
        )
        assert imported is False

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2"), reason="tpm2-tss bug, see #2028"
    )
    def test_import_policy_double_fail(self):
        policy = """
{
    "description":"Description of this policy",
    "policy":[{"type": "POLICYAUTHVALUE"}]
}
"""
        policy_path = f"/policy/policy_{random_uid()}"
        imported = self.fapi.import_object(path=policy_path, import_data=policy)
        assert imported is True
        assert policy_path in self.fapi.list()
        with pytest.raises(TSS2_Exception):
            self.fapi.import_object(path=policy_path, import_data=policy)

    def test_import_exported_key(self, sign_key):
        exported_data = self.fapi.export_key(path=sign_key)
        profile_name = self.fapi.config.profile_name
        new_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.import_object(path=new_path, import_data=exported_data)

    def test_export_imported_policy(self):
        policy = """
        {
            "description":"Description of this policy",
            "policy":[{"type": "POLICYAUTHVALUE"}]
        }
        """
        policy_path = f"/policy/policy_{random_uid()}"
        self.fapi.import_object(path=policy_path, import_data=policy)

        exported_policy = self.fapi.export_policy(path=policy_path)
        assert type(exported_policy) == str
        assert "Description of this policy" in exported_policy

    def test_create_seal(self):
        profile_name = self.fapi.config.profile_name
        seal_path = f"/{profile_name}/HS/SRK/seal_{random_uid()}"
        seal_data = "Hello World"
        created = self.fapi.create_seal(path=seal_path, data=seal_data)
        assert created is True
        assert seal_path in self.fapi.list()

    def test_create_seal_double_ok(self):
        profile_name = self.fapi.config.profile_name
        seal_path = f"/{profile_name}/HS/SRK/seal_{random_uid()}"
        seal_data = "Hello World"
        created = self.fapi.create_seal(path=seal_path, data=seal_data)
        assert created is True
        assert seal_path in self.fapi.list()

        created = self.fapi.create_seal(path=seal_path, data=seal_data, exists_ok=True)
        assert created is False

    def test_create_seal_double_fail(self):
        profile_name = self.fapi.config.profile_name
        seal_path = f"/{profile_name}/HS/SRK/seal_{random_uid()}"
        seal_data = "Hello World"
        created = self.fapi.create_seal(path=seal_path, data=seal_data)
        assert created is True
        assert seal_path in self.fapi.list()

        with pytest.raises(TSS2_Exception):
            self.fapi.create_seal(path=seal_path, data=seal_data)

    def test_create_seal_random(self):
        profile_name = self.fapi.config.profile_name
        seal_path = f"/{profile_name}/HS/SRK/seal_{random_uid()}"
        seal_len = 12
        created = self.fapi.create_seal(path=seal_path, size=seal_len)
        assert created is True
        assert seal_path in self.fapi.list()

        unseal_data = self.fapi.unseal(path=seal_path)
        assert type(unseal_data) is bytes
        assert len(unseal_data) == seal_len

    def test_create_seal_both_data_and_size_fail(self):
        profile_name = self.fapi.config.profile_name
        seal_path = f"/{profile_name}/HS/SRK/seal_{random_uid()}"
        with pytest.raises(ValueError):
            self.fapi.create_seal(path=seal_path, data="Hello World", size=11)

    def test_create_seal_neither_data_nor_size_fail(self):
        profile_name = self.fapi.config.profile_name
        seal_path = f"/{profile_name}/HS/SRK/seal_{random_uid()}"
        with pytest.raises(ValueError):
            self.fapi.create_seal(path=seal_path)

    def test_unseal(self, seal):
        seal_path, seal_data = seal
        unseal_data = self.fapi.unseal(path=seal_path)
        assert type(unseal_data) is bytes
        assert seal_data == unseal_data

    def test_quote_verify(self, sign_key):
        info, signature, pcr_log, certificate = self.fapi.quote(
            path=sign_key, pcrs=[7, 9]
        )
        info_json = json.loads(info)
        assert info_json["attest"]["type"] == "ATTEST_QUOTE"
        assert type(signature) is bytes
        pcr_log_json = json.loads(pcr_log)
        assert pcr_log_json == []
        assert certificate == ""

        # TODO verify via openssl
        # exported_data = self.fapi.export_key(path=sign_key)
        # sign_key_public_pem = json.loads(exported_data)["pem_ext_public"].encode()
        # public_key = serialization.load_pem_public_key(sign_key_public_pem)
        # message = b"TODO"
        # public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

        # signature via fapi
        self.fapi.verify_quote(path=sign_key, signature=signature, quote_info=info)

    def test_export_key(self, sign_key):
        exported_data = self.fapi.export_key(path=sign_key)
        assert type(exported_data) is str
        json.loads(exported_data)

    def test_delete_key(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/key_{random_uid()}"
        self.fapi.create_key(path=key_path)
        assert key_path in self.fapi.list()

        self.fapi.delete(path=key_path)
        assert key_path not in self.fapi.list()

    def test_set_get_description(self, sign_key):
        description = "Nobody expects the Spanish Inquisition!"
        self.fapi.set_description(path=sign_key, description=description)
        returned_description = self.fapi.get_description(path=sign_key)
        assert description == returned_description

    def test_get_empty_description(self, sign_key):
        description = self.fapi.get_description(path=sign_key)
        assert description == ""

    def test_set_get_app_data(self, sign_key):
        app_data = b"\x00\xDE\xCA\xFB\xAD\x00"
        self.fapi.set_app_data(path=sign_key, app_data=app_data)
        returned_app_data = self.fapi.get_app_data(path=sign_key)
        assert app_data == returned_app_data

    def test_get_no_app_data(self, sign_key):
        app_data = self.fapi.get_app_data(path=sign_key)
        assert app_data is None

    def test_set_get_certificate(self, sign_key):
        certificate = "<PEM-encoded certificate (but FAPI does not really check)>"
        self.fapi.set_certificate(path=sign_key, certificate=certificate)
        returned_certificate = self.fapi.get_certificate(path=sign_key)
        assert certificate == returned_certificate

    def test_get_empty_certificate(self, sign_key):
        certificate = self.fapi.get_certificate(path=sign_key)
        assert certificate == ""

    def test_get_empty_platform_certificates_ok(self):
        certificates = self.fapi.get_platform_certificates(no_cert_ok=True)
        assert certificates == b""

    def test_get_empty_platform_certificates_fail(self):
        with pytest.raises(TSS2_Exception):
            self.fapi.get_platform_certificates()

    def test_pcr_read(self):
        value, log = self.fapi.pcr_read(7)
        assert value == b"\0" * 32
        assert log == "[\n]"

    def test_pcr_extend_read(self):
        index = 16
        value_old, _ = self.fapi.pcr_read(index)

        data = b"\x11" * 100
        log = '{"test":"myfile"}'
        self.fapi.pcr_extend(index, data, log)

        returned_value, returned_log = self.fapi.pcr_read(index)
        assert returned_value == sha256(value_old + sha256(data))
        assert '"test":"myfile"' in returned_log

    def test_nv_write_read(self, nv_ordinary):
        data = b"ABCDEFGHIJ"  # 10 bytes as defined in fixture
        self.fapi.nv_write(nv_ordinary, data)

        returned_data, log = self.fapi.nv_read(nv_ordinary)
        assert returned_data == data
        assert log == ""

    def test_nv_increment(self, nv_increment):
        # TODO initial increment should not be necessary, check in with upstream
        self.fapi.nv_increment(nv_increment)

        data_before, log = self.fapi.nv_read(nv_increment)
        assert len(data_before) == 8
        assert log == ""

        self.fapi.nv_increment(nv_increment)

        data_after, log = self.fapi.nv_read(nv_increment)
        assert len(data_after) == 8
        assert log == ""
        assert int.from_bytes(data_before, byteorder="big") + 1 == int.from_bytes(
            data_after, byteorder="big"
        )

    def test_nv_pcr(self, nv_pcr):
        value_old = b"\x00" * 32

        data = b"\x11" * 100
        log = '{"test":"myfile"}'
        self.fapi.nv_extend(nv_pcr, data, log)

        returned_value, returned_log = self.fapi.nv_read(nv_pcr)
        assert returned_value == sha256(value_old + data)
        assert '"test":"myfile"' in returned_log

    def test_nv_set_bits(self, nv_bitfield):
        bitfield = 0x0000DECAFBAD0000
        self.fapi.nv_set_bits(nv_bitfield, bitfield)

        returned_value, returned_log = self.fapi.nv_read(nv_bitfield)
        assert returned_value == bitfield.to_bytes(8, byteorder="big")
        assert returned_log == ""

    def test_set_auth_callback(self, sign_key):
        def callback(path, descr, user_data):
            print(f"Callback: path={path}, descr={descr}, user_data={user_data}")
            return user_data

        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"

        self.fapi.create_key(path=key_path, auth_value=b"123456")

        self.fapi.set_auth_callback(callback, user_data=b"123456")
        self.fapi.sign(key_path, b"\x11" * 32)

        self.fapi.change_auth(path=key_path, auth_value=b"ABCDEF")
        self.fapi.set_auth_callback(callback, user_data=b"ABCDEF")
        self.fapi.sign(key_path, b"\x22" * 32)

    def test_unset_auth_callback(self, sign_key):
        def callback(path, descr, user_data):
            print(f"Callback: path={path}, descr={descr}, user_data={user_data}")
            return user_data

        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"

        self.fapi.create_key(path=key_path, auth_value=b"123456")

        self.fapi.set_auth_callback(callback, user_data=b"123456")
        self.fapi.sign(key_path, b"\x11" * 32)

        self.fapi.change_auth(path=key_path, auth_value=None)
        self.fapi.set_auth_callback(callback=None)
        self.fapi.sign(key_path, b"\x22" * 32)

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2", backports=["2.4.7", "3.0.5", "3.1.1"]),
        reason="tpm2-tss bug, see #2084",
    )
    def test_write_authorize_nv(self, esys):
        # write CommandCode policy for sign key into nv index
        nv_path = f"/nv/Owner/nv_policy_{random_uid()}"
        policy = """
        {
            "description": "",
            "policy": [
                {
                    "type": "CommandCode",
                    "code": "sign"
                }
            ]
        }"""
        policy_auth_nv_path = f"/policy/policy_{random_uid()}"
        self.fapi.import_object(path=policy_auth_nv_path, import_data=policy)
        self.fapi.create_nv(path=nv_path, size=34)
        self.fapi.write_authorize_nv(nv_path, policy_auth_nv_path)

        # create key with AuthorizeNV policy (which ties the above policy, stored in the nv index, to the key)
        policy_auth_nv = f"""
        {{
            "description":"Description pol_authorize_nv",
            "policy":[
                {{
                    "type": "AuthorizeNV",
                    "nvPath": "{nv_path}",
                }}
          ]
        }}
        """
        policy_path = f"/policy/policy_{random_uid()}"
        self.fapi.import_object(path=policy_path, import_data=policy_auth_nv)
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(path=key_path, type_="sign", policy_path=policy_path)

        # use key for signing: success
        self.fapi.sign(path=key_path, digest=b"\x11" * 32)

        # use key for quoting: fail
        with pytest.raises(TSS2_Exception):
            self.fapi.quote(path=key_path, pcrs=[7, 9])

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2", backports=["2.4.7", "3.0.5", "3.1.1"]),
        reason="tpm2-tss bug, see #2084",
    )
    def test_authorize_policy(self, sign_key):
        # create policy Authorize, which is satisfied via a signature by sign_key
        policy_authorize_path = f"/policy/policy_{random_uid()}"
        policy_authorize = f"""
        {{
            "description": "Description pol_authorize",
            "policy": [
                {{
                    "type": "Authorize",
                    "policyRef": [1, 2, 3, 4, 5],
                    "keyPath": "{sign_key}",
                }}
            ]
        }}
        """
        self.fapi.import_object(
            path=policy_authorize_path, import_data=policy_authorize
        )

        # create policy CommandCode
        policy = """
        {
            "description": "",
            "policy": [
                {
                    "type": "CommandCode",
                    "code": "sign"
                }
            ]
        }"""
        policy_path = f"/policy/policy_{random_uid()}"
        self.fapi.import_object(path=policy_path, import_data=policy)

        # create key which can only be used if policy Authorize is satisfied
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(
            path=key_path, type_="sign", policy_path=policy_authorize_path
        )

        # try to use key without satisfying policy Authorize: fail
        with pytest.raises(TSS2_Exception):
            self.fapi.sign(path=key_path, digest=b"\x11" * 32)

        # specify underlying policy CommandCode and use key: success
        self.fapi.authorize_policy(
            policy_path=policy_path,
            key_path=sign_key,
            policy_ref=b"\x01\x02\x03\x04\x05",
        )
        self.fapi.sign(path=key_path, digest=b"\x11" * 32)

        # specify underlying policy CommandCode and use key: fail because policy CommandCode is not satisfied
        self.fapi.authorize_policy(
            policy_path=policy_path,
            key_path=sign_key,
            policy_ref=b"\x01\x02\x03\x04\x05",
        )
        with pytest.raises(TSS2_Exception):
            self.fapi.quote(path=key_path, pcrs=[7, 9])

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2"), reason="tpm2-tss bug, see #2080"
    )
    def test_policy_signed(self, cryptography_key):
        # create external signing key used by the signing authority external to the TPM
        sign_key, sign_key_public_pem = cryptography_key

        # create policy Signed, which is satisfied via a signature by sign_key
        policy = f"""
        {{
            "description": "Description pol_signed",
            "policy": [
                {{
                    "type": "PolicySigned",
                    "publicKeyHint": "Test key hint",
                    "keyPEM": "{sign_key_public_pem}",
                }}
            ]
        }}
        """
        policy_path = f"/policy/policy_{random_uid()}"
        self.fapi.import_object(path=policy_path, import_data=policy)

        # create key which can only be used if policy Signed is satisfied
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(path=key_path, type_="sign", policy_path=policy_path)

        # try to use key without satisfying policy Signed: fail
        with pytest.raises(TSS2_Exception):
            self.fapi.sign(path=key_path, digest=b"\x11" * 32)

        def sign_callback(
            path,
            description,
            public_key,
            public_key_hint,
            hash_alg,
            data_to_sign,
            user_data,
        ):
            assert key_path.endswith(path)
            assert description == "PolicySigned"
            assert public_key == sign_key_public_pem
            assert public_key_hint == "Test key hint"
            assert hash_alg == lib.TPM2_ALG_SHA256
            assert user_data == b"123456"

            # signing authority signs external to TPM (via openssl) to authorize usage of key (policy Signed)
            return sign_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

        # set signing callback, will be called if policy Signed is to be satisfied
        self.fapi.set_sign_callback(callback=sign_callback, user_data=b"123456")

        # use key for signing: success
        self.fapi.sign(path=key_path, digest=b"\x11" * 32)

    def test_policy_branched(self):
        pcr_index = 15
        pcr_data = b"ABCDEF"
        pcr_digest, _ = self.fapi.pcr_read(index=pcr_index)
        pcr_digest = sha256(pcr_digest + sha256(pcr_data))

        # create policy Signed, which is satisfied via a signature by sign_key
        policy = f"""
        {{
          "description": "Read, Password for write",
          "policy": [
            {{
              "type": "PolicyOR",
              "branches": [
                {{
                  "name": "Read",
                  "description": "des",
                  "policy": [
                    {{
                      "type": "CommandCode",
                      "code": "NV_READ"
                    }}
                  ]
                }},
                {{
                  "name": "Write",
                  "description": "dgf",
                  "policy": [
                    {{
                      "type": "CommandCode",
                      "code": "NV_WRITE"
                    }},
                    {{
                        "type": "PolicyPCR",
                        "pcrs":[
                            {{
                                "pcr": {pcr_index},
                                "hashAlg": "TPM2_ALG_SHA256",
                                "digest": "{binascii.hexlify(pcr_digest).decode()}"
                            }}
                        ]
                    }}
                  ]
                }}
              ]
            }}
          ]
        }}
        """

        policy_path = f"/policy/policy_{random_uid()}"
        self.fapi.import_object(path=policy_path, import_data=policy)

        # create key which can only be used if policy Signed is satisfied
        nv_path = f"/nv/Owner/nv_{random_uid()}"
        self.fapi.create_nv(path=nv_path, size=11, policy_path=policy_path)

        def branch_callback(path, description, branch_names, user_data):
            assert path == nv_path
            assert description == "PolicyOR"
            assert branch_names == ["Read", "Write"]
            assert user_data == b"123456"

            return policy_coice(branch_names)

        # set branch callback, will be called if the nv index is accessed
        self.fapi.set_branch_callback(callback=branch_callback, user_data=b"123456")

        # at first, we will choose the 'Write' branch
        policy_coice = lambda options: options.index("Write")

        # write to nv index: fail
        with pytest.raises(TSS2_Exception):
            self.fapi.nv_write(path=nv_path, data="Hello World")

        # satisfy policy PCR (and thus policy OR)
        self.fapi.pcr_extend(index=pcr_index, data=pcr_data)

        # write to nv index: success
        self.fapi.nv_write(path=nv_path, data="Hello World")

        # extend PCR so policy PCR cannot be satisfied anymore
        self.fapi.pcr_extend(
            index=pcr_index, data="nobody expects the spanish inquisition!"
        )

        # secondly, we will choose the 'Read' branch
        policy_coice = lambda options: options.index("Read")

        # use the 'Read' branch (satisfied via policy CommandCode)
        nv_data, _ = self.fapi.nv_read(nv_path)
        assert nv_data == b"Hello World"

        policy_coice = None

        # thirdly, we set different branch callback function (here lambda) and read again
        self.fapi.set_branch_callback(
            callback=lambda _path, _description, branch_names, _user_data: branch_names.index(
                "Read"
            )
        )
        nv_data, _ = self.fapi.nv_read(nv_path)
        assert nv_data == b"Hello World"

        # clean up
        self.fapi.delete(path=nv_path)

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2", backports=["2.4.7", "3.0.5", "3.1.1"]),
        reason="tpm2-tss bug, see #2089",
    )
    def test_policy_action(self):
        # create policy Action, which is satisfied via the callback
        policy = f"""
                {{
                    "description":"The description",
                    "policy":[
                        {{
                            "type": "POLICYACTION",
                            "action": "myaction"
                        }}
                    ]
                }}
                """
        policy_path = f"/policy/policy_{random_uid()}"
        self.fapi.import_object(path=policy_path, import_data=policy)

        # create key which can only be used if policy Action is satisfied
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(path=key_path, type_="sign", policy_path=policy_path)

        # try to use key without satisfying policy Action: fail
        with pytest.raises(TSS2_Exception):
            self.fapi.sign(path=key_path, digest=b"\x11" * 32)

        def policy_action_callback_error(path, action, user_data) -> None:
            assert f"/{path}" == key_path
            assert action == "myaction"
            assert user_data == b"123456"

            raise ValueError("Policy Action: Invalid action.")

        # set policy Action callback, will be called if policy Action is to be satisfied
        self.fapi.set_policy_action_callback(
            callback=policy_action_callback_error, user_data=b"123456"
        )

        # try to use key with policy Action that raises an exception: fail
        with pytest.raises(TSS2_Exception):
            self.fapi.sign(path=key_path, digest=b"\x11" * 32)

        # set policy Action callback to lambda, returning success
        self.fapi.set_policy_action_callback(callback=lambda *_: None)

        # use key for signing: success
        self.fapi.sign(path=key_path, digest=b"\x11" * 32)


@pytest.mark.usefixtures("init_fapi_ecc")
class TestFapiECC(Common):
    def test_sign(self, sign_key):
        # create signature
        message = b"Hello World"
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        digest = digest.finalize()

        signature, key_public_pem, cert_pem = self.fapi.sign(
            path=sign_key, digest=digest
        )
        assert type(signature) == bytes
        assert type(key_public_pem) == bytes
        assert type(cert_pem) == bytes

        # verify via fapi
        self.fapi.verify_signature(sign_key, digest, signature)

        # verify via openssl
        public_key = serialization.load_pem_public_key(
            key_public_pem, backend=default_backend()
        )
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

    def test_get_tpm_blobs(self, sign_key):
        tpm_2b_public, tpm_2b_private, policy = self.fapi.get_tpm_blobs(path=sign_key)
        assert tpm_2b_public.size == 0x56
        assert tpm_2b_public.publicArea.type == lib.TPM2_ALG_ECC
        assert tpm_2b_public.publicArea.nameAlg == lib.TPM2_ALG_SHA256
        assert (
            tpm_2b_public.publicArea.objectAttributes
            == lib.TPMA_OBJECT_SIGN_ENCRYPT
            | lib.TPMA_OBJECT_USERWITHAUTH
            | lib.TPMA_OBJECT_SENSITIVEDATAORIGIN
        )
        assert tpm_2b_public.publicArea.authPolicy.size == 0
        assert (
            tpm_2b_public.publicArea.parameters.eccDetail.symmetric.algorithm
            == lib.TPM2_ALG_NULL
        )
        assert (
            tpm_2b_public.publicArea.parameters.eccDetail.scheme.scheme
            == lib.TPM2_ALG_NULL
        )
        assert (
            tpm_2b_public.publicArea.parameters.eccDetail.curveID
            == lib.TPM2_ECC_NIST_P256
        )
        assert (
            tpm_2b_public.publicArea.parameters.eccDetail.kdf.scheme
            == lib.TPM2_ALG_NULL
        )
        assert tpm_2b_private.size == 0x7E
        assert policy == ""


@pytest.mark.usefixtures("init_fapi_rsa")
class TestFapiRSA(Common):
    def test_sign(self, sign_key):
        # create signature
        message = b"Hello World"
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        digest = digest.finalize()

        signature, key_public_pem, cert_pem = self.fapi.sign(
            path=sign_key, digest=digest
        )
        assert type(signature) == bytes
        assert type(key_public_pem) == bytes
        assert type(cert_pem) == bytes

        # verify via fapi
        self.fapi.verify_signature(sign_key, digest, signature)

        # verify via openssl
        public_key = serialization.load_pem_public_key(
            key_public_pem, backend=default_backend()
        )
        public_key.verify(
            signature,
            message,
            PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )

    def test_get_tpm_blobs(self, sign_key):
        tpm_2b_public, tpm_2b_private, policy = self.fapi.get_tpm_blobs(path=sign_key)
        assert tpm_2b_public.size == 0x116
        assert tpm_2b_public.publicArea.type == lib.TPM2_ALG_RSA
        assert tpm_2b_public.publicArea.nameAlg == lib.TPM2_ALG_SHA256
        assert (
            tpm_2b_public.publicArea.objectAttributes
            == lib.TPMA_OBJECT_SIGN_ENCRYPT
            | lib.TPMA_OBJECT_USERWITHAUTH
            | lib.TPMA_OBJECT_SENSITIVEDATAORIGIN
        )
        assert tpm_2b_public.publicArea.authPolicy.size == 0
        assert (
            tpm_2b_public.publicArea.parameters.rsaDetail.symmetric.algorithm
            == lib.TPM2_ALG_NULL
        )
        assert (
            tpm_2b_public.publicArea.parameters.rsaDetail.scheme.scheme
            == lib.TPM2_ALG_NULL
        )
        assert tpm_2b_public.publicArea.parameters.rsaDetail.keyBits == 2048
        assert tpm_2b_public.publicArea.parameters.rsaDetail.exponent == 0
        assert tpm_2b_private.size == 0xDE
        assert policy == ""

    @pytest.mark.skipif(
        not is_bug_fixed(fixed_in="3.2", backports=["2.4.7", "3.0.5", "3.1.1"]),
        reason="tpm2-tss bug, see #2092",
    )
    def test_encrypt_decrypt(self, decrypt_key):
        plaintext = b"Hello World!"
        ciphertext = self.fapi.encrypt(decrypt_key, plaintext)
        assert isinstance(ciphertext, bytes)

        decrypted = self.fapi.decrypt(decrypt_key, ciphertext)
        assert decrypted == plaintext


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv))
