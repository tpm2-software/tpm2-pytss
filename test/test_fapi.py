#!/usr/bin/python3 -u
"""
SPDX-License-Identifier: BSD-2
"""

import random
import string

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from tpm2_pytss import *

from .TSS2_BaseTest import TpmSimulator, TSS2_BaseTest


@pytest.fixture(scope="module")
def simulator():
    tpm = TpmSimulator.getSimulator()
    tpm.start()
    yield tpm
    tpm.close()


@pytest.fixture(scope="module")
def fapi_config(simulator):
    with FapiConfig(
        temp_dirs=True, tcti=simulator.tcti_name_conf, ek_cert_less="yes"
    ) as fapi_confi:
        yield fapi_confi


@pytest.fixture(scope="module")
def fapi(fapi_config):
    with FAPI() as fapi:
        fapi.provision()
        yield fapi


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
def init_fapi(request, fapi):
    request.cls.fapi = fapi
    request.cls.fapi.provision()
    request.cls.profile_name = request.cls.fapi.config.profile_name
    yield request.cls.fapi


# @pytest.mark.forked
@pytest.mark.usefixtures("init_fapi")
class TestFapi:
    @pytest.fixture
    def cryptography_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        key_public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return key, key_public_pem

    @pytest.fixture
    def sign_key(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(path=key_path, type="sign, exportable")
        yield key_path
        self.fapi.delete(path=key_path)

    @pytest.fixture
    def decrypt_key(self):
        profile_name = self.fapi.config.profile_name
        key_path = f"/{profile_name}/HS/SRK/key_{random_uid()}"
        self.fapi.create_key(path=key_path, type="decrypt, restricted, noda")
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
        self.fapi.create_nv(path=nv_path, size=10, type="counter")
        yield nv_path
        self.fapi.delete(path=nv_path)

    @pytest.fixture
    def nv_pcr(self):
        nv_path = f"/nv/Owner/nv_{random_uid()}"
        self.fapi.create_nv(path=nv_path, size=32, type="pcr")
        yield nv_path
        self.fapi.delete(path=nv_path)

    @pytest.fixture
    def nv_bitfield(self):
        nv_path = f"/nv/Owner/nv_{random_uid()}"
        self.fapi.create_nv(path=nv_path, size=32, type="bitfield")
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

    def test_info(self):
        info = self.fapi.info()
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

    def test_import_key(self, cryptography_key):
        key, key_public_pem = cryptography_key
        key_path = f"/ext/key_{random_uid()}"
        imported = self.fapi.import_object(path=key_path, import_data=key_public_pem)
        assert imported is True
        assert key_path in self.fapi.list()

    def test_import_key_double_ok(self, cryptography_key):
        key, key_public_pem = cryptography_key
        key_path = f"/ext/key_{random_uid()}"
        imported = self.fapi.import_object(path=key_path, import_data=key_public_pem)
        assert imported is True
        assert key_path in self.fapi.list()

        self.fapi.import_object(
            path=key_path, import_data=key_public_pem, exists_ok=True
        )
        assert imported is True

    def test_import_key_double_fail(self, cryptography_key):
        key, key_public_pem = cryptography_key
        key_path = f"/ext/key_{random_uid()}"
        imported = self.fapi.import_object(path=key_path, import_data=key_public_pem)
        assert imported is True
        assert key_path in self.fapi.list()

        self.fapi.import_object(path=key_path, import_data=key_public_pem)
        # assert imported is False  # TODO bug: tpm2-tss #2028, fixed in master
        assert imported is True

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

        self.fapi.import_object(path=policy_path, import_data=policy, exists_ok=True)
        assert imported is True

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

        self.fapi.import_object(path=policy_path, import_data=policy)
        # assert imported is False  # TODO bug: tpm2-tss #2028, fixed in master
        assert imported is True

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

    def test_get_empty_platform_certificates_fail(self):
        with pytest.raises(TSS2_Exception):
            self.fapi.get_platform_certificates()

    # TODO bug in TSS?
    # def test_get_empty_platform_certificates_ok(self):
    #    certificates = self.fapi.get_platform_certificates(no_cert_ok=True)
    #    assert certificates is None

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
        self.fapi.nv_increment(nv_increment)

        returned_data, log = self.fapi.nv_read(nv_increment)
        assert returned_data == b"\x00\x00\x00\x00\x00\x00\x00\x01"
        assert log == ""

    def test_nv_pcr(self, nv_pcr):
        value_old = b"\x00" * 32

        data = b"\x11" * 100
        log = '{"test":"myfile"}'
        self.fapi.nv_extend(nv_pcr, data, log)

        returned_value, returned_log = self.fapi.nv_read(nv_pcr)
        assert returned_value == sha256(value_old + data)
        assert '"test":"myfile"' in returned_log

    def test_nv_set_bits(self, nv_bitfield):
        value_old = b"\x00" * 32

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

    def test_write_authorize_nv(self):
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
        self.fapi.create_key(path=key_path, type="sign", policy_path=policy_path)

        # use key for signing: success
        self.fapi.sign(path=key_path, digest=b"\x11" * 32)

        # use key for quoting: fail
        with pytest.raises(TSS2_Exception):
            self.fapi.quote(path=key_path, pcrs=[7, 9])

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
            path=key_path, type="sign", policy_path=policy_authorize_path
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


# if __name__ == "__main__":
#    unittest.main()
