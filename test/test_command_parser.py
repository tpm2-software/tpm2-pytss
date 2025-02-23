# SPDX-License-Identifier: BSD-2
import unittest
from io import BytesIO
from tpm2_pytss.command_parser import (
    read_command,
    read_response,
    read_command_header,
    UINT32,
    read_command_sessions,
    TPM_ENCRYPTED_PARAMETER,
    tpm2_command,
    tpm2_response,
)
from tpm2_pytss.constants import (
    TPM2_ST,
    TPM2_CC,
    TPM2_SU,
    TPM2_RC,
    TPMA_SESSION,
    TPM2_SE,
    TPM2_ALG,
    TSS2_RC,
)
from tpm2_pytss.types import (
    TPM2_HANDLE,
    TPM2B_NONCE,
    TPM2B_AUTH,
    TPM2B_ENCRYPTED_SECRET,
    TPMT_SYM_DEF,
    TPM2B_DIGEST,
    TPM2B_SENSITIVE_DATA,
)
from tpm2_pytss.TSS2_Exception import TSS2_Exception


class CommandParserTest(unittest.TestCase):
    def test_startup_command(self):
        buf = b""
        buf += TPM2_CC.Startup.marshal()
        buf += TPM2_SU.CLEAR.marshal()
        tag = TPM2_ST.NO_SESSIONS.marshal()
        # commandSize is size of tag, bytes for commandSize and size of parameters
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        command = read_command(fp)
        self.assertEqual(len(fp.getvalue()), fp.tell())
        self.assertEqual(command.command_code, TPM2_CC.Startup)
        self.assertEqual(len(command.handles), 0)
        self.assertEqual(len(command.sessions), 0)
        self.assertEqual(len(command.parameters), 1)
        self.assertEqual(command.parameters, (TPM2_SU.CLEAR,))

    def test_startup_response(self):
        buf = b""
        buf += TPM2_RC.SUCCESS.marshal()
        tag = TPM2_ST.NO_SESSIONS.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        response = read_response(fp, TPM2_CC.Startup)
        self.assertEqual(len(fp.getvalue()), fp.tell())
        self.assertEqual(response.response_code, TPM2_RC.SUCCESS)
        self.assertEqual(response.handle, None)
        self.assertEqual(len(response.sessions), 0)
        self.assertEqual(len(response.parameters), 0)

    def test_failure_response(self):
        buf = b""
        buf += TPM2_RC.FAILURE.marshal()
        tag = TPM2_ST.NO_SESSIONS.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        response = read_response(fp, TPM2_CC.Startup)
        self.assertEqual(len(fp.getvalue()), fp.tell())
        self.assertEqual(response.response_code, TPM2_RC.FAILURE)
        self.assertEqual(response.handle, None)
        self.assertEqual(len(response.sessions), 0)
        self.assertEqual(len(response.parameters), 0)

    def test_read_command_header(self):
        fp = BytesIO()
        fp.write(TPM2_ST.SESSIONS.marshal())
        fp.write(UINT32(10).marshal())
        fp.write(TPM2_CC.Startup.marshal())
        fp.seek(0)
        print(int(10).to_bytes(4, byteorder="big"))

        tag, cc, left = read_command_header(fp)

        self.assertEqual(tag, TPM2_ST.SESSIONS)
        self.assertEqual(cc, TPM2_CC.Startup)
        self.assertEqual(left, 0)

    def test_read_command_sessions(self):
        fp = BytesIO()
        for i in range(0, 3):
            fp.write(TPM2_HANDLE(i).marshal())
            fp.write(TPM2B_NONCE(32 * bytes([i])).marshal())
            fp.write(TPMA_SESSION(i).marshal())
            fp.write(TPM2B_AUTH(bytes([i] * 32)).marshal())

        size = UINT32(len(fp.getvalue()))
        newfp = BytesIO()
        newfp.write(size.marshal())
        newfp.write(fp.getvalue())
        newfp.seek(0)

        sessions = read_command_sessions(newfp)

        self.assertEqual(len(sessions), 3)
        self.assertEqual(newfp.tell(), len(newfp.getvalue()))

        for i in range(0, len(sessions)):
            self.assertEqual(sessions[i].handle, i)
            self.assertEqual(sessions[i].attributes, i)
            self.assertEqual(sessions[i].nonce, bytes([i] * 32))
            self.assertEqual(sessions[i].authorization, bytes([i] * 32))

    def test_start_auth_session_command(self):
        buf = b""
        buf += TPM2_CC.StartAuthSession.marshal()
        buf += TPM2_HANDLE(1).marshal()
        buf += TPM2_HANDLE(2).marshal()
        # session here
        session_buf = b""
        session_buf += TPM2_HANDLE(1234).marshal()
        session_buf += TPM2B_NONCE(b"1234").marshal()
        session_buf += TPMA_SESSION(234).marshal()
        session_buf += TPM2B_AUTH(b"1234").marshal()
        session_size = UINT32(len(session_buf)).marshal()
        buf += session_size
        buf += session_buf
        # parameters here
        buf += TPM2B_NONCE(b"3").marshal()
        buf += TPM2B_ENCRYPTED_SECRET(b"4").marshal()
        buf += TPM2_SE.HMAC.marshal()
        buf += TPMT_SYM_DEF.parse("aes128cbc").marshal()
        buf += TPM2_ALG.SHA256.marshal()
        tag = TPM2_ST.SESSIONS.marshal()
        # commandSize is size of tag, bytes for commandSize and size of parameters
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        command = read_command(fp)

        self.assertEqual(command.tag, TPM2_ST.SESSIONS)
        self.assertEqual(len(command.handles), 2)
        self.assertEqual(command.handles[0], 1)
        self.assertEqual(command.handles[1], 2)

        self.assertEqual(len(command.sessions), 1)
        self.assertEqual(command.sessions[0].handle, TPM2_HANDLE(1234))
        self.assertEqual(command.sessions[0].nonce, TPM2B_NONCE(b"1234"))
        self.assertEqual(command.sessions[0].attributes, TPMA_SESSION(234))
        self.assertEqual(command.sessions[0].authorization, TPM2B_AUTH(b"1234"))

        self.assertEqual(len(command.parameters), 5)
        self.assertEqual(command.parameters[0], TPM2B_NONCE(b"3"))
        self.assertEqual(command.parameters[1], TPM2B_ENCRYPTED_SECRET(b"4"))
        self.assertEqual(command.parameters[2], TPM2_SE.HMAC)
        self.assertEqual(command.parameters[3].algorithm, TPM2_ALG.AES)
        self.assertEqual(command.parameters[3].mode.sym, TPM2_ALG.CBC)
        self.assertEqual(command.parameters[3].keyBits.sym, 128)
        self.assertEqual(command.parameters[4], TPM2_ALG.SHA256)

    def test_start_auth_session_response(self):
        buf = b""
        buf += TPM2_RC.SUCCESS.marshal()
        # handle here
        buf += TPM2_HANDLE(1).marshal()
        # parameters here
        parameter_buf = TPM2B_NONCE(b"falafel").marshal()
        parameter_size = UINT32(len(parameter_buf)).marshal()
        buf += parameter_size + parameter_buf
        # sessions here
        session_buf = TPM2B_NONCE(b"1234").marshal()
        session_buf += TPMA_SESSION(123).marshal()
        session_buf += TPM2B_DIGEST(b"1234").marshal()
        session_size = UINT32(len(session_buf)).marshal()
        buf += session_size + session_buf
        tag = TPM2_ST.SESSIONS.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        response = read_response(fp, TPM2_CC.StartAuthSession)

        self.assertEqual(response.tag, TPM2_ST.SESSIONS)
        self.assertEqual(response.response_code, TPM2_RC.SUCCESS)
        self.assertEqual(response.handle, TPM2_HANDLE(1))

        self.assertEqual(len(response.parameters), 1)
        self.assertEqual(response.parameters[0], TPM2B_NONCE(b"falafel"))

        self.assertEqual(len(response.sessions), 1)
        self.assertEqual(response.sessions[0].nonce, TPM2B_NONCE(b"1234"))
        self.assertEqual(response.sessions[0].attributes, TPMA_SESSION(123))
        self.assertEqual(response.sessions[0].acknowledgment, TPM2B_DIGEST(b"1234"))

    def test_encrypt_parameter(self):
        buf = b""
        buf += TPM2_RC.SUCCESS.marshal()
        parameter_buf = TPM2B_DIGEST(b"falafel").marshal()
        parameter_size = UINT32(len(parameter_buf)).marshal()
        buf += parameter_size + parameter_buf
        session_buf = TPM2B_NONCE(b"1234").marshal()
        session_buf += TPMA_SESSION.ENCRYPT.marshal()
        session_buf += TPM2B_DIGEST(b"1234").marshal()
        session_size = UINT32(len(session_buf)).marshal()
        buf += session_size + session_buf
        tag = TPM2_ST.SESSIONS.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        response = read_response(fp, TPM2_CC.GetRandom)

        self.assertEqual(response.tag, TPM2_ST.SESSIONS)
        self.assertEqual(response.response_code, TPM2_RC.SUCCESS)

        self.assertEqual(len(response.parameters), 1)
        self.assertIsInstance(response.parameters[0], TPM_ENCRYPTED_PARAMETER)
        self.assertEqual(response.parameters[0].underlying_type, TPM2B_DIGEST)
        self.assertEqual(response.parameters[0], b"falafel")

        self.assertEqual(len(response.sessions), 1)
        self.assertEqual(response.sessions[0].nonce, TPM2B_NONCE(b"1234"))
        self.assertEqual(response.sessions[0].attributes, TPMA_SESSION.ENCRYPT)
        self.assertEqual(response.sessions[0].acknowledgment, TPM2B_DIGEST(b"1234"))

    def test_decrypt_parameter(self):
        buf = b""
        buf += TPM2_CC.StirRandom.marshal()
        session_buf = b""
        session_buf += TPM2_HANDLE(1234).marshal()
        session_buf += TPM2B_NONCE(b"1234").marshal()
        session_buf += TPMA_SESSION.DECRYPT.marshal()
        session_buf += TPM2B_AUTH(b"1234").marshal()
        session_size = UINT32(len(session_buf)).marshal()
        buf += session_size + session_buf
        buf += TPM2B_SENSITIVE_DATA(b"falafel").marshal()
        tag = TPM2_ST.SESSIONS.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        command = read_command(fp)

        self.assertEqual(command.tag, TPM2_ST.SESSIONS)

        self.assertEqual(len(command.sessions), 1)
        self.assertEqual(command.sessions[0].handle, TPM2_HANDLE(1234))
        self.assertEqual(command.sessions[0].nonce, TPM2B_NONCE(b"1234"))
        self.assertEqual(command.sessions[0].attributes, TPMA_SESSION.DECRYPT)
        self.assertEqual(command.sessions[0].authorization, TPM2B_AUTH(b"1234"))

        self.assertIsInstance(command.parameters[0], TPM_ENCRYPTED_PARAMETER)
        self.assertEqual(command.parameters[0].underlying_type, TPM2B_SENSITIVE_DATA)
        self.assertEqual(command.parameters[0], b"falafel")

    def test_command_bad_tag(self):
        buf = b""
        buf += TPM2_CC.Startup.marshal()
        buf += TPM2_SU.CLEAR.marshal()
        tag = TPM2_ST.NULL.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)

        with self.assertRaises(TSS2_Exception) as e:
            read_command(fp)

        self.assertEqual(e.exception.rc, TPM2_RC.BAD_TAG)

    def test_response_bad_tag(self):
        buf = b""
        buf += TPM2_RC.SUCCESS.marshal()
        tag = TPM2_ST.ATTEST_NV.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)

        with self.assertRaises(TSS2_Exception) as e:
            read_response(fp, TPM2_CC.Startup)

        self.assertEqual(e.exception.rc, TPM2_RC.BAD_TAG)

    def test_tpm_encrypted_parameter(self):
        p = TPM_ENCRYPTED_PARAMETER(TPM2B_DIGEST, b"falafel")

        self.assertEqual(bytes(p), b"falafel")

        marshaled = p.marshal()
        self.assertEqual(marshaled, b"\x00\x07falafel")

        self.assertNotEqual(p, "falafel")

    def test_missing_commands(self):
        with self.assertRaises(TSS2_Exception) as e:
            tpm2_command.lookup_command_class(TPM2_CC.LAST + 1)
        self.assertEqual(e.exception.rc, TSS2_RC.BASE_RC_NOT_IMPLEMENTED)

        with self.assertRaises(TSS2_Exception) as e:
            tpm2_response.lookup_response_class(TPM2_CC.LAST + 1)
        self.assertEqual(e.exception.rc, TSS2_RC.BASE_RC_NOT_IMPLEMENTED)

    def test_without_encrypted_parameter(self):
        buf = b""
        buf += TPM2_RC.SUCCESS.marshal()
        parameter_buf = TPM2B_DIGEST(b"falafel").marshal()
        parameter_size = UINT32(len(parameter_buf)).marshal()
        buf += parameter_size + parameter_buf
        session_buf = TPM2B_NONCE(b"1234").marshal()
        session_buf += TPMA_SESSION(0).marshal()
        session_buf += TPM2B_DIGEST(b"1234").marshal()
        session_size = UINT32(len(session_buf)).marshal()
        buf += session_size + session_buf
        tag = TPM2_ST.SESSIONS.marshal()
        size = len(tag) + 4 + len(buf)
        size_bytes = size.to_bytes(4, byteorder="big")
        fp = BytesIO()
        fp.write(tag)
        fp.write(size_bytes)
        fp.write(buf)
        fp.seek(0)
        response = read_response(fp, TPM2_CC.GetRandom)

        self.assertIsInstance(response.parameters[0], TPM2B_DIGEST)
