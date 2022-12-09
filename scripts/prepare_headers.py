#!/usr/bin/python3
# SPDX-License-Identifier: BSD-2

import os
import pkgconfig
import pathlib
import re
import sys
import textwrap


def remove_common_guards(s):

    # Remove includes and guards
    s = re.sub("#ifndef.*", "", s)
    s = re.sub("#if .*", "", s)
    s = re.sub("#define .*_H_*?\n", "", s)
    s = re.sub("#endif.*", "", s)
    s = re.sub("#error.*", "", s)
    s = re.sub('#ifdef __cplusplus\nextern "C" {', "", s, flags=re.MULTILINE)
    s = re.sub("#ifdef __cplusplus\n}", "", s, flags=re.MULTILINE)
    s = re.sub("#include.*", "", s)

    # Remove certain macros
    s = re.sub("#define TSS2_API_VERSION.*", "", s)
    s = re.sub("#define TSS2_ABI_VERSION.*", "", s)
    s = re.sub("#define TSS2_RC_LAYER\(level\).*", "", s)
    s = re.sub("(#define.*)TSS2_RC_LAYER\(0xff\)", "\g<1>0xff0000", s)

    # Remove comments
    s = re.sub("/\*.*?\*/", "", s, flags=re.MULTILINE)

    # Restructure #defines with ...
    s = re.sub("(#define [A-Za-z0-9_]+) +\(\(.*?\) \(.*?\)\)", "\g<1>...", s)
    s = re.sub("(#define [A-Za-z0-9_]+) +\(\(.*?\).*?\) ", "\g<1>...", s)
    s = re.sub(
        "(#define [A-Za-z0-9_]+) .*\n.*?.*\)\)", "\g<1>...", s, flags=re.MULTILINE
    )
    s = re.sub("(#define [A-Za-z0-9_]+) .*", "\g<1>...", s)

    # Restructure structs and untions with ...
    s = re.sub("\[.+?\]", "[...]", s)

    return s


def remove_poll_stuff(s, poll_handle_type):

    r = r"#if defined\(__linux__\) \|\| defined\(__unix__\) \|\| defined\(__APPLE__\) \|\| defined \(__QNXNTO__\) \|\| defined \(__VXWORKS__\)(\n.*)+#endif\n#endif"

    s = re.sub(r, f"typedef struct pollfd {poll_handle_type};", s)
    return s


def remove_INTERNALBUILD(s):

    r = r"#if\s+defined\(INTERNALBUILD\)(?:(?!endif).)*#endif"
    s = re.sub(r, "", s, flags=re.MULTILINE | re.DOTALL)
    s = re.sub(r"DEPRECATED", "", s)

    return re.sub(r"__attribute__\(\(deprecated\)\)", "", s)


def prepare_common(dirpath):

    s = pathlib.Path(dirpath, "tss2_common.h").read_text(encoding="utf-8")

    return remove_common_guards(s)


def prepare_types(dirpath):

    s = pathlib.Path(dirpath, "tss2_tpm2_types.h").read_text(encoding="utf-8")

    # Remove false define (workaround)
    s = re.sub(
        "#define TPM2_MAX_TAGGED_POLICIES.*\n.*TPMS_TAGGED_POLICY\)\)",
        "",
        s,
        flags=re.MULTILINE,
    )

    s = remove_INTERNALBUILD(s)

    return remove_common_guards(s)


def prepare_tcti(dirpath):

    s = pathlib.Path(dirpath, "tss2_tcti.h").read_text(encoding="utf-8")

    s = re.sub("#ifndef TSS2_API_VERSION.*\n.*\n#endif", "", s, flags=re.MULTILINE)

    s = remove_poll_stuff(s, "TSS2_TCTI_POLL_HANDLE")

    s = re.sub(r"#define TSS2_TCTI_.*\n.*", "", s, flags=re.MULTILINE)
    s = re.sub(r"^\s*#define Tss2_Tcti_(?:.*\\\r?\n)*.*$", "", s, flags=re.MULTILINE)

    s += """
    struct pollfd {
        int   fd;         /* file descriptor */
        short events;     /* requested events */
        short revents;    /* returned events */
    };
    """

    # Add the callbacks for a TCTI
    s += """
    extern "Python" TSS2_RC _tcti_transmit_wrapper (
        TSS2_TCTI_CONTEXT *tctiContext,
        size_t size,
        uint8_t const *command);

    extern "Python" TSS2_RC _tcti_receive_wrapper (
        TSS2_TCTI_CONTEXT *tctiContext,
        size_t *size,
        uint8_t *response,
        int32_t timeout);

    extern "Python" void _tcti_finalize_wrapper (
        TSS2_TCTI_CONTEXT *tctiContext);

    extern "Python" TSS2_RC _tcti_cancel_wrapper (
        TSS2_TCTI_CONTEXT *tctiContext);

    extern "Python" TSS2_RC _tcti_get_pollfds_wrapper (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles);

    extern "Python" TSS2_RC _tcti_set_locality_wrapper (
        TSS2_TCTI_CONTEXT *tctiContext,
        uint8_t locality);

    extern "Python" TSS2_RC _tcti_make_sticky_wrapper (
        TSS2_TCTI_CONTEXT *tctiContext,
        TPM2_HANDLE *handle,
        uint8_t sticky);
    """

    # Add this struct here so CFFI knows about it and its size
    s += """
    typedef struct PYTCTI_CONTEXT PYTCTI_CONTEXT;
    struct PYTCTI_CONTEXT {
        TSS2_TCTI_CONTEXT_COMMON_V2 common;
        void *thiz;
    };
    """

    return remove_common_guards(s)


def prepare_tcti_ldr(dirpath):

    s = pathlib.Path(dirpath, "tss2_tctildr.h").read_text(encoding="utf-8")
    return remove_common_guards(s)


def prepare_tcti_spi_helper(dirpath):

    s = pathlib.Path(dirpath, "tss2_tcti_spi_helper.h").read_text(encoding="utf-8")

    # Add the callbacks for a TCTI
    s += """
    extern "Python" TSS2_RC _tcti_spi_helper_sleep_ms (
        void *userdata,
        int milliseconds);

    extern "Python" TSS2_RC _tcti_spi_helper_start_timeout (
        void *userdata,
        int milliseconds);

    extern "Python" TSS2_RC _tcti_spi_helper_timeout_expired (
        void *userdata, bool *is_timeout_expired);

    extern "Python" TSS2_RC _tcti_spi_helper_spi_acquire (
        void *userdata);

    extern "Python" TSS2_RC _tcti_spi_helper_spi_release (
    void *userdata);

    extern "Python" TSS2_RC _tcti_spi_helper_spi_transfer (
        void *userdata,
        const void *data_out,
        void *data_in,
        size_t cnt);

    extern "Python" void _tcti_spi_helper_finalize (
        void *userdata);
    """

    return remove_common_guards(s)


def prepare_sapi():
    return "typedef struct TSS2_SYS_CONTEXT TSS2_SYS_CONTEXT;"


def prepare_esapi(dirpath):

    s = pathlib.Path(dirpath, "tss2_esys.h").read_text(encoding="utf-8")
    return remove_common_guards(s)


def prepare_fapi(dirpath):

    s = pathlib.Path(dirpath, "tss2_fapi.h").read_text(encoding="utf-8")

    s = remove_poll_stuff(s, "FAPI_POLL_HANDLE")

    s += """
    extern "Python" TSS2_RC _fapi_auth_callback(
        char     const *objectPath,
        char     const *description,
        char    const **auth,
        void           *userData);
    extern "Python" TSS2_RC _fapi_branch_callback(
        char     const *objectPath,
        char     const *description,
        char    const **branchNames,
        size_t          numBranches,
        size_t         *selectedBranch,
        void           *userData);
    extern "Python" TSS2_RC _fapi_sign_callback(
        char     const *objectPath,
        char     const *description,
        char     const *publicKey,
        char     const *publicKeyHint,
        uint32_t        hashAlg,
        uint8_t  const *dataToSign,
        size_t          dataToSignSize,
        uint8_t const **signature,
        size_t         *signatureSize,
        void           *userData);
    extern "Python" TSS2_RC _fapi_policy_action_callback(
        char     const *objectPath,
        char     const *action,
        void           *userData);
     """

    return remove_common_guards(s)


def prepare_rcdecode(dirpath):

    s = pathlib.Path(dirpath, "tss2_rc.h").read_text(encoding="utf-8")

    return remove_common_guards(s)


def prepare_mu(dirpath):

    s = pathlib.Path(dirpath, "tss2_mu.h").read_text(encoding="utf-8")

    s = remove_INTERNALBUILD(s)

    s = remove_common_guards(s)

    # At least tpm2-tss 3.0.3 have duplicated BYTE (un)marshal functions which break cffi
    # So removing them is needed until 3.1.x has reached most distributions
    n = re.findall(
        "TSS2_RC\s+Tss2_MU_BYTE_Marshal\(.+?\);", s, re.DOTALL | re.MULTILINE
    )
    if len(n) > 1:
        s = re.sub(
            "TSS2_RC\s+Tss2_MU_BYTE_Marshal\(.+?\);", "", s, 1, re.DOTALL | re.MULTILINE
        )

    n = re.findall(
        "TSS2_RC\s+Tss2_MU_BYTE_Unmarshal\(.+?\);", s, re.DOTALL | re.MULTILINE
    )
    if len(n) > 1:
        s = re.sub(
            "TSS2_RC\s+Tss2_MU_BYTE_Unmarshal\(.+?\);",
            "",
            s,
            1,
            re.DOTALL | re.MULTILINE,
        )

    return s


def prepare_policy(dirpath):
    s = pathlib.Path(dirpath, "tss2_policy.h").read_text(encoding="utf-8")
    s = remove_common_guards(s)
    # cparser complains if a typedef of an enum is before the definition of the enum
    s = re.sub(
        "typedef enum TSS2_POLICY_PCR_SELECTOR TSS2_POLICY_PCR_SELECTOR;", "", s, 1
    )
    s = re.sub(
        r"(enum TSS2_POLICY_PCR_SELECTOR.*?\};)",
        r"\1" + "\ntypedef enum TSS2_POLICY_PCR_SELECTOR TSS2_POLICY_PCR_SELECTOR;",
        s,
        1,
        re.DOTALL | re.MULTILINE,
    )
    s += """
    extern "Python" TSS2_RC _policy_cb_calc_pcr(
        TSS2_POLICY_PCR_SELECTION *selection,
        TPML_PCR_SELECTION *out_selection,
        TPML_DIGEST *out_digest,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_calc_name(
        const char *path,
        TPM2B_NAME *name,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_calc_public(
        const char *path,
        TPMT_PUBLIC *public,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_calc_nvpublic(
        const char *path,
        TPMI_RH_NV_INDEX nv_index,
        TPMS_NV_PUBLIC *nv_public,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_exec_auth(
        TPM2B_NAME *name,
        ESYS_TR *object_handle,
        ESYS_TR *auth_handle,
        ESYS_TR *authSession,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_exec_polsel(
        TSS2_OBJECT *auth_object,
        const char **branch_names,
        size_t branch_count,
        size_t *branch_idx,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_exec_sign(
        char *key_pem,
        char *public_key_hint,
        TPMI_ALG_HASH key_pem_hash_alg,
        uint8_t *buffer,
        size_t buffer_size,
        const uint8_t **signature,
        size_t *signature_size,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_exec_polauth(
        TPMT_PUBLIC *key_public,
        TPMI_ALG_HASH hash_alg,
        TPM2B_DIGEST *digest,
        TPM2B_NONCE *policyRef,
        TPMT_SIGNATURE *signature,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_exec_polauthnv(
        TPMS_NV_PUBLIC *nv_public,
        TPMI_ALG_HASH hash_alg,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_exec_poldup(
        TPM2B_NAME *name,
        void *userdata);
    extern "Python" TSS2_RC _policy_cb_exec_polaction(
        const char *action,
        void *userdata);
    """
    return s


def prepare(
    indir, outfile, build_fapi=True, build_policy=True, build_tcti_spi_helper=True
):
    indir = os.path.join(indir, "tss2")

    common = prepare_common(indir)

    types = prepare_types(indir)

    tcti = prepare_tcti(indir)

    tcti_ldr = prepare_tcti_ldr(indir)

    if build_tcti_spi_helper:
        tcti_spi_helper = prepare_tcti_spi_helper(indir)

    sapi = prepare_sapi()

    esapi = prepare_esapi(indir)

    if build_fapi:
        fapi = prepare_fapi(indir)

    rcdecode = prepare_rcdecode(indir)

    mu = prepare_mu(indir)

    if build_policy:
        policy = prepare_policy(indir)

    # Write result
    with open(outfile, "w") as f:
        f.write(
            textwrap.dedent(
                """
            /*
             * SPDX-License-Identifier: BSD-2
             * This file was automatically generated. Do not modify !
             */
            """
            )
        )

        f.write(common)
        f.write(types)
        f.write(tcti)
        f.write(tcti_ldr)
        if build_tcti_spi_helper:
            f.write(tcti_spi_helper)
        f.write(sapi)
        f.write(esapi)
        if build_fapi:
            f.write(fapi)
        f.write(rcdecode)
        f.write(mu)
        if build_policy:
            f.write(policy)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {0} <tss2-header-dir> <output-file>".format(sys.argv[0]))
        exit(1)

    build_fapi = pkgconfig.installed("tss2-fapi", ">=3.0.0")
    build_tcti_spi_helper = pkgconfig.exists("tss2-tcti-spi-helper")
    prepare(
        sys.argv[1],
        sys.argv[2],
        build_fapi=build_fapi,
        build_tcti_spi_helper=build_tcti_spi_helper,
    )
