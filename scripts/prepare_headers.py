#!/usr/bin/python3
# SPDX-License-Identifier: BSD-2

import importlib.util
import os
import pkgconfig
import pathlib
import re
import sys
import textwrap

# import tpm2_pytss.constants
constants_spec = importlib.util.spec_from_file_location(
    "tpm2_pytss.internal.constants", "tpm2_pytss/internal/constants.py"
)
constants = importlib.util.module_from_spec(constants_spec)
constants_spec.loader.exec_module(constants)


def remove_common_guards(s):

    # Remove includes and guards
    s = re.sub("#ifndef.*", "", s)
    s = re.sub("#define .*_H\n", "", s)
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

    return remove_common_guards(s)


def prepare_tcti_ldr(dirpath):

    s = pathlib.Path(dirpath, "tss2_tctildr.h").read_text(encoding="utf-8")

    return remove_common_guards(s)


def prepare_sapi():
    return "typedef struct TSS2_SYS_CONTEXT TSS2_SYS_CONTEXT;"


def prepare_esapi(dirpath):

    s = pathlib.Path(dirpath, "tss2_esys.h").read_text(encoding="utf-8")
    return remove_common_guards(s)


def prepare_fapi(dirpath):

    s = pathlib.Path(dirpath, "tss2_fapi.h").read_text(encoding="utf-8")

    s = remove_poll_stuff(s, "FAPI_POLL_HANDLE")

    s += "".join(
        f"""
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_AUTH]}{i}(
        char     const *objectPath,
        char     const *description,
        char    const **auth,
        void           *userData);
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_BRANCH]}{i}(
        char     const *objectPath,
        char     const *description,
        char    const **branchNames,
        size_t          numBranches,
        size_t         *selectedBranch,
        void           *userData);
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_SIGN]}{i}(
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
    extern "Python" TSS2_RC {constants.CALLBACK_BASE_NAME[constants.CallbackType.FAPI_POLICYACTION]}{i}(
        char     const *objectPath,
        char     const *action,
        void           *userData);
     """
        for i in range(0, constants.CALLBACK_COUNT)
    )

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


def prepare(indir, outfile, build_fapi=True):
    indir = os.path.join(indir, "tss2")

    common = prepare_common(indir)

    types = prepare_types(indir)

    tcti = prepare_tcti(indir)

    tcti_ldr = prepare_tcti_ldr(indir)

    sapi = prepare_sapi()

    esapi = prepare_esapi(indir)

    if build_fapi:
        fapi = prepare_fapi(indir)

    rcdecode = prepare_rcdecode(indir)

    mu = prepare_mu(indir)

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
        f.write(sapi)
        f.write(esapi)
        if build_fapi:
            f.write(fapi)
        f.write(rcdecode)
        f.write(mu)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: {0} <tss2-header-dir> <output-file>".format(sys.argv[0]))
        exit(1)

    build_fapi = pkgconfig.installed("tss2-fapi", ">=3.0.0")

    prepare(sys.argv[1], sys.argv[2], build_fapi=build_fapi)
