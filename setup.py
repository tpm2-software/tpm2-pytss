import site
import sys
import os
import platform
from setuptools import setup
from setuptools.command.build_ext import build_ext
from pkgconfig import pkgconfig
from pycparser import c_parser, preprocess_file
from pycparser.c_ast import (
    Typedef,
    TypeDecl,
    IdentifierType,
    Struct,
    ArrayDecl,
    Union,
    Enum,
)
from textwrap import dedent

# workaround bug https://github.com/pypa/pip/issues/7953
site.ENABLE_USER_SITE = "--user" in sys.argv[1:]


class type_generator(build_ext):
    cares = set(
        (
            "TPM2_ALG_ID",
            "TPM2_ST",
            "TPM2_ECC_CURVE",
            "TPM2_CC",
            "TPM2_CAP",
            "TPM2_PT",
            "TPM2_PT_PCR",
            "TPMA_SESSION",
            "TPMA_LOCALITY",
            "TPMA_NV",
            "TPMA_CC",
            "TPMA_OBJECT",
            "TPMA_ALGORITHM",
            "TPM2_HANDLE",
            "TPM2_GENERATED",
            "ESYS_TR",
            "TSS2_POLICY_PCR_SELECTOR",
        )
    )

    type_mapping = {
        "TPM2_ALG_ID": "TPM2_ALG",
        "TPMI_RH_HIERARCHY": "TPM2_RH",
        "TPMI_RH_ENABLES": "TPM2_RH",
        "TPMI_RH_HIERARCHY_AUTH": "TPM2_RH",
        "TPMI_RH_HIERARCHY_POLICY": "TPM2_RH",
        "TPMI_RH_PLATFORM": "TPM2_RH",
        "TPMI_RH_OWNER": "TPM2_RH",
        "TPMI_RH_ENDORSEMENT": "TPM2_RH",
        "TPMI_RH_PROVISION": "TPM2_RH",
        "TPMI_RH_CLEAR": "TPM2_RH",
        "TPMI_RH_NV_AUTH": "TPM2_RH",
        "TPMI_RH_LOCKOUT": "TPM2_RH",
        "TPMI_RH_NV_INDEX": "TPM2_RH",
        "TPMI_RH_AC": "TPM2_RH",
        "TPMI_RH_ACT": "TPM2_RH",
    }

    map_template = """
    # SPDX-License-Identifier: BSD-2

    # this file is autogenerated during the build

    _type_map = {{
    {mstr}
    }}

    _element_type_map = {{
    {estr}
    }}
    """

    version_template = """
    # SPDX-License-Identifier: BSD-2
    # this file is autogenerated during the build

    _versions = {{
    {vstr}
    }}
    """

    version_libs = ("tss2-esys", "tss2-fapi", "tss2-policy", "tss2-tcti-spi-helper")

    def get_types(self, ast):
        tm = dict()
        for v in ast:
            if (
                isinstance(v, Typedef)
                and isinstance(v.type, TypeDecl)
                and isinstance(v.type.type, (IdentifierType, Enum))
            ):
                if hasattr(v.type.type, "names"):
                    names = v.type.type.names
                elif hasattr(v.type.type, "name"):
                    names = [v.type.type.name]
                name = " ".join(names)
                if v.name in self.type_mapping:
                    tm[v.name] = self.type_mapping[v.name]
                elif name in self.type_mapping:
                    tm[v.name] = self.type_mapping[name]
                elif name in self.cares:
                    self.cares.add(v.name)
                    tm[v.name] = name
                elif v.name in self.cares:
                    tm[v.name] = v.name
        return tm

    def get_fields(self, v, tm):
        fields = list()
        nf = 0
        for d in v.decls:
            nf = nf + 1
            if not isinstance(d.type.type, (IdentifierType, Enum)):
                continue
            dn = d.name
            if hasattr(d.type.type, "names"):
                names = d.type.type.names
            elif hasattr(d.type.type, "name"):
                names = [d.type.type.name]
            tname = " ".join(names)
            if tname not in tm:
                continue
            fields.append((dn, tm[tname]))
        return fields

    def get_array_fields(self, v, tm):
        fields = list()
        nf = 0
        for d in v.decls:
            nf = nf + 1
            if not isinstance(d.type, ArrayDecl):
                continue
            tname = " ".join(d.type.type.type.names)
            if tname not in tm:
                continue
            fields.append(tm[tname])
        return fields

    def get_first_struct(self, v):
        if isinstance(v, (Struct, Union)):
            return v
        while hasattr(v, "type"):
            v = v.type
            if isinstance(v, (Struct, Union)):
                return v
        return None

    def generate_mappings(self, ast, tm):
        mapping = dict()
        element_mapping = dict()
        for v in ast:
            if isinstance(v, Typedef):
                name = v.name
            v = self.get_first_struct(v)
            if v is None or getattr(v, "decls") is None:
                continue
            fields = self.get_fields(v, tm)
            for f in fields:
                mapping[(name, f[0])] = f[1]
            afields = self.get_array_fields(v, tm)
            for af in afields:
                element_mapping[name] = af
        return (mapping, element_mapping)

    def get_mappings(self):
        pk = pkgconfig.parse("tss2-esys")
        header_path = None
        for ip in pk["include_dirs"]:
            hp = os.path.join(ip, "tss2_tpm2_types.h")
            if os.path.isfile(hp):
                header_path = hp
                break
            hp = os.path.join(ip, "tss2", "tss2_tpm2_types.h")
            if os.path.isfile(hp):
                header_path = hp
                break
        if header_path is None:
            raise RuntimeError(
                f"unable to find tss2_tpm2_types.h in {pk['include_dirs']}"
            )

        if platform.system() == "FreeBSD":
            pdata = preprocess_file(
                header_path,
                cpp_args=[
                    "-std=c99",
                    "-D__builtin_va_list=char*",
                    "-D__extension__=",
                    "-D__attribute__(x)=",
                ],
            )
        else:
            pdata = preprocess_file(
                header_path,
                cpp_args=["-std=c99", "-D__extension__=", "-D__attribute__(x)="],
            )
        parser = c_parser.CParser()
        ast = parser.parse(pdata, "tss2_tpm2_types.h")
        tm = self.get_types(ast)
        (mapping, element_mapping) = self.generate_mappings(ast, tm)
        if pkgconfig.exists("tss2-policy"):
            pk = pkgconfig.parse("tss2-policy")
            for ip in pk["include_dirs"]:
                hp = os.path.join(ip, "tss2_policy.h")
                if os.path.isfile(hp):
                    policy_header_path = hp
                    break
                hp = os.path.join(ip, "tss2", "tss2_policy")
                if os.path.isfile(hp):
                    policy_header_path = hp
                    break
            if policy_header_path:
                if platform.system() == "FreeBSD":
                    pdata = preprocess_file(
                        policy_header_path,
                        cpp_args=[
                            "-std=c99",
                            "-D__builtin_va_list=char*",
                            "-D__extension__=",
                            "-D__attribute__(x)=",
                            "-D__float128=long double",
                            "-D_FORTIFY_SOURCE=0",
                        ],
                    )
                else:
                    pdata = preprocess_file(
                        policy_header_path,
                        cpp_args=[
                            "-std=c99",
                            "-D__extension__=",
                            "-D__attribute__(x)=",
                            "-D__float128=long double",
                            "-D_FORTIFY_SOURCE=0",
                        ],
                    )
                parser = c_parser.CParser()
                past = parser.parse(pdata, "tss2_policy.h")
                ptm = self.get_types(past)
                tm.update(ptm)
                (pmapping, pelement_mapping) = self.generate_mappings(past, ptm)
                mapping.update(pmapping)
                element_mapping.update(pelement_mapping)
        return (mapping, element_mapping)

    def get_versions(self):
        versions = dict()
        for lib in self.version_libs:
            try:
                versions[lib] = pkgconfig.modversion(lib)
            except pkgconfig.PackageNotFoundError:
                # Library not installed, ignore
                pass
        return versions

    def run(self):
        super().run()
        type_map, element_type_map = self.get_mappings()
        mstr = ""
        for k, v in type_map.items():
            (t, f) = k
            mstr = mstr + f'    ("{t}", "{f}"): "{v}",\n'
        mstr = mstr.rstrip()
        estr = ""
        for k, v in element_type_map.items():
            estr = estr + f'    "{k}": "{v}",\n'
        estr = estr.rstrip()

        versions = self.get_versions()
        vstr = ""
        for k, v in versions.items():
            vstr = vstr + f'    "{k}": "{v}",\n'
        vstr = vstr.rstrip()

        p = os.path.join(self.build_lib, "tpm2_pytss/internal/type_mapping.py")
        sp = os.path.join(
            os.path.dirname(__file__), "src/tpm2_pytss/internal/type_mapping.py"
        )

        vp = os.path.join(self.build_lib, "tpm2_pytss/internal/versions.py")
        svp = os.path.join(
            os.path.dirname(__file__), "src/tpm2_pytss/internal/versions.py"
        )

        print(f"generated _type_map with {len(type_map)} mappings in {p} and {sp}")
        print(f"generated _element_type_map with {len(element_type_map)} mappings")
        print(f"generated _versions with {len(versions)} versions")

        stempl = dedent(self.map_template)
        mout = stempl.format(mstr=mstr, estr=estr).lstrip()

        vtempl = dedent(self.version_template)
        vout = vtempl.format(vstr=vstr).lstrip()

        if not self.dry_run:
            self.mkpath(os.path.dirname(p))
            with open(p, "wt") as tf:
                tf.seek(0)
                tf.truncate(0)
                tf.write(mout)
            with open(vp, "wt") as vf:
                vf.seek(0)
                vf.truncate(0)
                vf.write(vout)

        if self.inplace:
            self.copy_file(p, sp)
            self.copy_file(vp, svp)


setup(
    use_scm_version=True,
    cffi_modules=["scripts/libtss2_build.py:ffibuilder"],
    cmdclass={"build_ext": type_generator},
)
