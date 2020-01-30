#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

# tss -> build: update exported symbols map for libtss2-mu
export TPM2_TSS_SHA=8823180397fed4f7052d4c44e4724935396e3f41
# TODO (pdxjohnny) Can't remember if we still need abrmd, I think not
# abrmd -> 2.2.0_rc
export TPM2_ABRMD_SHA=b41fbe23089b8701d229db1988a2811315288dfc

function get_deps() {

  echo "pwd starting: `pwd`"
  pushd "$1"
  if [ ! -d tpm2-tss ]; then
    echo "pwd download tss: `pwd`"
    curl -sSL https://github.com/tpm2-software/tpm2-tss/archive/${TPM2_TSS_SHA}.tar.gz \
      | tar xvz
    mv tpm2-tss-${TPM2_TSS_SHA} tpm2-tss
    pushd tpm2-tss
    echo "pwd build tss: `pwd`"
    ./bootstrap
    ./configure CFLAGS=-g
    make -j4
    make install
    ldconfig
    echo "pwd done tss: `pwd`"
    popd
  fi

	if [ ! -d tpm2-abrmd ]; then
    echo "pwd download abrmd: `pwd`"
    curl -sSL https://github.com/tpm2-software/tpm2-abrmd/archive/${TPM2_ABRMD_SHA}.tar.gz \
      | tar xvz
    mv tpm2-abrmd-${TPM2_ABRMD_SHA} tpm2-abrmd
    pushd tpm2-abrmd
    echo "pwd build abrmd: `pwd`"
    ./bootstrap
    ./configure CFLAGS=-g
    make -j4
    make install
    ldconfig
    echo "pwd done abrmd: `pwd`"
    popd
	fi

}
