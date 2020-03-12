#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

# TPM2 2.4.0
export TPM2_TSS_SHA=70da4f245a575948712a7c2cf52de84213dc9db8

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
}
