#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -exo pipefail

export TPM2_TSS_VERSION=${TPM2_TSS_VERSION:-"3.0.3"}
export TPM2_TSS_FAPI=${TPM2_TSS_FAPI:-"true"}
export TPM2_TOOLS_VERSION=${TPM2_TOOLS_VERSION:-"5.3"}

#
# Get dependencies for building and install tpm2-tss and abrmd projects
#
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    autoconf-archive \
    curl \
    libcmocka0 \
    libcmocka-dev \
    net-tools \
    build-essential \
    git \
    pkg-config \
    gcc \
    g++ \
    m4 \
    libtool \
    automake \
    libgcrypt20-dev \
    libssl-dev \
    autoconf \
    gnulib \
    wget \
    doxygen \
    lcov \
    libcurl4-openssl-dev \
    expect \
    gawk \
    libjson-c-dev \
    uuid-dev \
    gnutls-bin \
    acl \
    libtasn1-6-dev \
    socat \
    libseccomp-dev \
    libjson-glib-dev

#
# Install tpm2-tss
#
if ! pkg-config tss2-sys; then
  # for git describe to work, one needs either a tag or a deep clone of master.
  if [ "${TPM2_TSS_VERSION}" != "master" ]; then
    tpm2_tss2_extra_git_flags="--depth 1"
  fi
  git -C /tmp clone ${tpm2_tss2_extra_git_flags} \
    --branch "${TPM2_TSS_VERSION}" https://github.com/tpm2-software/tpm2-tss.git
  pushd /tmp/tpm2-tss

  if [ "${TPM2_TSS_FAPI}" != "true" ]; then
    extra_configure_flags="--disable-fapi"
  fi
  ./bootstrap
  ./configure --sysconfdir=/etc ${extra_configure_flags} CFLAGS=-g
  make -j4
  sudo make install
  sudo ldconfig
  popd
fi

#
# Get a simulator
#

# Does our tcti support the TCTI for swtpm? If so get the swtpm simulator
if pkg-config --exists tss2-tcti-swtpm; then

  # libtpms
  if ! pkg-config libtpms; then
    git -C /tmp clone --depth=1 https://github.com/stefanberger/libtpms.git
    pushd /tmp/libtpms
    ./autogen.sh --prefix=/usr --with-openssl --with-tpm2 --without-tpm1
    make -j$(nproc)
    sudo make install
    popd
    rm -fr /tmp/libtpms
    sudo ldconfig
  fi

  # swtpm
  if ! command -v swtpm; then
    git -C /tmp clone --depth=1 https://github.com/stefanberger/swtpm.git
    pushd /tmp/swtpm
    ./autogen.sh --prefix=/usr
    make -j$(nproc)
    sudo make install
    popd
    rm -fr /tmp/swtpm
  fi
# Get IBM Simulator (supported for a longer time)
else
  # pull from fork that has fixes for RC handling not yet in mainline.
  git -C /tmp clone --depth=1 https://github.com/williamcroberts/ibmswtpm2.git -b fix-rc-exits
  pushd /tmp/ibmswtpm2/src
  make -j$(nproc)
  sudo cp tpm_server /usr/local/bin
  popd
  rm -fr /tmp/ibmswtpm2
fi

#
# Install tpm2-tools
#
if ! command -v tpm2; then
  # for git describe to work, one needs either a tag or a deep clone of master.
  if [ "${TPM2_TOOLS_VERSION}" != "master" ]; then
    tpm2_tools_extra_git_flags="--depth 1"
  fi
  git -C /tmp clone ${tpm2_tools_extra_git_flags} \
    --branch "${TPM2_TOOLS_VERSION}" https://github.com/tpm2-software/tpm2-tools.git
  pushd /tmp/tpm2-tools
  ./bootstrap
  ./configure CFLAGS=-g --disable-fapi
  make -j$(nproc)
  sudo make install
  popd
fi


#
# Pip version 21.3 was broken with in-pace (-e) installs. Thus use something
# after it as it was fixed in 21.3.1
#
python3 -m pip install --user --upgrade 'pip>21.3'

#
# Install Python Development Dependencies
#
python3 -m pip install --user -e .[dev]

exit 0
