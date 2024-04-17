#!/bin/bash

set -ex

cd /tmp

LIBPCAP_VERSION="${LIBPCAP_VERSION:-1.10.4}"
# Set by docker
TARGETARCH="${TARGETARCH:-""}"

echo "CC=$CC"

wget "http://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz"
tar xvf "libpcap-${LIBPCAP_VERSION}.tar.gz"
cd "libpcap-${LIBPCAP_VERSION}"

CONFIGURE_ARGS=(--with-pcap=linux)
if [[ -n "$TARGETARCH" ]]; then
  CONFIGURE_ARGS+=("--host=${TARGETARCH}-linux" --prefix=/usr/)
fi

MAKE_ARGS=()
if [[ "${MAKE_INSTALL:-"false"}" == "true" ]]; then
  MAKE_ARGS+=("install")
fi

./configure "${CONFIGURE_ARGS[@]}"
make "${MAKE_ARGS[@]}"
