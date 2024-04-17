#!/bin/bash

if [[ "$TARGETARCH" == "amd64" ]]; then
  echo x86_64-linux-gnu-gcc
elif [[ "$TARGETARCH" == "arm64" ]]; then
  echo aarch64-linux-gnu-gcc
else
  exit 1
fi
