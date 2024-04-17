FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build

WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    gcc-x86-64-linux-gnu \
    gcc-aarch64-linux-gnu \
    libc6-dev-amd64-cross \
    libc6-dev-arm64-cross \
    byacc flex && \
    rm -rf /var/lib/apt/lists/*

ARG TARGETOS TARGETARCH

COPY scripts/target-arch-cc.sh /tmp/target-arch-cc.sh
COPY scripts/compile-libpcap.sh /tmp/compile-libpcap.sh
RUN CC=$(/tmp/target-arch-cc.sh) MAKE_INSTALL=true /tmp/compile-libpcap.sh

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
     CC=$(/tmp/target-arch-cc.sh) GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=1 make capper

FROM debian:bookworm

COPY --from=build /lib/libpcap.* /lib/
COPY --from=build /usr/src/app/capper /usr/bin/capper

ENTRYPOINT ["/usr/bin/capper"]
