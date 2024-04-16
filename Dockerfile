# Using alpine because it has a static version of libcap
FROM golang:1.22-alpine

WORKDIR /usr/src/app

RUN apk add --no-cache libcap-static libpcap-dev linux-headers git file make build-base

COPY . .
RUN CGO_ENABLED=1 make capper GO_LINKER_FLAGS="-L /usr/lib/libcap.a -linkmode external -extldflags \"-static\""

ENTRYPOINT ["/usr/src/app/capper"]
