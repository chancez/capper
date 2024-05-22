GO := go
GO_LINKER_FLAGS ?=
GO_BUILD_FLAGS ?=
IMAGE_TAG := main
DOCKER_FLAGS ?=

all: proto capper

.PHONY: capper
capper:
	$(GO) build --ldflags='$(GO_LINKER_FLAGS)' $(GO_BUILD_FLAGS) -o capper .

.PHONY: proto
proto:
	protoc \
		--go_opt=paths=source_relative \
		--go_out=. \
		--go-grpc_opt=paths=source_relative \
		--go-grpc_out=. \
		proto/capper/*.proto

image:
	docker build $(DOCKER_FLAGS) -t quay.io/capper/capper:$(IMAGE_TAG) .
