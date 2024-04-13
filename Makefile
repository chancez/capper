GO := go

all: proto capper

.PHONY: capper
capper:
	$(GO) build -o capper .

.PHONY: proto
proto:
	protoc \
		--go_opt=paths=source_relative \
		--go_out=. \
		--go-grpc_opt=paths=source_relative \
		--go-grpc_out=. \
		proto/capper/capper.proto
