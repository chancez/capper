GO := go

.PHONY: capper
capper:
	$(GO) build -o capper .
