# For development only.
# This Makefile is not being used by Dockerfile.

talos-vmtoolsd:
	go build -ldflags="-s -w" -trimpath -o $@ ./cmd/$@

.PHONY: talos-vmtoolsd
