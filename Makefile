# For development only.
# This Makefile is not being used by Dockerfile or GitHub actions.

SHA ?= $(shell git describe --match=none --always --abbrev=8 --dirty)

talos-vmtoolsd:
	go build -ldflags="-s -w" -trimpath -o $@ ./cmd/$@

docker-build:
	docker buildx build . --tag talos-vmtoolsd:$(SHA) --file Dockerfile

.PHONY: talos-vmtoolsd docker-build
