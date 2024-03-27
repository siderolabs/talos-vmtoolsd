REGISTRY ?= ghcr.io
USERNAME ?= sidereolabs
SHA ?= $(shell git describe --match=none --always --abbrev=8 --dirty)
TAG ?= $(shell git describe --tag --always --dirty --match v[0-9]\*)
ABBREV_TAG ?= $(shell git describe --tag --always --match v[0-9]\* --abbrev=0 )
TAG_SUFFIX ?=
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
IMAGE_REGISTRY ?= $(REGISTRY)
IMAGE_NAME = talos-vmtoolsd
IMAGE_TAG ?= $(TAG)$(TAG_SUFFIX)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
REGISTRY_AND_USERNAME := $(IMAGE_REGISTRY)/$(USERNAME)

talos-vmtoolsd:
	go build -ldflags="-s -w" -trimpath -o $@ ./cmd/$@

docker-build:
	docker buildx build . --tag $(REGISTRY_AND_USERNAME)/${IMAGE_NAME}:$(IMAGE_TAG)

.PHONY: talos-vmtoolsd docker-build
