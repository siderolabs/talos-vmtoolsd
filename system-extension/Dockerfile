###############################################################################
FROM golang:1.22.1-alpine AS build
WORKDIR /build
COPY . .
ARG CGO_ENABLED=0
ARG GOARCH=amd64
ARG GOOS=linux
RUN go test -v ./... && \
    go vet ./... && \
    go build -ldflags="-s -w" -trimpath -o talos-vmtoolsd ./cmd/talos-vmtoolsd

###############################################################################
FROM alpine AS stage

RUN mkdir -p /stage/rootfs/usr/local/etc/containers
RUN mkdir -p /stage/rootfs/usr/local/lib/containers/talos-vmtoolsd

COPY --from=build /build/talos-vmtoolsd /stage/rootfs/usr/local/lib/containers/talos-vmtoolsd/

COPY ./system-extension/manifest.yaml /stage/
COPY ./system-extension/talos-vmtoolsd.yaml /stage/rootfs/usr/local/etc/containers/

###############################################################################
FROM scratch
COPY --from=stage /stage /
