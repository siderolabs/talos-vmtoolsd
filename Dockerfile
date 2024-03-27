#### Build binary
FROM golang:1.22.1-alpine AS builder
WORKDIR /build
COPY . .
ARG TARGETARCH
ARG CGO_ENABLED=0
ARG GOARCH=$TARGETARCH
ARG GOOS=linux
RUN go test -v ./... && \
    go vet ./... && \
    go build -ldflags="-s -w" -trimpath -o talos-vmtoolsd ./cmd/talos-vmtoolsd

#### Build system extension tree
FROM alpine:3.19 AS stage
RUN mkdir -p /stage/rootfs/usr/local/etc/containers
RUN mkdir -p /stage/rootfs/usr/local/lib/containers/talos-vmtoolsd
COPY --from=builder /build/talos-vmtoolsd /stage/rootfs/usr/local/lib/containers/talos-vmtoolsd/
COPY ./manifest.yaml /stage/
COPY ./talos-vmtoolsd.yaml /stage/rootfs/usr/local/etc/containers/

#### Build final container
FROM scratch
COPY --from=stage /stage /
ENTRYPOINT ["/rootfs/usr/local/lib/containers/talos-vmtoolsd/talos-vmtoolsd"]
