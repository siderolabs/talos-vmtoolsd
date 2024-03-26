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

FROM scratch
WORKDIR /bin
COPY --from=builder /build/talos-vmtoolsd /bin/talos-vmtoolsd
ENTRYPOINT ["/bin/talos-vmtoolsd"]
