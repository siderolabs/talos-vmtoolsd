FROM golang:1-alpine AS builder
WORKDIR /build
COPY . .
ENV CGO_ENABLED=0
ARG GOARCH=amd64
RUN GOOS=linux GOARCH=${GOARCH} go build -ldflags="-s -w" -trimpath -o talos-vmtoolsd ./cmd/talos-vmtoolsd

FROM alpine:latest
COPY --from=builder /build/talos-vmtoolsd /usr/local/bin/talos-vmtoolsd
ENTRYPOINT [ "/usr/local/bin/talos-vmtoolsd" ]
