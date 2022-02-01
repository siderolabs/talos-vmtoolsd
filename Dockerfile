FROM golang:1.17.6-alpine AS builder
WORKDIR /build
COPY . .
ARG CGO_ENABLED=0
ARG GOARCH=amd64
ARG GOOS=linux
RUN go test -v ./... && \
    go vet ./... && \
    go build -ldflags="-s -w" -trimpath -o talos-vmtoolsd ./cmd/talos-vmtoolsd

FROM gcr.io/distroless/static-debian10
COPY --from=builder /build/talos-vmtoolsd /bin/talos-vmtoolsd
ENTRYPOINT ["/bin/talos-vmtoolsd"]
