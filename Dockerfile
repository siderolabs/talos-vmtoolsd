FROM golang:1.17.2-alpine AS builder
WORKDIR /build
COPY . .
ENV CGO_ENABLED=0
ARG GOARCH=amd64
RUN GOOS=linux GOARCH=${GOARCH} go build -ldflags="-s -w" -trimpath -o talos-vmtoolsd ./cmd/talos-vmtoolsd

FROM gcr.io/distroless/static-debian10
COPY --from=builder /build/talos-vmtoolsd /bin/talos-vmtoolsd
ENTRYPOINT ["/bin/talos-vmtoolsd"]
