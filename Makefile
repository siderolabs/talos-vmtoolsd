talos-vmtoolsd:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o $@ ./cmd/$@

.PHONY: talos-vmtoolsd
