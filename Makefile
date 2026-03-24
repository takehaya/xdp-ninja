.PHONY: build clean test test-unit test-bpf test-integration test-all vet

BINARY = xdp-ninja

build:
	go build -o $(BINARY) ./cmd/xdp-ninja/

vet:
	go vet ./...

test: test-unit

test-unit:
	go test ./...

test-bpf:
	sudo env "PATH=$(PATH)" "HOME=$(HOME)" "GOPATH=$$(go env GOPATH)" "GOMODCACHE=$$(go env GOMODCACHE)" \
		go test -v -count 1 -timeout 5m ./internal/program/ -run TestBpf

test-integration: build
	sudo scripts/test/run_tests.sh

test-all: test-unit test-bpf test-integration

clean:
	rm -f $(BINARY)
