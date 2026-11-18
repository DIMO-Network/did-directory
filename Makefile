.PHONY: build run test lint fmt docker clean odrl-builder odrl-builder-serve vectors

BINARY := did-directory
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/did-directory
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/org-host ./cmd/org-host
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/dimocli ./cmd/dimocli

run: build
	./bin/$(BINARY) -settings settings.yaml

test:
	go test -v -race -count=1 ./...

# Also runs the org host's store and HTTP tests against Postgres. Create the
# database once with `createdb org_host_test`.
test-postgres:
	ORG_HOST_TEST_DATABASE_URL="postgres://localhost:5432/org_host_test?sslmode=disable" go test -race -count=1 ./internal/orghost/...

vectors:
	go run ./cmd/didvectors -out testdata/vectors/did-ops.json

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .
	go mod tidy

docker:
	docker build -t dimo/did-directory:$(VERSION) .

clean:
	rm -rf bin/ docs/odrl-builder/builder.wasm docs/odrl-builder/wasm_exec.js

# The ODRL builder page: pkg/odrl compiled to WebAssembly, next to docs/odrl-builder/index.html.
odrl-builder:
	GOOS=js GOARCH=wasm go build -ldflags "-s -w" -o docs/odrl-builder/builder.wasm ./cmd/odrl-builder
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" docs/odrl-builder/

odrl-builder-serve: odrl-builder
	@echo "http://localhost:8765/"
	python3 -m http.server 8765 --directory docs/odrl-builder

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
