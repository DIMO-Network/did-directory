.PHONY: build run test lint fmt docker clean

BINARY := did-directory
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/did-directory

run: build
	./bin/$(BINARY) -settings settings.yaml

test:
	go test -v -race -count=1 ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .
	go mod tidy

docker:
	docker build -t dimo/did-directory:$(VERSION) .

clean:
	rm -rf bin/

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
