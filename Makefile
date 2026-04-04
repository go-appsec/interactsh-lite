export GO111MODULE = on

VERSION := $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-s -w -X github.com/go-appsec/interactsh-lite/oobclient.Version=$(VERSION)"
PLATFORMS ?= linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64
SRV_PLATFORMS ?= linux-amd64 linux-arm64

.PHONY: build build-cross test test-all test-cover lint bench clean

build:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/interactsh-lite .
	cd interactsh-srv && go build $(LDFLAGS) -o ../bin/interactsh-srv .

build-cross:
	@mkdir -p bin
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'-' -f1); \
		arch=$$(echo $$platform | cut -d'-' -f2); \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building interactsh-lite for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o bin/interactsh-lite-$$platform$$ext .; \
	done
	@for platform in $(SRV_PLATFORMS); do \
		os=$$(echo $$platform | cut -d'-' -f1); \
		arch=$$(echo $$platform | cut -d'-' -f2); \
		echo "Building interactsh-srv for $$os/$$arch..."; \
		(cd interactsh-srv && GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o ../bin/interactsh-srv-$$platform$$ext .); \
	done

test:
	go test -short ./...
	cd interactsh-srv && go test -short ./...

test-all:
	go test -race -cover ./...
	cd interactsh-srv && go test -race -cover ./...

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

lint:
	golangci-lint run --timeout=600s && go vet ./...
	cd interactsh-srv && golangci-lint run --timeout=600s -c ../.golangci.yml && go vet ./...

bench:
	go test -benchmem -benchtime=10s -bench='Benchmark.*' -run='^$$' ./...
	cd interactsh-srv && go test -benchmem -benchtime=10s -bench='Benchmark.*' -run='^$$' ./...

clean:
	rm -rf bin test.out
