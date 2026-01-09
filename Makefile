export GO111MODULE = on

VERSION ?= 0.1.0
LDFLAGS = -ldflags "-X main.version=$(VERSION) -X main.rev=$$(git rev-list --count HEAD 2>/dev/null || echo 0)"
CMDS = $(notdir $(wildcard cmd/*))
PLATFORMS ?= linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64

.PHONY: build build-cross test test-all test-cover lint clean $(CMDS)

build: $(CMDS)

$(CMDS):
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$@ ./cmd/$@

build-cross:
	@mkdir -p bin
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'-' -f1); \
		arch=$$(echo $$platform | cut -d'-' -f2); \
		for cmd in $(CMDS); do \
			ext=""; \
			if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
			echo "Building $$cmd for $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o bin/$$cmd-$$platform$$ext ./cmd/$$cmd; \
		done; \
	done

test:
	go test -short ./...

test-all:
	go test -race -cover ./...

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

lint:
	golangci-lint run --timeout=600s && go vet ./...

clean:
	rm -rf bin test.out
