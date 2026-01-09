export GO111MODULE = on

VERSION ?= 0.1.0
LDFLAGS = -ldflags "-X main.version=$(VERSION) -X main.rev=$$(git rev-list --count HEAD 2>/dev/null || echo 0)"
CMDS = $(notdir $(wildcard cmd/*))

.PHONY: build test test-all test-cover lint clean $(CMDS)

build: $(CMDS)

$(CMDS):
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$@ ./cmd/$@

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
