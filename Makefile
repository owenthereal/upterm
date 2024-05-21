SHELL=/bin/bash -o pipefail

BIN_DIR ?= $(CURDIR)/bin
export PATH := $(BIN_DIR):$(PATH)

.PHONY: tools
tools:
	rm -rf $(BIN_DIR) && mkdir -p $(BIN_DIR)
	# goreleaser
	GOBIN=$(BIN_DIR) go install github.com/goreleaser/goreleaser@latest

.PHONY: generate
generate: proto

.PHONY: docs
docs:
	rm -rf docs && mkdir docs
	rm -rf etc && mkdir -p etc/man/man1 && mkdir -p etc/completion
	go run cmd/gendoc/main.go

.PHONY: proto
proto:
	docker run -v $(CURDIR)/server:/defs namely/protoc-all -f server.proto -l go --go-source-relative -o .
	docker run -v $(CURDIR)/host/api:/defs namely/protoc-all -f api.proto -l go --go-source-relative -o .

.PHONY: build
build:
	go build -o $(BIN_DIR)/upterm ./cmd/upterm
	go build -o $(BIN_DIR)/uptermd ./cmd/uptermd

.PHONY: install
install:
	go install ./cmd/...

TAG ?= latest
REPO ?= ghcr.io/owenthereal/upterm/uptermd
DOCKER_BUILD_FLAGS ?= --load
.PHONY: docker_build
docker_build:
	docker buildx build -t $(REPO):$(TAG) -f Dockerfile.uptermd $(DOCKER_BUILD_FLAGS) .

GO_TEST_FLAGS ?= ""
.PHONY: test
test:
	go test ./... -timeout=120s -coverprofile=c.out -covermode=atomic -count=1 -race -v $(GO_TEST_FLAGS)

.PHONY: vet
vet:
	docker run --rm -v $(CURDIR):/app:z -w /app golangci/golangci-lint:latest golangci-lint run -v --timeout 15m

.PHONY: goreleaser
goreleaser:
	goreleaser release --clean --snapshot --skip=publish
