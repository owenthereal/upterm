SHELL=/bin/bash -o pipefail

BIN_DIR ?= $(CURDIR)/bin
export PATH := $(BIN_DIR):$(PATH)

.PHONY: tools
tools:
	rm -rf $(BIN_DIR) && mkdir -p $(BIN_DIR)
	# goreleaser
	GOBIN=$(BIN_DIR) go install github.com/goreleaser/goreleaser/v2@latest

.PHONY: generate
generate: proto

.PHONY: docs
docs:
	rm -rf docs && mkdir docs
	rm -rf etc && mkdir -p etc/man/man1 && mkdir -p etc/completion
	XDG_STATE_HOME=/home/user/.local/state XDG_CONFIG_HOME=/home/user/.config XDG_RUNTIME_DIR=/run/user/1000 go run cmd/gendoc/main.go

# protoc-gen-go tracks google.golang.org/protobuf in go.mod: the generator and
# the runtime it generates against are one version. protoc itself is not
# go-installable, so install libprotoc 36.1 (brew install protobuf) and put it
# on PATH; a different protoc only changes the version comment in the headers.
PROTOC_GEN_GO_VERSION ?= v1.36.12
PROTOC_GEN_GO_GRPC_VERSION ?= v1.2.0

.PHONY: proto_tools
proto_tools:
	mkdir -p $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(BIN_DIR) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

# require_unimplemented_servers=false keeps api.AdminServiceServer satisfiable
# from outside this module: the mandatory shape adds an unexported marker
# method that no out-of-tree implementer can write.
.PHONY: proto
proto: proto_tools
	protoc -I server --go_out=server --go_opt=paths=source_relative server/server.proto
	protoc -I host/api --go_out=host/api --go_opt=paths=source_relative \
		--go-grpc_out=host/api --go-grpc_opt=paths=source_relative \
		--go-grpc_opt=require_unimplemented_servers=false \
		host/api/api.proto host/api/startup.proto

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
# The bound is a guard against a hung test, not a performance budget. ftests is
# what sets it: on the Consul job it runs both suites in one binary and had
# grown to 126s of the old 180s before this timeout was last touched, leaving
# less headroom than runner-to-runner variance.
.PHONY: test
test:
	go test $$(go list ./... | grep -v /e2e) -timeout=300s -coverprofile=c.out -covermode=atomic -count=1 -race -v $(GO_TEST_FLAGS)

# E2E tests require tmux and UPTERM_E2E_SERVER env var
# Example: UPTERM_E2E_SERVER=ssh://uptermd.upterm.dev:22 make test-e2e
.PHONY: test-e2e
test-e2e:
	go test ./internal/e2e/... -timeout=180s -count=1 -v $(GO_TEST_FLAGS)

.PHONY: vet
vet:
	docker run --rm -v $(CURDIR):/app:z -w /app golangci/golangci-lint:latest golangci-lint run -v --timeout 15m --fix

DOCKER_REPO ?= ghcr.io/owenthereal/upterm/uptermd
.PHONY: goreleaser
goreleaser:
	DOCKER_REPO=$(DOCKER_REPO) goreleaser release --clean --snapshot --skip=publish
