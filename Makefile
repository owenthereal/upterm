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
# Set TEST_COVER= to turn coverage off, and TEST_FORMAT=-json for go test's
# JSON event stream in place of -v.
TEST_COVER ?= -coverprofile=c.out -covermode=atomic
TEST_FORMAT ?= -v
# The bound is a guard against a hung test, not a performance budget. ftests
# is what sets it: a local make test runs both suites in one binary (CI's
# Ubuntu jobs split them), and a go test -timeout bounds that binary as a
# whole. On master's CI (655960a) the ftests package took 221.5s on the
# Ubuntu + Consul job, and 144s on macOS and 137s on Windows, which run
# without Consul. That was before the scenarios of a host redialling its
# relay were added; with them, this branch's CI took 250.5s on the Ubuntu +
# Consul job (160s on macOS, 133s on Windows), which leaves the old 300s
# with less headroom than runner-to-runner variance.
TEST_FLAGS = -timeout=600s $(TEST_COVER) -count=1 -race $(TEST_FORMAT) $(GO_TEST_FLAGS)

# go test starts packages in the order it is given, a few at a time, so a slow
# package listed late starts late and finishes last. The slow packages go
# first, and the rest follow in go list order.
TEST_SLOW_PKGS = ./host/internal/replay ./host/internal ./server ./host
# Deferred, and used only in recipes, so go list runs only when a test target
# does (make -n included) and other targets never run it. Each step's exit
# status is checked, and a failure or an empty list is an error: either would
# otherwise let go test pass on a partial list or the root package alone.
TEST_PKGS = $(call check_test_pkgs,$(shell s=$$(go list $(TEST_SLOW_PKGS)) && a=$$(go list ./...) && f=$$(printf '%s\n' "$$s" "$$a" | grep -v /e2e) && p=$$(printf '%s\n' "$$f" | awk '!seen[$$0]++') && [ -n "$$p" ] && printf '%s\n' "$$p" || echo test-pkgs-failed))
check_test_pkgs = $(if $(filter test-pkgs-failed,$(1)),$(error no packages to test: go list, grep or awk failed or printed nothing),$(or $(1),$(error no packages to test: the package listing printed nothing)))
TEST_OTHER_PKGS = $(filter-out github.com/owenthereal/upterm/ftests,$(TEST_PKGS))

# The ftests tests that test-ftests-split runs and test-ftests-rest skips.
FTESTS_SPLIT = ^(TestConsul|TestHopKeyRotationPhases)$$

.PHONY: test
test:
	go test $(TEST_PKGS) $(TEST_FLAGS)

.PHONY: test-others
test-others:
	go test $(TEST_OTHER_PKGS) $(TEST_FLAGS)

.PHONY: test-ftests
test-ftests:
	go test ./ftests $(TEST_FLAGS)

.PHONY: test-ftests-split
test-ftests-split:
	go test ./ftests -run '$(FTESTS_SPLIT)' $(TEST_FLAGS)

.PHONY: test-ftests-rest
test-ftests-rest:
	go test ./ftests -skip '$(FTESTS_SPLIT)' $(TEST_FLAGS)

# E2E tests require tmux and UPTERM_E2E_SERVER env var
# Example: UPTERM_E2E_SERVER=ssh://uptermd.upterm.dev:22 make test-e2e
.PHONY: test-e2e
test-e2e:
	go test ./internal/e2e/... -timeout=180s -count=1 -v $(GO_TEST_FLAGS)

# The mixed-version suite: this build's relay in fleets with released ones,
# which it installs from the module proxy, each into a directory of its own
# under $(COMPAT_BIN). Its Consul cases skip without Consul.
COMPAT_BIN = $(BIN_DIR)/compat
.PHONY: test-compat
test-compat:
	GOBIN=$(COMPAT_BIN)/v0.40.0 go install github.com/owenthereal/upterm/cmd/uptermd@v0.40.0 github.com/owenthereal/upterm/cmd/upterm@v0.40.0
	GOBIN=$(COMPAT_BIN)/a72f5571 go install github.com/owenthereal/upterm/cmd/uptermd@a72f5571534fe074e993ed048061c13cb98bf6c4
	GOBIN=$(COMPAT_BIN)/v0.41.1 go install github.com/owenthereal/upterm/cmd/uptermd@v0.41.1 github.com/owenthereal/upterm/cmd/upterm@v0.41.1
	UPTERM_COMPAT_BIN=$(COMPAT_BIN) go test -tags compat ./ftests -run '^TestMixedVersionFleets$$' -timeout=900s -count=1 -v $(GO_TEST_FLAGS)

.PHONY: vet
vet:
	docker run --rm -v $(CURDIR):/app:z -w /app golangci/golangci-lint:latest golangci-lint run -v --timeout 15m --fix

.PHONY: wasm-check
wasm-check:
	GOOS=js GOARCH=wasm go build ./join ./attach

DOCKER_REPO ?= ghcr.io/owenthereal/upterm/uptermd
.PHONY: goreleaser
goreleaser:
	DOCKER_REPO=$(DOCKER_REPO) goreleaser release --clean --snapshot --skip=publish
