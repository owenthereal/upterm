SHELL=/bin/bash -o pipefail

.PHONY: docs build proto client install test vet

generate: proto client

docs:
	rm -rf docs && mkdir docs
	rm -rf etc && mkdir -p etc/man/man1 && mkdir -p etc/completion
	go run cmd/gendoc/main.go

proto:
	protoc \
		-I server \
		-I $$(go env GOPATH)/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		--go_out=plugins=grpc:server \
		./server/server.proto
	protoc \
		-I host/api \
		-I $$(go env GOPATH)/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		--go_out=plugins=grpc:host/api \
		./host/api/api.proto
	protoc \
		-I host/api \
		-I $$(go env GOPATH)/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		--grpc-gateway_out=logtostderr=true:host/api \
		./host/api/api.proto
	protoc \
		-I host/api \
		-I $$(go env GOPATH)/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
		--swagger_out=logtostderr=true:host/api \
		./host/api/api.proto

client:
	rm -rf host/api/swagger
	mkdir -p host/api/swagger
	docker \
		run \
		--rm \
		-e GOPATH=/go \
		--volume $(CURDIR):/go/src/github.com/jingweno/upterm \
		-w /go/src/github.com/jingweno/upterm quay.io/goswagger/swagger \
		generate client -t host/api/swagger -f ./host/api/api.swagger.json


build:
	go build -o build/upterm -mod=vendor ./cmd/upterm
	go build -o build/uptermd -mod=vendor ./cmd/uptermd

install:
	go install ./cmd/... 

docker_build:
	docker build -t jingweno/uptermd -f Dockerfile.uptermd .

docker: docker_build
	docker push jingweno/uptermd

test:
	go test ./... -timeout=60s -coverprofile=c.out -covermode=atomic -mod=vendor -count=1 -race -v

vet:
	docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:latest golangci-lint run -v
