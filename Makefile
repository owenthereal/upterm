SHELL=/bin/bash -o pipefail

.PHONY: build proto client install docker k8s test generate-host-keys

K8S_NS := default

generate: proto client

proto:
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
	go build -o build/upterm -mod=vendor ./cmd/upterm/...
	go build -o build/uptermd -mod=vendor ./cmd/uptermd/...

install:
	go install -mod=vendor ./cmd/... 

test:
	go test ./... -count=1

docker:
	docker build -t jingweno/uptermd . && docker push jingweno/uptermd

k8s:
	kubectl apply -f config/uptermd.yml -n $(K8S_NS)

generate-host-keys:
	rm -rf config/server_host_keys config/router_host_keys
	mkdir config/server_host_keys config/router_host_keys
	ssh-keygen -q -t ed25519  -f config/server_host_keys/ed25519_key -N "" -C ""
	ssh-keygen -q -t ed25519  -f config/router_host_keys/ed25519_key -N "" -C ""
	kubectl -n $(K8S_NS) create secret generic server-host-keys \
		--from-file=config/server_host_keys/ed25519_key \
		--from-file=config/server_host_keys/ed25519_key.pub
	kubectl -n $(K8S_NS) create secret generic router-host-keys \
		--from-file=config/router_host_keys/ed25519_key \
		--from-file=config/router_host_keys/ed25519_key.pub
