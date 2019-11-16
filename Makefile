.PHONY: build install docker k8s test generate-host-keys

build:
	go build -o build/upterm ./cmd/upterm/...
	go build -o build/uptermd ./cmd/uptermd/...

install:
	go install ./cmd/...

test:
	go test ./... -count=1

docker:
	docker build -t jingweno/uptermd . && docker push jingweno/uptermd

K8S_NS := default

k8s:
	kubectl apply -f config/uptermd.yml -n $(K8S_NS)

generate-host-keys:
	rm -rf config/host_keys
	mkdir config/host_keys
	ssh-keygen -q -t ed25519  -f config/host_keys/ed25519_key -N "" -C ""
	kubectl -n $(K8S_NS) create secret generic host-keys \
		--from-file=config/host_keys/ed25519_key \
		--from-file=config/host_keys/ed25519_key.pub
