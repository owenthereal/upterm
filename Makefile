.PHONY: build install docker k8s

build:
	go build -o build/upterm ./cmd/upterm/...
	go build -o build/uptermd ./cmd/uptermd/...

install:
	go install ./cmd/...

docker:
	docker build -t jingweno/uptermd . && docker push jingweno/uptermd

k8s:
	kubectl apply -f config/uptermd.yml
