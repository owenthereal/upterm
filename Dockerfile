FROM golang:latest as builder

WORKDIR $GOPATH/src/github.com/jingweno/upterm
COPY . .
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN make install

# Prepare for image
FROM ubuntu:18.04
MAINTAINER Owen Ou

RUN apt-get update && apt-get install -y less curl iputils-ping
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /go/bin/uptermd /usr/bin/uptermd

EXPOSE 22

ENTRYPOINT ["uptermd"]
