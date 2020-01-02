package main

import (
	"github.com/jingweno/upterm/cmd/uptermd/internal/command"
	log "github.com/sirupsen/logrus"
)

func main() {
	if err := command.Root().Execute(); err != nil {
		log.Fatal(err)
	}
}
