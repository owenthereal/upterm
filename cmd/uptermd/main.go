package main

import (
	"os"

	"github.com/heroku/rollrus"
	"github.com/owenthereal/upterm/cmd/uptermd/command"
	log "github.com/sirupsen/logrus"
)

func main() {
	logger := log.New()
	token := os.Getenv("ROLLBAR_ACCESS_TOKEN")
	if token != "" {
		logger.Info("Using Rollbar for error reporting")
		defer rollrus.ReportPanic(token, "uptermd.upterm.dev")
		logger.AddHook(rollrus.NewHook(token, "uptermd.upterm.dev"))
	}

	if err := command.Root(logger).Execute(); err != nil {
		logger.Fatal(err)
	}
}
