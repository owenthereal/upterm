// Command upterm-test is upterm composed with the test extension, for tests
// that drive the built CLI.
package main

import (
	"os"

	"github.com/owenthereal/upterm/cmd/upterm/command"
	"github.com/owenthereal/upterm/internal/testhelpers/testextension"
)

func main() {
	os.Exit(command.MainWith(testextension.New()))
}
