package main

import (
	"compress/gzip"
	"io"
	"os"

	"github.com/owenthereal/upterm/cmd/upterm/command"
	"github.com/owenthereal/upterm/internal/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra/doc"
)

func main() {
	rootCmd := command.Root()

	if err := doc.GenMarkdownTree(rootCmd, "./docs"); err != nil {
		log.Fatal(err)
	}

	header := &doc.GenManHeader{
		Title:   "UPTERM",
		Section: "1",
		Source:  "Upterm " + version.String(),
		Manual:  "Upterm Manual",
	}
	if err := doc.GenManTree(rootCmd, header, "./etc/man/man1"); err != nil {
		log.Fatal(err)
	}

	if err := rootCmd.GenBashCompletionFile("./etc/completion/upterm.bash_completion.sh"); err != nil {
		log.Fatal(err)
	}
	if err := rootCmd.GenZshCompletionFile("./etc/completion/upterm.zsh_completion"); err != nil {
		log.Fatal(err)
	}
}

func compressFile(filename string) error {
	// Open the original file
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create the compressed file
	compressedFilename := filename + ".gz"
	compressedFile, err := os.Create(compressedFilename)
	if err != nil {
		return err
	}
	defer compressedFile.Close()

	// Create gzip writer
	gzipWriter := gzip.NewWriter(compressedFile)
	defer gzipWriter.Close()

	// Copy file content to gzip writer
	_, err = io.Copy(gzipWriter, file)
	if err != nil {
		return err
	}

	// Remove the original uncompressed file
	return os.Remove(filename)
}
