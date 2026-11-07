package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/owenthereal/upterm/internal/capacity"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "helper" {
		if len(os.Args) != 4 {
			return fmt.Errorf("helper requires host ID and active flag")
		}
		id, err := strconv.Atoi(os.Args[2])
		if err != nil {
			return err
		}
		active, err := strconv.ParseBool(os.Args[3])
		if err != nil {
			return err
		}
		return capacity.Helper(ctx, os.Stdin, os.Stdout, id, active)
	}
	manifest := flag.String("manifest", "", "explicit bounded-run manifest JSON")
	phase := flag.String("phase", "", "explicit phase JSON")
	validate := flag.Bool("validate", false, "validate only; never dial")
	flag.Parse()
	if *manifest == "" || *phase == "" {
		return fmt.Errorf("both -manifest and -phase are required")
	}
	m, err := os.Open(*manifest)
	if err != nil {
		return err
	}
	defer func() { _ = m.Close() }()
	p, err := os.Open(*phase)
	if err != nil {
		return err
	}
	defer func() { _ = p.Close() }()
	cfg, err := capacity.Decode(m, p)
	if err != nil {
		return err
	}
	if *validate {
		_, err = fmt.Fprintln(os.Stdout, `{"event":"validated","dialed":false}`)
		return err
	}
	_, err = capacity.Run(ctx, cfg, os.Stdout)
	return err
}
