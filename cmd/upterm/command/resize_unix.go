//go:build !windows

package command

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
)

// watchResize reports f's size after every SIGWINCH until ctx ends.
func watchResize(ctx context.Context, f *os.File) <-chan termsize.Size {
	out := make(chan termsize.Size, 1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	go func() {
		defer signal.Stop(sig)
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				size, err := tty.Size(f)
				if err != nil {
					continue
				}
				// Coalesce: a burst of resizes only needs the last size.
				select {
				case out <- size:
				default:
					select {
					case <-out:
					default:
					}
					out <- size
				}
			}
		}
	}()
	return out
}
