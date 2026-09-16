//go:build windows

package command

import (
	"context"
	"os"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/internal/tty"
)

// watchResize reports f's size whenever it changes, polled every 500ms.
// Windows has no SIGWINCH: polling is the only way to notice a resize.
func watchResize(ctx context.Context, f *os.File) <-chan termsize.Size {
	out := make(chan termsize.Size, 1)
	go func() {
		defer close(out)

		last, err := tty.Size(f)
		if err != nil {
			// If we can't get the size, skip resize monitoring.
			return
		}

		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				size, err := tty.Size(f)
				if err != nil {
					// Can't get size, skip this check.
					continue
				}

				// Only notify if size actually changed.
				if size == last {
					continue
				}
				last = size

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
