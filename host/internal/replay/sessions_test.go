package replay

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	uio "github.com/owenthereal/upterm/io"
)

// The sessions in testdata/sessions are what programs wrote, each recorded
// from a pane of 80x24 under the TERM its name holds: vim 9.2, by xterm's,
// tmux's and Ghostty's TERMs, Neovim, zsh with oh-my-zsh, as under xterm's
// TERM and as under tmux's, where it sends a screen title string at every
// prompt, bash, less, man under tmux's TERM, as in a session hosted inside
// tmux, htop 3.5, by xterm's and tmux's TERMs, and tmux run inside the
// session. A join at every 97th byte of each renders, once one has, and one
// does: the joins before it, made as the program starts, before its screen
// holds a cell the render could print REP's character on, may fall back on
// that alone. A joiner given the render and the rest of the stream ends as
// the session's terminal does, both reading the screen title strings as tmux
// does under tmux's TERM.
func TestReplayRendersRecordedSessions(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "sessions", "*.raw"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			stream, err := os.ReadFile(f)
			require.NoError(t, err)
			_, term, _ := strings.Cut(strings.TrimSuffix(name, ".raw"), ".")
			read := func(p []byte) string { return string(p) }
			if screenTerm(term) {
				read = func(p []byte) string { return tmuxReads(string(p)) }
			}
			sizes := []uio.SizeEvent{event(1, 0, 80, 24)}
			rendered := false
			for at := 97; at < len(stream)+97; at += 97 {
				at = min(at, len(stream))
				joined, fellBack := fanOut(t, NewForTerm(term), stream[:at], sizes, uio.DefaultReplayBytes)
				if ie := (*IneligibleError)(nil); !rendered && errors.As(fellBack, &ie) && ie.State == "REP's last character" {
					continue
				}
				require.NoError(t, fellBack, "at %d", at)
				rendered = true
				a, aHist := newReference(80, 24)
				aNames := watchTitle(a)
				_, _ = a.WriteString(read(stream))
				b, bHist := newReference(80, 24)
				bNames := watchTitle(b)
				_, _ = b.WriteString(read(append(joined, stream[at:]...)))
				require.Empty(t, sameState(a, b, *aHist, *bHist, *aNames, *bNames), "at %d", at)
			}
			require.True(t, rendered, "no join rendered")
		})
	}
}
