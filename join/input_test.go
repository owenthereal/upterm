package join

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKeysTypedDuringAWaitNeverReachTheNextSession(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	v1 := in.session()
	v1.activate()
	_ = v1.Close()                          // the session ended
	_, _ = pw.Write([]byte("rm -rf ~\r"))   // typed during the wait
	require.Equal(t, keyRetry, <-in.keys()) // the Enter retried; the rest was dropped
	v2 := in.session()
	v2.activate()
	go func() { _, _ = pw.Write([]byte("ok")) }()
	buf := make([]byte, 64)
	n, _ := v2.Read(buf)
	require.Equal(t, "ok", string(buf[:n]))
}

func TestAChunkHandedToAClosingViewIsDropped(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.handing = make(chan struct{}, 1)
	in.start()
	v := in.session()
	v.activate() // nobody reads v, so the next hand-off stays pending
	go func() { _, _ = pw.Write([]byte("lost\r")) }()
	<-in.handing
	require.NoError(t, v.Close())

	_, _ = pw.Write([]byte("\r"))
	require.Equal(t, keyRetry, <-in.keys()) // only this Enter; "lost\r" went nowhere
	select {
	case k := <-in.keys():
		t.Fatalf("the dropped chunk produced key %v", k)
	case <-time.After(50 * time.Millisecond):
	}
	v2 := in.session()
	v2.activate()
	go func() { _, _ = pw.Write([]byte("x")) }()
	b := make([]byte, 8)
	n, _ := v2.Read(b)
	require.Equal(t, "x", string(b[:n]))
}

func TestAnInactiveViewLeavesKeysWithJoin(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	v := in.session() // setup and the Joined line are still in progress
	go func() { _, _ = pw.Write([]byte{0x03}) }()
	require.Equal(t, keyStop, <-in.keys())
	v.activate()
	go func() { _, _ = pw.Write([]byte("x")) }()
	b := make([]byte, 8)
	n, _ := v.Read(b)
	require.Equal(t, "x", string(b[:n])) // the Ctrl-C never reached the view
}

func TestWaitCountsCRLFAsOneEnter(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	_, _ = pw.Write([]byte("\r\n"))
	require.Equal(t, keyRetry, <-in.keys())
	select {
	case k := <-in.keys():
		t.Fatalf("a second key %v from one CRLF", k)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestWaitKeys(t *testing.T) {
	for typed, want := range map[string]waitKey{"\x03": keyStop, "~.": keyLeave, "\r": keyRetry, "\n": keyRetry, "x\x03": keyStop} {
		pr, pw := io.Pipe()
		in := newInput(pr, '~')
		in.start()
		// The reader ends once join takes the keyLeave that the EOF becomes.
		t.Cleanup(func() {
			_ = pw.Close()
			<-in.keys()
		})
		go func() { _, _ = pw.Write([]byte(typed)) }()
		require.Equal(t, want, <-in.keys(), "%q", typed)
	}
}

// Keys typed before "~." count whether they arrive in a read of their own or
// in the same read as the escape: how the reads split them changes nothing.
func TestKeysBeforeAnEscapeInTheSameReadCount(t *testing.T) {
	for typed, want := range map[string][]waitKey{
		"\x03\r~.": {keyStop, keyRetry, keyLeave},
		"\r~.":     {keyRetry, keyLeave},
	} {
		pr, pw := io.Pipe()
		in := newInput(pr, '~')
		in.start()
		t.Cleanup(func() {
			in.stop()
			_ = pw.Close()
		})
		go func() { _, _ = pw.Write([]byte(typed)) }() // one Write, read as one chunk
		for _, k := range want {
			require.Equal(t, k, <-in.keys(), "%q", typed)
		}
	}
}

func TestEOFDuringAWaitIsLeaving(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	require.NoError(t, pw.Close())
	require.Equal(t, keyLeave, <-in.keys())
}

func TestAShortReadKeepsTheRestOfTheChunk(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	v := in.session()
	v.activate()
	go func() {
		_, _ = pw.Write([]byte("hello"))
		_, _ = pw.Write([]byte("!"))
	}()
	var got []byte
	b := make([]byte, 2)
	for len(got) == 0 || got[len(got)-1] != '!' {
		n, err := v.Read(b)
		require.NoError(t, err)
		got = append(got, b[:n]...)
	}
	require.Equal(t, "hello!", string(got))

	// What the view was handed and hasn't delivered goes with it when it
	// closes: neither a later Read nor the keys see it.
	go func() { _, _ = pw.Write([]byte("a\r")) }()
	n, err := v.Read(b[:1])
	require.NoError(t, err)
	require.Equal(t, "a", string(b[:n]))
	require.NoError(t, v.Close())
	n, err = v.Read(b)
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
	go func() { _, _ = pw.Write([]byte{0x03}) }()
	require.Equal(t, keyStop, <-in.keys()) // not the "\r" the view dropped
}

func TestEOFWhileASessionIsActiveReachesIt(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	v := in.session()
	v.activate()
	require.NoError(t, pw.Close())
	_, err := v.Read(make([]byte, 8))
	require.ErrorIs(t, err, io.EOF)
}

func TestEOFTakenByAnAbandonedReadIsStillLeaving(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	v := in.session()
	v.activate()
	// The session has ended for some other reason, and the goroutine its
	// Terminal read Stdin on is still parked in v.Read, its result going to
	// nobody. The test waits for that result only to know the EOF went there
	// before v closes.
	abandoned := make(chan error, 1)
	go func() {
		_, err := v.Read(make([]byte, 8))
		abandoned <- err
	}()
	require.NoError(t, pw.Close())
	require.ErrorIs(t, <-abandoned, io.EOF)
	require.NoError(t, v.Close())
	select {
	case k := <-in.keys():
		require.Equal(t, keyLeave, k)
	case <-time.After(5 * time.Second):
		t.Fatal("the terminal went away, and join was never told")
	}
}

func TestEOFASessionNeverTookIsLeaving(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	v := in.session()
	v.activate()
	require.NoError(t, pw.Close())
	<-in.ended // the reader has the EOF, and waits for v to close
	require.NoError(t, v.Close())
	require.Equal(t, keyLeave, <-in.keys())
}

func TestEverySessionAfterTheEndSeesItAtOnce(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	gone := errors.New("the terminal went away")
	require.NoError(t, pw.CloseWithError(gone))
	require.Equal(t, keyLeave, <-in.keys())

	v := in.session()
	_, err := v.Read(make([]byte, 8)) // inactive, and still not blocked
	require.ErrorIs(t, err, gone)
	v.activate()
	_, err = v.Read(make([]byte, 8))
	require.ErrorIs(t, err, gone)
}

func TestAnEscapeStartedBeforeASessionDoesNotCarryOver(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	_, _ = pw.Write([]byte("\r~")) // Enter, then the first half of "~."
	require.Equal(t, keyRetry, <-in.keys())
	v := in.session()
	v.activate()
	require.NoError(t, v.Close())
	_, _ = pw.Write([]byte(".\r"))
	require.Equal(t, keyRetry, <-in.keys()) // the "." was dropped, not the end of a "~."
}

// A stopped reader returns at once from wherever it holds what it read, and
// otherwise as the Read in progress returns, dropping what that Read took.
func TestAStoppedReaderDeliversNothing(t *testing.T) {
	// reader starts a reader of r whose return closes exited.
	reader := func(r io.Reader, handing chan struct{}) *input {
		in := newInput(r, '~')
		in.exited = make(chan struct{})
		in.handing = handing
		in.start()
		return in
	}
	// stop stops in, and fails the test if its reader doesn't return.
	stop := func(t *testing.T, in *input) {
		t.Helper()
		in.stop()
		select {
		case <-in.exited:
		case <-time.After(5 * time.Second):
			t.Fatal("the reader outlived its stop")
		}
	}
	t.Run("holding a key join didn't take", func(t *testing.T) {
		pr, pw := io.Pipe()
		in := reader(pr, nil)
		// Two Enters in one chunk: join takes the first, and has stopped taking
		// keys by the second, which the reader holds.
		_, _ = pw.Write([]byte("\r\r"))
		require.Equal(t, keyRetry, <-in.keys())
		stop(t, in)
	})
	t.Run("holding a chunk a session didn't take", func(t *testing.T) {
		pr, pw := io.Pipe()
		handing := make(chan struct{}, 1)
		in := reader(pr, handing)
		in.session().activate() // nobody reads it
		_, _ = pw.Write([]byte("x"))
		<-handing
		stop(t, in)
	})
	t.Run("holding the end of the input", func(t *testing.T) {
		pr, pw := io.Pipe()
		in := reader(pr, nil)
		in.session().activate() // nobody reads it, so the reader waits for it to close
		require.NoError(t, pw.Close())
		<-in.ended
		stop(t, in)
	})
	t.Run("in a Read", func(t *testing.T) {
		pr, pw := io.Pipe()
		input := newWatchedInput(pr)
		in := reader(input, nil)
		v := in.session()
		v.activate()
		got := make(chan string, 1)
		go func() { // the session, waiting for its keys
			b := make([]byte, 8)
			n, _ := v.Read(b)
			got <- string(b[:n])
		}()
		<-input.reading
		in.stop()
		_, _ = pw.Write([]byte("x")) // taken by the Read in progress
		stop(t, in)
		require.Empty(t, input.reading, "a stopped reader read again")
		require.NoError(t, v.Close())
		require.Empty(t, <-got, "a stopped reader handed a chunk to a session")
	})
}
