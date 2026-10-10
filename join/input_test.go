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
	require.NoError(t, v.Close())
	select {
	case k := <-in.keys():
		t.Fatalf("the session took the EOF, yet join got key %v", k)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEOFASessionNeverTookIsLeaving(t *testing.T) {
	pr, pw := io.Pipe()
	in := newInput(pr, '~')
	in.start()
	v := in.session()
	v.activate()
	require.NoError(t, pw.Close())
	<-in.ended // the reader has the EOF, and v is where it is going
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
