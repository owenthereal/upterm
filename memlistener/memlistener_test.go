package memlistener

import (
	"testing"
)

func Test_MemListener_RemoveListener(t *testing.T) {
	sln, err := Listen("mem", "path")
	if err != nil {
		t.Fatal(err)
	}

	if want, got := 1, len(listeners); want != got {
		t.Fatalf("number of listeners is incorrect: want=%d, got=%d", want, got)
	}

	if err := sln.Close(); err != nil {
		t.Fatal(err)
	}

	if want, got := 0, len(listeners); want != got {
		t.Fatalf("number of listeners is incorrect: want=%d, got=%d", want, got)
	}
}
