package memlistener

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_MemListener_Listen(t *testing.T) {
	t.Parallel()

	sln, err := Listen("mem", "path_foo")
	if err != nil {
		t.Fatal(err)
	}
	defer sln.Close()

	// error on listener with the same address
	_, err = Listen("mem", "path_foo")
	want, got := errListenerAlreadyExist{"path_foo"}, err
	if !strings.Contains(got.Error(), want.Error()) {
		t.Fatalf("got doesn't contain want (-want +got):\n%s", cmp.Diff(want.Error(), got.Error()))
	}
}

func Test_MemListener_Dial(t *testing.T) {
	t.Parallel()

	_, err := Dial("mem", "not_exist")
	want, got := errListenerNotFound{"not_exist"}, err
	if !strings.Contains(got.Error(), want.Error()) {
		t.Fatalf("got doesn't contain want (-want +got):\n%s", cmp.Diff(want.Error(), got.Error()))
	}
}

func Test_MemListener_RemoveListener(t *testing.T) {
	t.Parallel()

	sln, err := Listen("mem", "path_bar")
	if err != nil {
		t.Fatal(err)
	}

	sln2, ok := listeners.Load("path_bar")
	if !ok {
		t.Fatal("listener path not found")
	}

	if want, got := sln, sln2; want != got {
		t.Fatalf("listeners not equal: want=%v, got=%v", want, got)
	}

	if err := sln.Close(); err != nil {
		t.Fatal(err)
	}

	_, ok = listeners.Load("path_bar")
	if ok {
		t.Fatal("listener path shouldn't be found")
	}
}
