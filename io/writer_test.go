package io

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_MultiWriter(t *testing.T) {
	t.Parallel()

	w1 := bytes.NewBuffer(nil)
	w := NewMultiWriter(w1)

	r := bytes.NewBufferString("hello1")
	io.Copy(w, r)

	want := "hello1"
	got := w1.String()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("want=%s got=%s:\n%s", want, got, diff)
	}

	// append w2
	r = bytes.NewBufferString("hello2")
	w2 := bytes.NewBuffer(nil)
	w.Append(w2)
	io.Copy(w, r)

	want = "hello1hello2"
	got = w1.String()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("want=%s got=%s:\n%s", want, got, diff)
	}

	want = "hello1hello2" // new writer has the last write
	got = w2.String()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("want=%s got=%s:\n%s", want, got, diff)
	}

	// remove w2
	r = bytes.NewBufferString("hello3")
	w.Remove(w2)
	io.Copy(w, r)

	want = "hello1hello2hello3"
	got = w1.String()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("want=%s got=%s:\n%s", want, got, diff)
	}

	want = "hello1hello2" // removed writer doesn't have the latest write
	got = w2.String()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("want=%s got=%s:\n%s", want, got, diff)
	}
}
