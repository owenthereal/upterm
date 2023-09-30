package io

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func Test_ContextReader(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		r := bytes.NewBufferString("hello1")
		w := bytes.NewBuffer(nil)

		_, _ = io.Copy(w, NewContextReader(context.Background(), r))
		want := "hello1"
		got := w.String()
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("want=%s got=%s:\n%s", want, got, diff)
		}
	})

	t.Run("pass in canceled context", func(t *testing.T) {
		t.Parallel()

		r := readFunc(func(p []byte) (int, error) {
			t.Error("should never get here")
			return 0, nil
		})
		w := bytes.NewBuffer(nil)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := io.Copy(w, NewContextReader(ctx, r))
		want := context.Canceled
		got := err
		if diff := cmp.Diff(want.Error(), got.Error()); diff != "" {
			t.Errorf("want=%s got=%s:\n%s", want, got, diff)
		}
	})

	t.Run("cancel context during copy", func(t *testing.T) {
		t.Parallel()

		r := readFunc(func(p []byte) (int, error) {
			time.Sleep(5 * time.Second) // simulate slow read
			t.Error("should never get here")
			return 0, nil
		})
		w := bytes.NewBuffer(nil)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(1 * time.Second) // cancel ctx before any read
			cancel()
		}()
		_, err := io.Copy(w, NewContextReader(ctx, r))
		want := context.Canceled
		got := err
		if diff := cmp.Diff(want.Error(), got.Error()); diff != "" {
			t.Errorf("want=%s got=%s:\n%s", want, got, diff)
		}
	})

	t.Run("cancel context after copy", func(t *testing.T) {
		t.Parallel()

		ch := make(chan string, 1)
		ch <- "hello2" // feed with one read and then it hangs
		r := readFunc(func(p []byte) (int, error) {
			s := <-ch
			return bytes.NewBufferString(s).Read(p)
		})
		w := bytes.NewBuffer(nil)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(3 * time.Second) // cancel ctx after first read
			cancel()
		}()
		_, err := io.Copy(w, NewContextReader(ctx, r))
		want := context.Canceled
		got := err
		if diff := cmp.Diff(want.Error(), got.Error()); diff != "" {
			t.Errorf("want=%s got=%s:\n%s", want, got, diff)
		}
	})
}

type readFunc func(p []byte) (n int, err error)

func (rf readFunc) Read(p []byte) (n int, err error) { return rf(p) }
