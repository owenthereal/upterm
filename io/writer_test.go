package io

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MultiWriter(t *testing.T) {
	assert := assert.New(t)

	w1 := bytes.NewBuffer(nil)
	w := NewMultiWriter(1, w1)

	r := bytes.NewBufferString("hello1")
	_, _ = io.Copy(w, r)

	assert.Equal("hello1", w1.String())

	// append w2
	r = bytes.NewBufferString("hello2")
	w2 := bytes.NewBuffer(nil)
	_ = w.Append(w2)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2", w1.String())
	assert.Equal("hello1hello2", w2.String())

	// append w3
	r = bytes.NewBufferString("hello3")
	w3 := bytes.NewBuffer(nil)
	_ = w.Append(w3)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2hello3", w1.String())
	assert.Equal("hello1hello2hello3", w2.String())
	assert.Equal("hello2hello3", w3.String())

	// remove w2
	r = bytes.NewBufferString("hello4")
	w.Remove(w2)
	_, _ = io.Copy(w, r)

	assert.Equal("hello1hello2hello3hello4", w1.String())
	assert.Equal("hello1hello2hello3", w2.String())
	assert.Equal("hello2hello3hello4", w3.String())
}
