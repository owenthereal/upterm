package api

import (
	"testing"

	"github.com/golang/protobuf/proto"
)

func Test_EncodeDecodeIdentifier(t *testing.T) {
	want := &Identifier{
		Id:       "owen",
		Type:     Identifier_CLIENT,
		NodeAddr: "127.0.0.1:22",
	}

	str, err := EncodeIdentifier(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecodeIdentifier(str)
	if err != nil {
		t.Fatal(err)
	}

	if !proto.Equal(want, got) {
		t.Errorf("Encode/decode failed, want=%s got=%s", want, got)
	}
}
