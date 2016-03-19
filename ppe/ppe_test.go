package ppe

import (
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestPpe(t *testing.T) {
	S, Ss, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cpeerPipeR, cpeerPipeW := io.Pipe()
	speerPipeR, speerPipeW := io.Pipe()

	cpeer := NewClientPeer(Stream, speerPipeW, cpeerPipeR, nil, nil, S)

	keypool := NewKeyPool()

	keypool.AddKey(S, Ss)

	clientpool := NewKeyPool()

	clientpool.AddKey(S, nil)

	speer := NewServerPeer(Stream, cpeerPipeW, speerPipeR, keypool, clientpool)

	go func() {
		text := make([]byte, 1024)

		n, err := speer.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		if string(text[:n]) != "hello" {
			t.Fatal("hello")
		}

		n, err = speer.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		if string(text[:n]) != "hello2" {
			t.Fatal("hello2")
		}

		_, err = speer.Write([]byte("world"))
		if err != nil {
			t.Fatal(err)
		}

		n, err = speer.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		if string(text[:n]) != "client" {
			t.Fatal("client")
		}

		_, err = speer.Write([]byte("server"))
		if err != nil {
			t.Fatal(err)
		}
	}()

	_, err = cpeer.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = cpeer.Write([]byte("hello2"))
	if err != nil {
		t.Fatal(err)
	}

	text := make([]byte, 1024)

	n, err := cpeer.Read(text)
	if err != nil {
		t.Fatal(err)
	}
	if string(text[:n]) != "world" {
		t.Fatal("world")
	}

	_, err = cpeer.Write([]byte("client"))
	if err != nil {
		t.Fatal(err)
	}

	n, err = cpeer.Read(text)
	if err != nil {
		t.Fatal(err)
	}
	if string(text[:n]) != "server" {
		t.Fatal("server")
	}
}
