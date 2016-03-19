package ppe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type Transport bool

const (
	Stream Transport = true
	Packet           = false
)

type Peer interface {
	io.ReadWriteCloser
	HandShake() error
	State() State
}

type State struct {
	PeerKey *[32]byte
	AssocID uint32
	Nonce   uint32
}

type peer struct {
	w       io.Writer
	r       io.Reader
	assocID uint32
	nonce   uint32
	window  uint32

	initNonce Nonce
	sharedKey *[32]byte

	handshake bool
	tr        Transport
}

func (peer *peer) getNonce() uint32 {
	n := peer.nonce
	peer.nonce++
	return n
}

func (peer *peer) Close() error {
	zero(peer.sharedKey)
	return nil
}

func (peer *peer) Write(head, p []byte) (n int, err error) {
	cryptbox := box.SealAfterPrecomputation(nil, p, peer.initNonce.Read(peer.getNonce()), peer.sharedKey)
	return peer.WriteBlock(append(head, cryptbox...))
}

func (peer *peer) Read(head, p []byte) (n int, err error) {
	buf, err := peer.ReadBlock()
	if err != nil {
		return 0, err
	}
	copy(head, buf)
	buf = buf[len(head):]
	msg, ok := box.OpenAfterPrecomputation(nil, buf, peer.initNonce.Read(peer.getNonce()), peer.sharedKey)
	if !ok {
		return 0, errors.New("Decryption failed")
	}
	copy(p, msg)
	return len(msg), nil
}

func (peer *peer) WriteBlock(p []byte) (n int, err error) {
	outbuf := new(bytes.Buffer)
	binary.Write(outbuf, binary.BigEndian, peer.assocID)
	binary.Write(outbuf, binary.BigEndian, peer.nonce-1)
	binary.Write(outbuf, binary.BigEndian, uint16(len(p)))
	outbuf.Write(p)
	return peer.w.Write(outbuf.Bytes())
}

func (peer *peer) ReadBlock() (buf []byte, err error) {
	sizebuf := make([]byte, 10)
	_, err = peer.r.Read(sizebuf)
	if err != nil {
		return nil, err
	}
	inbuf := bytes.NewBuffer(sizebuf)
	size := uint16(0)
	binary.Read(inbuf, binary.BigEndian, &peer.assocID)
	binary.Read(inbuf, binary.BigEndian, &peer.nonce)

	window := peer.window - 1
	nonce := peer.nonce
	if nonce >= window+1 && nonce <= window+64 {

	}
	binary.Read(inbuf, binary.BigEndian, &size)
	buf = make([]byte, size)
	_, err = io.ReadFull(peer.r, buf)
	if err != nil {
		return nil, err
	}
	return
}
