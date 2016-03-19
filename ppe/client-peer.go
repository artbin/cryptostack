package ppe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type ClientPeer struct {
	C            *[32]byte
	Cs           *[32]byte
	S            *[32]byte
	EC           *[32]byte
	ECs          *[32]byte
	handShakeBuf []byte
	peer
}

func NewClientPeer(tr Transport, w io.Writer, r io.Reader, pkey *[32]byte, skey *[32]byte, serverpkey *[32]byte) Peer {
	peer := &ClientPeer{}
	peer.w = w
	peer.r = r
	peer.C = pkey
	peer.Cs = skey
	peer.S = serverpkey
	peer.sharedKey = &[32]byte{}
	peer.tr = tr
	peer.assocID, _ = randomAssocID()
	peer.nonce = 1
	return peer
}

func (peer *ClientPeer) State() State {
	return State{peer.S, peer.assocID, peer.nonce}
}

func (peer *ClientPeer) Close() error {
	zero(peer.C)
	zero(peer.Cs)
	zero(peer.S)
	zero(peer.EC)
	zero(peer.ECs)
	peer.peer.Close()
	return nil
}

func (peer *ClientPeer) HandShake() error {
	if peer.handshake {
		return nil
	}
	peer.handshake = true
	EC, ECs, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	if peer.C == nil || peer.Cs == nil {
		peer.C, peer.Cs, err = box.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
	}

	Cnonce, err := NewNonce(append(EC[:], peer.S[:]...))
	if err != nil {
		return err
	}

	box.Precompute(peer.sharedKey, peer.S, ECs)

	peer.initNonce = Cnonce

	id, err := KeyID(peer.S[:])
	if err != nil {
		return err
	}

	if peer.tr == Packet {
		peer.handShakeBuf = append(id, EC[:]...)
		return nil
	}

	Ctag := make([]byte, 32)

	if _, err = rand.Reader.Read(Ctag); err != nil {
		return err
	}

	cryptbox := box.Seal(nil, Ctag, Cnonce.Read(peer.getNonce()), peer.S, ECs) // Box[Ctag](ECs -> S)

	cryptbox = append(append(id, EC[:]...), cryptbox...)

	if _, err = peer.WriteBlock(cryptbox); err != nil {
		return err
	}

	buf, err := peer.ReadBlock()
	if err != nil {
		return err
	}

	cryptbox = buf

	text, ok := box.Open(nil, cryptbox, Cnonce.Read(peer.getNonce()), peer.S, ECs)
	if !ok {
		return errors.New("Decryption failed")
	}

	ES := [32]byte{}

	copy(ES[:], text[:32])

	ctag := text[32:64]

	if !bytes.Equal(Ctag, ctag) {
		return errors.New("Bad Ctag")
	}

	Stag := text[64:]

	message := peer.C[:]

	nonce := Cnonce.Read(peer.getNonce())

	v := box.Seal(nil, append(EC[:], Stag...), nonce, peer.S, peer.Cs) // V = Box[EC, Stag](Cs -> S)

	message = append(message, v...)

	cryptbox = box.Seal(nil, message, nonce, &ES, ECs) // Box[C,V](ECs -> ES)

	if _, err = peer.WriteBlock(cryptbox); err != nil {
		return err
	}

	box.Precompute(peer.sharedKey, &ES, ECs)

	peer.initNonce = Cnonce

	return nil
}

func (peer *ClientPeer) Write(p []byte) (n int, err error) {
	err = peer.HandShake()
	if err != nil {
		return 0, err
	}
	if peer.tr == Packet {
		if len(peer.handShakeBuf) == 0 {
			return peer.peer.Write([]byte{}, p)
		}
		buf := peer.handShakeBuf
		peer.handShakeBuf = []byte{}
		n, err = peer.peer.Write(buf, p)
		return
	}
	return peer.peer.Write([]byte{}, p)
}

func (peer *ClientPeer) Read(p []byte) (n int, err error) {
	if peer.tr == Packet {
		return peer.peer.Read([]byte{}, p)
	}
	err = peer.HandShake()
	if err != nil {
		return 0, err
	}
	return peer.peer.Read([]byte{}, p)
}
