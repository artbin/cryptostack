package ppe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

type ServerPeer struct {
	S            *[32]byte
	Ss           *[32]byte
	C            *[32]byte
	keypool      *KeyPool
	clientpool   *KeyPool
	handShakeBuf []byte
	peer
}

func NewServerPeer(tr Transport, w io.Writer, r io.Reader, keypool *KeyPool, clientpool *KeyPool) Peer {
	peer := &ServerPeer{}
	peer.w = w
	peer.r = r
	peer.keypool = keypool
	peer.clientpool = clientpool
	peer.sharedKey = &[32]byte{}
	peer.tr = tr
	return peer
}

func (peer *ServerPeer) State() State {
	return State{peer.C, peer.assocID, peer.nonce}
}

func (peer *ServerPeer) Close() error {
	zero(peer.S)
	zero(peer.Ss)
	zero(peer.C)
	peer.peer.Close()
	return nil
}

func (peer *ServerPeer) HandShake() error {
	if peer.handshake {
		return nil
	}
	peer.handshake = true

	buf, err := peer.ReadBlock()
	if err != nil {
		return err
	}

	var EC [32]byte

	copy(EC[:], buf[2:34])

	cryptbox := buf[34:]

	text := []byte{}
	ok := false
	var Snonce Nonce
	for _, keypair := range peer.keypool.GetKeys(buf[:2]) {
		peer.S = keypair.Pkey
		peer.Ss = keypair.Skey
		Snonce, err = NewNonce(append(EC[:], peer.S[:]...))
		if err != nil {
			return err
		}
		box.Precompute(peer.sharedKey, &EC, peer.Ss)

		peer.initNonce = Snonce

		text, ok = box.OpenAfterPrecomputation(nil, cryptbox, peer.initNonce.Read(peer.getNonce()), peer.sharedKey)
		if ok {
			break
		}
	}
	if !ok {
		return errors.New("Decryption failed")
	}

	if peer.tr == Packet {
		peer.handShakeBuf = text
		return nil
	}

	Ctag := text

	ES, ESs, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	Stag := make([]byte, 32)

	_, err = rand.Reader.Read(Stag)
	if err != nil {
		return err
	}

	message := append(append(ES[:], Ctag...), Stag...)

	cryptbox = box.Seal(nil, message, Snonce.Read(peer.getNonce()), &EC, peer.Ss) // Box[ES, Ctag, Stag](Ss -> EC)

	_, err = peer.WriteBlock(cryptbox)
	if err != nil {
		return err
	}

	buf, err = peer.ReadBlock()
	if err != nil {
		return err
	}

	cryptbox = buf

	nonce := Snonce.Read(peer.getNonce())

	text, ok = box.Open(nil, cryptbox, nonce, &EC, ESs)
	if !ok {
		return errors.New("Decryption failed")
	}

	C := [32]byte{}

	copy(C[:], text[:32])

	vv, ok := box.Open(nil, text[32:], nonce, &C, peer.Ss)
	if !ok {
		return errors.New("Decryption failed")
	}

	if !bytes.Equal(vv[:32], EC[:]) {
		return errors.New("Bad EC")
	}

	stag := vv[32:]

	if !bytes.Equal(Stag, stag) {
		return errors.New("Bad Stag")
	}

	peer.C = &C

	box.Precompute(peer.sharedKey, &EC, ESs)

	peer.initNonce = Snonce

	return nil
}

func (peer *ServerPeer) Write(p []byte) (n int, err error) {
	if peer.tr == Packet {
		return peer.peer.Write([]byte{}, p)
	}
	err = peer.HandShake()
	if err != nil {
		return 0, err
	}
	return peer.peer.Write([]byte{}, p)
}

func (peer *ServerPeer) Read(p []byte) (n int, err error) {
	err = peer.HandShake()
	if err != nil {
		return 0, err
	}
	if peer.tr == Packet {
		if len(peer.handShakeBuf) == 0 {
			return peer.peer.Read([]byte{}, p)
		}
		copy(p, peer.handShakeBuf)
		n, err = len(peer.handShakeBuf), nil
		peer.handShakeBuf = []byte{}
		return
	}
	return peer.peer.Read([]byte{}, p)
}
