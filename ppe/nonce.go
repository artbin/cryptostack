package ppe

import (
	"math/big"

	"github.com/dchest/blake2b"
)

type Nonce struct {
	*big.Int
}

func NewNonce(v []byte) (nonce Nonce, err error) {
	nonce = Nonce{}
	hash, err := blake2b.New(&blake2b.Config{Size: 24})
	if err != nil {
		return
	}
	if _, err = hash.Write(v); err != nil {
		return
	}
	n := big.NewInt(0)
	n.SetBytes(hash.Sum([]byte{}))
	nonce.Int = n
	return
}

func (n Nonce) Read(delta uint32) *[24]byte {
	var nonce [24]byte
	d := big.NewInt(0)
	d.SetUint64(uint64(delta))
	d.Add(n.Int, d)
	copy(nonce[:], d.Bytes())
	return &nonce
}
