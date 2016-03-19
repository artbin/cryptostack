package ppe

import "github.com/dchest/blake2b"

type KeyPool struct {
	pool map[string][]KeyPair
}

type KeyPair struct {
	Pkey *[32]byte
	Skey *[32]byte
}

func NewKeyPool() *KeyPool {
	return &KeyPool{map[string][]KeyPair{}}
}

func (kp KeyPool) GetKeys(id []byte) []KeyPair {
	return kp.pool[string(id)]
}

func (kp *KeyPool) AddKey(pkey, skey *[32]byte) (err error) {
	id, err := KeyID(pkey[:])
	if err != nil {
		return
	}
	kp.pool[string(id)] = append(kp.pool[string(id)], KeyPair{pkey, skey})
	return
}

func KeyID(pkey []byte) (id []byte, err error) {
	hash, err := blake2b.New(&blake2b.Config{Size: 2})
	if err != nil {
		return
	}
	if _, err = hash.Write(pkey); err != nil {
		return
	}
	id = hash.Sum([]byte{})
	return
}
