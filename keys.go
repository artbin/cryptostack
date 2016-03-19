package cryptostack

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"github.com/agl/ed25519"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/pbkdf2"
)

type Pkey struct {
	Alg   string `json:"alg"`
	ID    []byte `json:"id"`
	Curve struct {
		Pkey []byte `json:"pkey"`
	} `json:"curve"`
	Ed struct {
		Pkey []byte `json:"pkey"`
	} `json:"ed"`

	curvePkey *[32]byte
	edPkey    *[32]byte
}

func NewPkey(curvePkey *[32]byte, edPkey *[32]byte) *Pkey {
	pkey := &Pkey{Alg: "curve25519-ed25519"}
	pkey.Curve.Pkey = curvePkey[:]
	pkey.Ed.Pkey = edPkey[:]
	pkey.curvePkey = curvePkey
	pkey.edPkey = edPkey
	return pkey
}

func (pkey Pkey) GetCurveKey() *[32]byte {
	if pkey.curvePkey == nil {
		pkey.curvePkey = &[32]byte{}
		copy(pkey.curvePkey[:], pkey.Curve.Pkey)
	}
	curvePkey := *pkey.curvePkey
	return &curvePkey
}

func (pkey Pkey) GetEdKey() *[32]byte {
	if pkey.edPkey == nil {
		pkey.edPkey = &[32]byte{}
		copy(pkey.edPkey[:], pkey.Ed.Pkey)
	}
	edPkey := *pkey.edPkey
	return &edPkey
}

func (pkey *Pkey) Verify(message []byte, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("Signature size not equal 64")
	}
	s := &[64]byte{}
	copy(s[:], sig)
	if !ed25519.Verify(pkey.GetEdKey(), message, s) {
		return errors.New("Verify failed")
	}
	return nil
}

type Skey struct {
	Alg string `json:"alg"`
	ID  []byte `json:"id"`
	Kdf struct {
		Alg    string `json:"alg"`
		Salt   []byte `json:"salt"`
		Rounds int    `json:"rounds"`
	} `json:"kdf"`
	Curve struct {
		Pkey []byte `json:"pkey"`
		Skey []byte `json:"skey"`
	} `json:"curve"`
	Ed struct {
		Pkey []byte `json:"pkey"`
		Skey []byte `json:"skey"`
	} `json:"ed"`
	Checksum []byte `json:"checksum"`

	pkey      *Pkey
	curveSkey *[32]byte
	edSkey    *[64]byte
}

func (skey Skey) GetPkey() *Pkey {
	return skey.pkey
}

func (skey Skey) GetCurveKey() *[32]byte {
	curveSkey := *skey.curveSkey
	return &curveSkey
}

func (skey Skey) GetEdKey() *[64]byte {
	edSkey := *skey.edSkey
	return &edSkey
}

func (skey *Skey) Sign(message []byte) []byte {
	return ed25519.Sign(skey.edSkey, message)[:]
}

func (skey *Skey) Encrypt(password []byte) {
	skey.xor(password)
}

func (skey *Skey) Decrypt(password []byte) error {
	skey.xor(password)
	curvePkey := &[32]byte{}
	edPkey := &[32]byte{}
	copy(curvePkey[:], skey.Curve.Pkey)
	copy(edPkey[:], skey.Ed.Pkey)
	skey.pkey = NewPkey(curvePkey, edPkey)
	skey.pkey.ID = skey.ID

	skey.curveSkey = &[32]byte{}
	skey.edSkey = &[64]byte{}
	copy(skey.curveSkey[:], skey.Curve.Skey)
	copy(skey.edSkey[:], skey.Ed.Skey)

	if !bytes.Equal(skey.Checksum, skey.checksum()) {
		return errors.New("Bad checksum")
	}
	return nil
}

func (skey *Skey) checksum() []byte {
	checksum := blake2b.New256()
	checksum.Write(skey.ID)
	checksum.Write(skey.Curve.Skey)
	checksum.Write(skey.Ed.Skey)
	return checksum.Sum([]byte{})
}

func (skey *Skey) xor(password []byte) {
	s := skey
	l := len(s.ID) + len(s.Ed.Pkey) + len(s.Ed.Skey) + len(s.Curve.Pkey) + len(s.Curve.Skey) + len(s.Checksum)
	dk := pbkdf2.Key(password, s.Kdf.Salt, s.Kdf.Rounds, l, blake2b.New512)
	v := [][]byte{s.ID, s.Curve.Pkey, s.Curve.Skey, s.Ed.Pkey, s.Ed.Skey, s.Checksum}
	j := 0
	for k := range v {
		for i := range v[k] {
			v[k][i] = v[k][i] ^ dk[j]
			j++
		}
	}
}

func GenerateKey() (*Skey, error) {
	curvePkey, curveSkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	edPkey, edSkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pkey := NewPkey(curvePkey, edPkey)
	skey := Skey{pkey: pkey, curveSkey: curveSkey, edSkey: edSkey}
	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}
	rounds := 4096
	id := make([]byte, 8)
	_, err = rand.Read(id)
	if err != nil {
		return nil, err
	}
	skey.Alg = pkey.Alg
	pkey.ID = id
	skey.ID = pkey.ID
	skey.Kdf.Alg = "pbkdf2-blake2b"
	skey.Kdf.Rounds = rounds
	skey.Kdf.Salt = salt

	skey.Curve.Pkey = pkey.Curve.Pkey
	skey.Curve.Skey = curveSkey[:]

	skey.Ed.Pkey = pkey.Ed.Pkey
	skey.Ed.Skey = edSkey[:]

	skey.Checksum = skey.checksum()

	return &skey, nil
}

type Signature struct {
	Alg  string `json:"alg"`
	Pkey *Pkey  `json:"pkey"`
	Hash []byte `json:"hash"`
	Sig  []byte `json:"sig"`
}

func NewSignature(pkey *Pkey) *Signature {
	sig := &Signature{}
	sig.Alg = "ed25519"
	sig.Pkey = pkey
	return sig
}

func (sig *Signature) Sign(skey *Skey, r io.Reader) error {
	hash, err := sig.computeHash(r)
	if err != nil {
		return err
	}
	sig.Hash = hash
	sig.Sig = skey.Sign(sig.Hash)
	return nil
}

func (sig *Signature) Verify(r io.Reader) error {
	hash, err := sig.computeHash(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig.Hash, hash) {
		return errors.New("Bad checksum")
	}
	return sig.Pkey.Verify(sig.Hash, sig.Sig)
}

func (sig *Signature) computeHash(r io.Reader) ([]byte, error) {
	hash := blake2b.New512()
	_, err := io.Copy(hash, r)
	if err != nil {
		return nil, err
	}
	return hash.Sum([]byte{}), nil
}
