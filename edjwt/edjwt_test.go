package edjwt

import (
	"testing"

	"github.com/ArtemKulyabin/cryptostack"
)

func TestJwt(t *testing.T) {
	skey, err := cryptostack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	token := New()
	_, err = token.SignedString(skey)
	if err != nil {
		t.Fatal(err)
	}
}
