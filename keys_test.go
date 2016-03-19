package cryptostack

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestKeys(t *testing.T) {
	password := "12345"

	skey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	skey.Encrypt([]byte(password))
	buf, err := json.Marshal(skey)
	if err != nil {
		t.Fatal(err)
	}
	err = skey.Decrypt([]byte(password))
	if err != nil {
		t.Fatal(err)
	}

	skey2 := Skey{}
	err = json.Unmarshal(buf, &skey2)
	if err != nil {
		t.Fatal(err)
	}

	err = skey2.Decrypt([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	buf, err = json.Marshal(skey)
	if err != nil {
		t.Fatal(err)
	}

	buf, err = json.Marshal(skey2.GetPkey())
	if err != nil {
		t.Fatal(err)
	}

	pkey := Pkey{}

	err = json.Unmarshal(buf, &pkey)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("hello")

	sig := skey2.Sign(message)

	err = pkey.Verify(message, sig)
	if err != nil {
		t.Fatal(err)
	}

	signature := NewSignature(&pkey)

	err = signature.Sign(&skey2, bytes.NewBuffer(message))
	if err != nil {
		t.Fatal(err)
	}

	err = signature.Verify(bytes.NewBuffer(message))
	if err != nil {
		t.Fatal(err)
	}
}
