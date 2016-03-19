package ppe

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

func randomAssocID() (uint32, error) {
	r, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return 0, fmt.Errorf("Random generator error: %s", err)
	}
	return uint32(r.Uint64()), nil
}
