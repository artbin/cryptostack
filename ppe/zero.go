package ppe

func zero(mem *[32]byte) {
	var z [32]byte
	copy(mem[:], z[:])
}
