package lrp

// This is based off of NXP document 12304

type LrpMultiCipher struct {
	MainKey []byte
	M       int      // Nibble Size
	P       [][]byte // Plaintexts
}

// Creates a new multi-cipher with a given nibble size
func NewMultiCipher(key []byte, nibbleSize int) *LrpMultiCipher {
	lrp := LrpMultiCipher{
		MainKey: key,
		M:       nibbleSize,
		P:       [][]byte{},
	}

	lrp.Reset()

	return &lrp
}

// Create a multi-cipher with the standard nibble size
func NewStandardMultiCipher(key []byte) *LrpMultiCipher {
	return NewMultiCipher(key, 4)
}

// Recalculates all of the shared plaintexts of the multi-cipher
func (lrp *LrpMultiCipher) Reset() {
	// Algorithm 1 (pg. 5)
	numPlaintexts := 1 << (lrp.M)
	lrp.P = make([][]byte, numPlaintexts)

	h := encryptWith(lrp.MainKey, upper)
	for i := 0; i < numPlaintexts; i++ {
		lrp.P[i] = encryptWith(h, lower)
		h = encryptWith(h, upper)
	}
}

// Generates a cipher with the specific key number from the multi-cypher.
func (lrp LrpMultiCipher) Cipher(idx int) *LrpCipher {
	// Algorithm 2 (pg. 5)
	h := encryptWith(lrp.MainKey, lower)

	for i := 0; i < idx; i++ {
		h = encryptWith(h, upper)
	}
	k := encryptWith(h, lower)

	return &LrpCipher{
		Multi:   &lrp,
		Key:     k,
		Counter: 0,
		Encrypting: true,
	}
}

// Generates a cipher specifically for use for MAC-ing (uses the LRP primitive rather than the encryption).
// Note that the ``Encrypt'' function doesn't actually encrypt/decrypt, but MAC processes utilize that interface.
func (lrp LrpMultiCipher) CipherForMAC(idx int) *LrpForMAC {
	c := lrp.Cipher(idx)
	return &LrpForMAC{
		*c,
	}
}

