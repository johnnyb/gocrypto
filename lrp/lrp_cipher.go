package lrp

type LrpCipher struct {
	Multi       *LrpMultiCipher
	Key         []byte
	Counter     uint64
	CounterSize int
	Encrypting  bool
}

// Generates a decrypting cipher, compatible with cipher.BlockMode
func (lrp *LrpCipher) Decrypter() *LrpCipher {
	newCipher := LrpCipher{
		Multi:      lrp.Multi,
		Key:        lrp.Key,
		Counter:    lrp.Counter,
		Encrypting: false,
	}
	return &newCipher
}

// Generates a encrypting cipher, compatible with cipher.BlockMode
func (lrp *LrpCipher) Encrypter() *LrpCipher {
	newCipher := LrpCipher{
		Multi:      lrp.Multi,
		Key:        lrp.Key,
		Counter:    lrp.Counter,
		Encrypting: true,
	}
	return &newCipher
}

// Number of bytes in a block
func (lrp *LrpCipher) BlockSize() int {
	return blocksize
}

// This is the fundamental primitive used for encryption/decryption
func (lrp *LrpCipher) EvalLRP(x []int, final bool) []byte {
	l := len(x)

	// Algorithm 3 (pg. 6)
	y := lrp.Key

	for i := 0; i < l; i++ {
		p := lrp.Multi.P[x[i]]
		y = encryptWith(y, p)
	}
	if final {
		y = encryptWith(y, zeroBlock)
	}
	return y
}

/* Fundamental Primitives */

// Encrypts the given blocks from src to dst.
// Based on the smaller of src/dst.  Requires
// that src is only full blocks.
func (lrp *LrpCipher) EncryptBlocks(dst, src []byte) {
	// Algorithm 4 (pg. 7)
	srcblocks := len(src) / blocksize
	numblocks := len(dst) / blocksize
	if srcblocks < numblocks {
		numblocks = srcblocks
	}

	for i := 0; i < numblocks; i++ {
		blockstart := i * blocksize
		blockend := blockstart + blocksize
		block := src[blockstart:blockend]
		x := lrp.CounterPieces()
		// l := len(x)
		y := lrp.EvalLRP(x, true)
		encryptedBlock := encryptWith(y, block)
		copy(dst[blockstart:blockend], encryptedBlock)
		lrp.Counter++
	}
}

// Decrypt the given blocks in src to dst.  Requires
// full blocks.
func (lrp *LrpCipher) DecryptBlocks(dst, src []byte) {
	// Algorithm 5 (pg. 8)
	srcblocks := len(src) / blocksize
	numblocks := len(dst) / blocksize
	if srcblocks < numblocks {
		numblocks = srcblocks
	}

	for i := 0; i < numblocks; i++ {
		blockstart := i * blocksize
		blockend := blockstart + blocksize
		block := src[blockstart:blockend]
		x := lrp.CounterPieces()
		// l := len(x)
		y := lrp.EvalLRP(x, true)
		decryptedBlock := decryptWith(y, block)
		copy(dst[blockstart:blockend], decryptedBlock)
		lrp.Counter++
	}
}

/* Standard BlockMode interface functions */
func (lrp *LrpCipher) CryptBlocks(dst, src []byte) {
	if lrp.Encrypting {
		lrp.EncryptBlocks(dst, src)
	} else {
		lrp.DecryptBlocks(dst, src)
	}
}

/* Standard cipher.Block interface functions */

// Encrypt a single block
func (lrp *LrpCipher) Encrypt(dst, src []byte) {
	lrp.EncryptBlocks(dst[0:blocksize], src[0:blocksize])
}

// Decrypt a single block
func (lrp *LrpCipher) Decrypt(dst, src []byte) {
	lrp.DecryptBlocks(dst[0:blocksize], src[0:blocksize])
}

/* Convenience functions */

// Encrypt the entire message.  All non-even blocks are padded.
// Setting padEvenBlocks to true will give you padded blocks no
// matter what.  This is normally what you want, but NXP has
// a few cases of non-padded encryption.
func (lrp *LrpCipher) EncryptAll(src []byte, padEvenBlocks bool) []byte {
	oldcounter := lrp.Counter
	length := len(src)
	var dst []byte

	if length == 0 {
		dst = make([]byte, blocksize)
		lrp.CryptBlocks(dst, fullBlockPadding)
	} else {
		if len(src)%blocksize == 0 {
			if padEvenBlocks {
				newsrc := make([]byte, len(src))
				copy(newsrc, src)
				newsrc = append(newsrc, fullBlockPadding...)
				dst = make([]byte, len(newsrc))
				lrp.CryptBlocks(dst, newsrc)
			} else {
				dst = make([]byte, len(src))
				lrp.CryptBlocks(dst, src)
			}
		} else {
			numblocks := (len(src) / blocksize) + 1
			newsrc := make([]byte, numblocks*blocksize)
			dst = make([]byte, len(newsrc))
			copy(newsrc, src)
			newsrc[len(src)] = 0x80
			lrp.CryptBlocks(dst, newsrc)
		}
	}
	lrp.Counter = oldcounter
	return dst
}

// Decrypt the entire message.  removePadding tells whether or not
// it was originally padded, and, therefore, whether to remove the
// padding before it is returned.
func (lrp *LrpCipher) DecryptAll(src []byte, removePadding bool) []byte {
	oldcounter := lrp.Counter

	dst := make([]byte, len(src))
	lrp.DecryptBlocks(dst, src)

	dividerByteIndex := len(dst) - 1

	if removePadding {
		for dst[dividerByteIndex] != 0x80 {
			dividerByteIndex--
		}
	}

	lrp.Counter = oldcounter

	return dst[0:dividerByteIndex]
}

// Breaks the block counter into nibbles for the EvalLRP primitive
func (lrp *LrpCipher) CounterPieces() []int {
	pieces := []int{}

	bits := lrp.Multi.M
	bitmask := uint64((1 << bits) - 1)

	ctr := lrp.Counter
	for true {
		low := ctr & bitmask
		pieces = append([]int{int(low)}, pieces...)
		ctr = ctr >> bits
		if lrp.CounterSize == 0 {
			if ctr == 0 {
				break
			}
		} else {
			if len(pieces) == lrp.CounterSize {
				break
			}
		}
	}

	return pieces
}
