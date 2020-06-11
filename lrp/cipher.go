package lrp

// This is based off of NXP document 12304

import (
	"crypto/aes"
)

type LrpMultiCipher struct {
	MainKey []byte
	M       int      // Nibble Size
	P       [][]byte // Plaintexts
}

func NewCipher(key []byte, nibbleSize int) *LrpMultiCipher {
	lrp := LrpMultiCipher{
		MainKey: key,
		M:       nibbleSize,
		P:       [][]byte{},
	}

	lrp.Reset()

	return &lrp
}

func NewStandardCipher(key []byte) *LrpMultiCipher {
	return NewCipher(key, 4)
}

// Refers to the values used for upper and lower branches of Figure 1, pg. 4
var upper = []byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
var lower = []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
var zeroBlock = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func encryptWith(key []byte, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	result := make([]byte, len(data))
	c.Encrypt(result, data)

	return result
}

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
	}
}

type LrpCipher struct {
	Multi   *LrpMultiCipher
	Key     []byte
	Counter int
}

func (lrp *LrpCipher) EvalLRP(x []int, final bool) []byte {
	l := len(x) % len(lrp.Multi.P)

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

func (lrp *LrpCipher) BlockSize() int {
	return blocksize
}

func (lrp *LrpCipher) EncryptAll(src []byte) []byte {
	oldcounter := lrp.Counter
	length := len(src)
	var dst []byte

	if length == 0 {
		dst = make([]byte, blocksize)
		lrp.CryptBlocks(dst, []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	} else {
		if len(src)%blocksize == 0 {
			dst = make([]byte, len(src))
			lrp.CryptBlocks(dst, src)

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

func (lrp *LrpCipher) Decrypt(dst, src []byte) {
}

var blocksize = 16

func (lrp *LrpCipher) CounterPieces() []int {
	pieces := []int{}

	bits := lrp.Multi.M
	bitmask := (1 << bits) - 1

	ctr := lrp.Counter
	for ctr != 0 {
		low := ctr & bitmask
		pieces = append([]int{low}, pieces...)
		ctr = ctr >> bits
	}

	return pieces
}

func (lrp *LrpCipher) CryptBlocks(dst, src []byte) {
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
	}
}
