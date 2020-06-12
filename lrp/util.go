package lrp

// Shared functions

import (
	"crypto/aes"
)

// Simplified AES decryption function, since we wind up with so many keys
func decryptWith(key []byte, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	result := make([]byte, len(data))
	c.Decrypt(result, data)

	return result
}

// Simplified AES encryption function, since we wind up with so many keys
func encryptWith(key []byte, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	result := make([]byte, len(data))
	c.Encrypt(result, data)

	return result
}

// Converts a byte array to a nibble array.  The bytes are converted to ints so they can be used as indices
func nibbles(bytes []byte) []int {
	nibbles := []int{}
	for _, x := range bytes {
		msb := 0b11110000 & x
		msb = msb >> 4
		lsb := 0b00001111 & x
		nibbles = append(nibbles, int(msb), int(lsb))
	}
	return nibbles
}

