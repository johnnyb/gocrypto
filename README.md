# GoCrypto Extensions

I'm using this as a repo for crypto extensions I need in Go.  
Right now, it is focused on the NXP LRP (leakage resistant primitive) 
specification.

Information about LRP can be found [here](https://www.nxp.com/docs/en/application-note/AN12304.pdf) 
and [here](https://www.nxp.com/docs/en/supporting-information/LRP_SI.pdf).
LRP is primarily used in the NXP 424 DNA NFC chip.

## Usage

LRP uses a single key to seed multiple keys, so the function to create
the cryptosystem is called `NewStandardMultiCipher(k)`.  This returns
an LrpMultiCipher struct.  You then choose a specific LrpCipher by 
index by calling the `Cipher(idx)` method.

This struct implements the cipher.Block interface, but also has the
`EncryptAll(msg, padding)` function and the `DecryptAll(msg, padding)`
functions for ease of use.  I suggest that you pass in `true` for the
padding unless there is a specific reason not to (some NXP functions
specifically operate without padding).

## CMAC

NXP uses this cipher for as a drop-in for CMACs, but not in a way that 
you might expect.  Instead of using the encryption mode for the CMAC,
it uses a separate internal primitive to do this.  Therefore, to get at
the encryption mode that is used for generating MACs, 
use `CipherForMAC(idx)` instead of `Cipher(idx)`.  For generating a CMAC
(which is often done with this protocol), there is a helper function
`CipherForMAC(idx).MAC()` and `CipherForMAC(idx).ShortMAC()`.  

For NXP, Key 0 (`CipherForMAC(0)`) is usually used for generating CMACs, 
and Key 1 (`Cipher(1)`) is used for encryption/decryption.

## Example

```
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/johnnyb/gocrypto/lrp"
)

func main() {
	message := "My Message"

	// Setup the system
	key := []byte{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }
	mc := lrp.NewStandardMultiCipher(key)

	// Grab a cipher using Key 1
	c := mc.Cipher(1)

	// Encrypt/Decrypt
	encryptedMessage := c.EncryptAll([]byte(message), true)
	result := string(c.DecryptAll(encryptedMessage, true))

	fmt.Printf("Here is our original message: %s\n", result)

	// Grab a cipher for doing MACs using Key 0
	macCipher := mc.CipherForMAC(0)

	// Generate a MAC
	h, _ := cmac.NewWithTagSize(macCipher, 16)
	h.Write([]byte(message))
	messageMac := h.Sum(nil)

	fmt.Printf("MAC for message: %s\n", hex.EncodeToString(messageMac))

	// Simpler version
	messageMac = macCipher.CMAC([]byte(message))

	// 8-byte MAC specified by NXP
	shortMac := macCipher.ShortCMAC([]byte(message))
}
```

## Limitations

This library is currently not very optimized.  Most of the test cases, however, 
were taken directly from the documentation, so it should work correctly.

## Additional Note

In the implementation of LRP, the counter has a specific size: 4 bytes.  
The LRP standard seems to indicate that the size of the counter for LRP 
is just based on how many bits you need.  In any case, if you set
CounterSize on the LrpCipher to 4, you will get the behavior in the chip,
and if you leave it you will get the behavior in the document.
