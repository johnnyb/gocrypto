package lrp

import (
	"github.com/aead/cmac"
)

type LrpForMAC struct {
	LrpCipher
}

// This overrides the Encrypt method on LrpCipher to only run the EvalLRP
func (lrp *LrpForMAC) Encrypt(dst, src []byte) {
	result := lrp.EvalLRP(nibbles(src), true)
	copy(dst[0:blocksize], result)
}

// Convenience function for doing a CMAC
func (lrp *LrpForMAC) CMAC(msg []byte) []byte {
	h, _ := cmac.NewWithTagSize(lrp, 16)
	h.Write(msg)
	return h.Sum(nil)
}

// Convenience function for doing an NXP-style short CMAC
func (lrp *LrpForMAC) ShortCMAC(msg []byte) []byte {
	mac := lrp.CMAC(msg)
	return []byte { mac[1], mac[3], mac[5], mac[7], mac[9], mac[11], mac[13], mac[15] }
}
