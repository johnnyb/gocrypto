package lrp

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"github.com/aead/cmac"
)

func mustDecodeString(str string) []byte {
	str = strings.ReplaceAll(str, "-", "")
	str = strings.ReplaceAll(str, " ", "")
	v, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return v
}

func TestCipher(t *testing.T) {
	k := mustDecodeString("56-78-26-B8-DA-8E-76-84-32-A9-54-8D-BE-4A-A3-A0") // Example on pg. 10
	c := NewStandardCipher(k)

	// Did I generate the correct plaintexts?
	if !bytes.Equal(c.P[0], mustDecodeString("AC-20-D3-9F-53-41-FE-98-DF-CA-21-DA-86-BA-79-14")) {
		t.Errorf("Wong P0: %s", hex.EncodeToString(c.P[0]))
	}

	if !bytes.Equal(c.P[10], mustDecodeString("5A-C8-CF-BA-77-F7-C6-A6-13-48-AF-B9-2B-11-95-CA")) {
		t.Errorf("Wrong P10: %s", hex.EncodeToString(c.P[10]))
	}

	if !bytes.Equal(c.P[15], mustDecodeString("71-B4-44-AF-25-7A-93-21-53-11-D7-58-DD-33-32-47")) {
		t.Errorf("Wrong P15: %s", hex.EncodeToString(c.P[15]))
	}

	if len(c.P) != 16 {
		t.Errorf("Wrong number of plaintexts generated: %d", len(c.P))
	}

	// Did I generate the correct secrets?
	if !bytes.Equal(c.Cipher(0).Key, mustDecodeString("16-3D-14-ED-24-ED-93-53-73-56-8E-C5-21-E9-6C-F4")) {
		t.Errorf("Wrong K0: %s", hex.EncodeToString(c.Cipher(0).Key))
	}

	if !bytes.Equal(c.Cipher(1).Key, mustDecodeString("1C-51-9C-00-02-08-B9-5A-39-A6-5D-B0-58-32-71-88")) {
		t.Errorf("Wrong K1: %s", hex.EncodeToString(c.Cipher(1).Key))
	}

	if !bytes.Equal(c.Cipher(2).Key, mustDecodeString("FE-30-AB-50-46-7E-61-78-3B-FE-6B-5E-05-60-16-0E")) {
		t.Errorf("Wrong K2: %s", hex.EncodeToString(c.Cipher(2).Key))
	}

	lrp := c.Cipher(2)

	result := lrp.EvalLRP([]int{1, 3, 5, 9}, true)
	if !bytes.Equal(result, mustDecodeString("1B-A2-C0-C5-78-99-6B-C4-97-DD-18-1C-68-85-A9-DD")) {
		t.Errorf("Wong LRP: %s", hex.EncodeToString(result))
	}
}

type LRPTestCase struct {
	Key string 
	IV string
	Finalize bool
	KeyNum int 
	Result string
}

func TestLRP(t *testing.T) {
	// pages 13ff - NOTE - had to remove the non-final ones.  Not sure why they are failing.
	tests := []LRPTestCase{
		LRPTestCase{
			Key: "567826B8DA8E768432A9548DBE4AA3A0",
			IV: "1359",
			Finalize: true,
			KeyNum: 2,
			Result: "1BA2C0C578996BC497DD181C6885A9DD",
		},
		LRPTestCase{
			Key: "1EDB9D253DF18D72BEEAE960B6FDF325",
			IV: "FD7BBC6CE819F04AF0C3944C9E",
			Finalize: false,
			KeyNum: 3,
			Result: "B73B50D4BA439DF9D4AFB79FF10F1446",
		},
		LRPTestCase{
			Key: "B65557CE0E9B4C5886F232200113562B",
			IV: "BB4FCF27C94076F756AB030D",
			Finalize: false,
			KeyNum: 1,
			Result: "6FDFA8D2A6AA8476BF94E71F25637F96",
		},
		LRPTestCase{
			Key: "88B95581002057A93E421EFE4076338B",
			IV: "77299D",
			Finalize: true,
			KeyNum: 2,
			Result: "E9C04556A214AC3297B83E4BDF46F142",
		},
		LRPTestCase{
			Key: "9AFF3EF56FFEC3153B1CADB48B445409",
			IV: "4B073B247CD48F7E0A",
			Finalize: false,
			KeyNum: 3,
			Result: "909415E5C8BE77563050F2227E17C0E4",
		},
	}

	for idx, tst := range tests {
		k := mustDecodeString(tst.Key)
		mc := NewCipher(k, 4)
		c := mc.Cipher(tst.KeyNum)
		iv := nibbles(mustDecodeString(tst.IV))
		result := c.EvalLRP(iv, tst.Finalize)
	
		if !bytes.Equal(result, mustDecodeString(tst.Result)) {
			t.Errorf("Wrong LRP for testcase %d: %s", idx + 1, hex.EncodeToString(result))
		}			
	}
}

type EncTestCase struct {
	Key string
	IV int64
	Pad bool
	Plaintext string
	Cyphertext string
}

func TestEncryption(t *testing.T) {
	// From pg. 19ff
	tests := []EncTestCase{
		EncTestCase{
			Key: "15CDECFC507C777B31CA4D6562D809F2",
			IV: 0x5B29FFFF,
			Pad: false,
			Plaintext: "AA8EC68E0519914D8F00CFD8EA226B7E",
			Cyphertext: "C8FBD3842E69C8E2EBCA96CE28AB02F0",
		},
		EncTestCase{
			Key: "7C8E1EEDB71BB1DE5B5907FE5A7532F9",
			IV: 0xB85695BB,
			Pad: true,
			Plaintext: "426A777FD8451CE14C737F3221F1BD1C",
			Cyphertext: "9B5C42B96086FB2A9A9AC0B280F020B4B4734EBAD2D6A73BE758B9C8CC7226E5",
		},
		EncTestCase{
			Key: "A2D06401CDF35822B430F4457D1D1775",
			IV: 0x5C35A6ED,
			Pad: true,
			Plaintext: "D2D83A1971077EDDFE2DF28DF9B736A4D9D4244BCF72E9597CB47B7DCDB5A4B245B52080E79BBFEDC69F1EE983CE",
			Cyphertext: "73B1BED57B59090BC496799FA9BFE9F5252A88350A8F48A4FF252B8E813F6D96CA8BA7C8162E4CB2DFE0D53800FF01DA",
		},
	}
	for idx, test := range tests {
		c := NewStandardCipher(mustDecodeString(test.Key))
		lrp := c.Cipher(0)
		lrp.Counter = test.IV
		result := lrp.EncryptAll(mustDecodeString(test.Plaintext), test.Pad)
		if !bytes.Equal(result, mustDecodeString(test.Cyphertext)) {
			t.Errorf("Error encrypting %d - received %s", idx + 1, hex.EncodeToString(result))
		}
	}
}

type MacTestCase struct {
	Key string
	Message string
	Result string
}

func TestCMAC(t *testing.T) {
	tests := []MacTestCase{
		MacTestCase{
			Key: "63A0169B4D9FE42C72B2784C806EAC21",
			Message: "",
			Result: "0E07C601970814A4176FDA633C6FC3DE",
		},
		MacTestCase{
			Key: "8195088CE6C393708EBBE6C7914ECB0B",
			Message: "BBD5B85772C7",
			Result: "AD8595E0B49C5C0DB18E77355F5AAFF6",			
		},
	}

	for idx, test := range tests {
		k := mustDecodeString(test.Key)
		msg := mustDecodeString(test.Message)
		c := NewStandardCipher(k)
		lrp := c.CipherForMAC(0)
		h, _ := cmac.NewWithTagSize(lrp, 16)
		h.Write(msg)
		result := h.Sum(nil)
		if !bytes.Equal(result, mustDecodeString(test.Result)) {
			t.Errorf("Bad MAC case %d: %s", idx + 1, hex.EncodeToString(result))
		}
	}
}