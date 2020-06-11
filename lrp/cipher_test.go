package lrp

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
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
	// pages 13ff
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
	tests := []EncTestCase{
		EncTestCase{
			Key: "7C8E1EEDB71BB1DE5B5907FE5A7532F9",
			IV: 0xB85695BB,
			Pad: true,
			Plaintext: "426A777FD8451CE14C737F3221F1BD1C",
			Cyphertext: "9B5C42B96086FB2A9A9AC0B280F020B4B4734EBAD2D6A73BE758B9C8CC7226E5",
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
