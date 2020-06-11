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

func TestLRP(t *testing.T) {
	k := mustDecodeString("567826B8DA8E768432A9548DBE4AA3A0")
	mc := NewCipher(k, 4)
	c := mc.Cipher(2)
	c.Counter = 0x1359
	result := c.EvalLRP(c.CounterPieces(), true)

	if !bytes.Equal(result, mustDecodeString("1BA2C0C578996BC497DD181C6885A9DD")) {
		t.Errorf("Wrong LRP: %s", hex.EncodeToString(result))
	}
}
