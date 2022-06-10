package consprf

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
)

type GGM struct {
	length int
}

type GGMConstrainedKey map[string][]byte

func NewGGM(length int) *GGM {
	return &GGM{
		length,
	}
}

func (ggm *GGM) EvalMK(mk []byte, input *big.Int) []byte {
	output := mk
	for i := ggm.length - 1; i >= 0; i-- {
		if input.Bit(i) == 1 {
			output = g1(output)
		} else {
			output = g0(output)
		}
	}
	return output
}

func (ggm *GGM) evalMKBitStr(mk []byte, input string) []byte {
	output := mk
	for i := 0; i < len(input); i++ {
		if input[i] == '1' {
			output = g1(output)
		} else {
			output = g0(output)
		}
	}
	return output
}

func (ggm *GGM) Constrain(mk []byte, a, b *big.Int) GGMConstrainedKey {
	ck := GGMConstrainedKey{}

	var t int
	for t = ggm.length - 1; t >= 0; t-- {
		if a.Bit(t) != b.Bit(t) {
			break
		}
	}
	if lastNBitsIsAllZero(a, t+1) {
		if lastNBitsIsAllOne(b, t+1) {
			prefix := getPrefixWithoutLastN(a, ggm.length, t+1)
			ck[prefix] = ggm.evalMKBitStr(mk, prefix)
			return ck
		} else {
			prefix := getPrefixWithoutLastN(a, ggm.length, t)
			ck[prefix] = ggm.evalMKBitStr(mk, prefix)
		}
	} else {
		var u int
		for u = 0; u < t; u++ {
			if a.Bit(u) == 1 {
				break
			}
		}
		for i := t - 1; i >= u+1; i-- {
			if a.Bit(i) == 0 {
				prefix := getPrefixWithoutLastN(a, ggm.length, i+1) + "1"
				ck[prefix] = ggm.evalMKBitStr(mk, prefix)
			}
		}
		prefix := getPrefixWithoutLastN(a, ggm.length, u)
		ck[prefix] = ggm.evalMKBitStr(mk, prefix)
	}

	if lastNBitsIsAllOne(b, t+1) {
		prefix := getPrefixWithoutLastN(b, ggm.length, t)
		ck[prefix] = ggm.evalMKBitStr(mk, prefix)
	} else {
		var v int
		for v = 0; v < t; v++ {
			if b.Bit(v) == 0 {
				break
			}
		}
		for i := t - 1; i >= v+1; i-- {
			if b.Bit(i) == 1 {
				prefix := getPrefixWithoutLastN(b, ggm.length, i+1) + "0"
				ck[prefix] = ggm.evalMKBitStr(mk, prefix)
			}
		}
		prefix := getPrefixWithoutLastN(b, ggm.length, v)
		ck[prefix] = ggm.evalMKBitStr(mk, prefix)
	}
	return ck
}

func (ggm *GGM) EvalCK(ck GGMConstrainedKey, input *big.Int) []byte {
	for i := ggm.length - 1; i >= 0; i-- {
		prefix := getPrefixWithoutLastN(input, ggm.length, i)
		if output, ok := ck[prefix]; ok {
			for j := i - 1; j >= 0; j-- {
				if input.Bit(j) == 1 {
					output = g1(output)
				} else {
					output = g0(output)
				}
			}
			return output
		}
	}
	return nil
}

func getPrefixWithoutLastN(num *big.Int, length, n int) string {
	realPrefix := (&big.Int{}).Rsh(num, uint(n)).Text(2)
	paddingLen := length - len(realPrefix) - n
	padding := make([]byte, paddingLen)
	for i := 0; i < len(padding); i++ {
		padding[i] = '0'
	}
	return string(padding) + realPrefix
}

func lastNBitsIsAllZero(num *big.Int, n int) bool {
	for i := 0; i < n; i++ {
		if num.Bit(i) != 0 {
			return false
		}
	}
	return true
}

func lastNBitsIsAllOne(num *big.Int, n int) bool {
	for i := 0; i < n; i++ {
		if num.Bit(i) != 1 {
			return false
		}
	}
	return true
}

func g0(input []byte) []byte {
	h := hmac.New(sha256.New, []byte{0})
	h.Write(input)
	return h.Sum(nil)
}

func g1(input []byte) []byte {
	h := hmac.New(sha256.New, []byte{1})
	h.Write(input)
	return h.Sum(nil)
}
