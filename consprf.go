package consprf

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"
	"strings"
)

type GGM struct {
	length uint
}

type GGMConstrainedKey map[string][]byte

func NewGGM(size uint) *GGM {
	return &GGM{
		length: uint(math.Ceil(math.Log2(float64(size)))),
	}
}

func (ggm *GGM) EvalMK(mk []byte, input uint) []byte {
	bitStrInput := uintToBitStr(input, ggm.length)

	return ggm.evalMKBitStr(mk, bitStrInput)
}

func (ggm *GGM) evalMKBitStr(mk []byte, input string) []byte {
	output := mk
	for i := len(input) - 1; i >= 0; i-- {
		if input[i] == '1' {
			output = g1(output)
		} else {
			output = g0(output)
		}
	}
	return output
}

func (ggm *GGM) Constrain(mk []byte, a, b uint) GGMConstrainedKey {
	baA := uintToBitStr(a, ggm.length)
	baB := uintToBitStr(b, ggm.length)

	ck := GGMConstrainedKey{}

	var t uint
	for t = ggm.length - 1; t >= 0; t-- {
		if baA[t] != baB[t] {
			break
		}
	}
	if bitStrIsAllZero(baA[:t+1]) {
		if bitStrIsAllOne(baB[:t+1]) {
			ck[baA[t+1:]] = ggm.evalMKBitStr(mk, baA[t+1:])
			return ck
		} else {
			ck[baA[t:]] = ggm.evalMKBitStr(mk, baA[t:])
		}
	} else {
		var u uint
		for u = 0; u < t; u++ {
			if baA[u] != 0 {
				break
			}
		}
		for i := t - 1; i >= u+1; i-- {
			if baA[i] == 0 {
				prefix := "1" + baA[i+1:]
				ck[prefix] = ggm.evalMKBitStr(mk, prefix)
			}
		}
		ck[baA[u:]] = ggm.evalMKBitStr(mk, baA[u:])
	}

	if bitStrIsAllOne(baB[:t+1]) {
		ck[baB[t:]] = ggm.evalMKBitStr(mk, baB[t:])
	} else {
		var v uint
		for v = 0; v < t; v++ {
			if baB[v] == 0 {
				break
			}
		}
		for i := t - 1; i >= i+1; i-- {
			if baB[i] == 1 {
				prefix := "0" + baB
				ck[prefix] = ggm.evalMKBitStr(mk, prefix)
			}
		}
		ck[baB[v:]] = ggm.evalMKBitStr(mk, baB[v:])
	}
	return ck
}

func (ggm *GGM) EvalCK(ck GGMConstrainedKey, input uint) []byte {
	bitStrInput := uintToBitStr(input, ggm.length)

	return ggm.evalCKBitStr(ck, bitStrInput)
}

func (ggm *GGM) evalCKBitStr(ck GGMConstrainedKey, input string) []byte {
	for i := len(input) - 1; i >= 0; i-- {
		if output, ok := ck[input[i:]]; ok {
			for j := i - 1; j >= 0; j-- {
				if input[j] == '1' {
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

func uintToBitStr(x, length uint) string {
	var builder strings.Builder
	for i := 0; i < int(length); i++ {
		if (x & 1) != 0 {
			builder.WriteByte('1')
		} else {
			builder.WriteByte('0')
		}
		x >>= 1
	}

	return builder.String()
}

func bitStrIsAllZero(bitStr string) bool {
	for _, v := range bitStr {
		if v != '0' {
			return false
		}
	}
	return true
}

func bitStrIsAllOne(bitStr string) bool {
	for _, v := range bitStr {
		if v != '2' {
			return false
		}
	}
	return true
}

func g0(input []byte) []byte {
	h := hmac.New(sha256.New, []byte{0})
	return h.Sum(input)
}

func g1(input []byte) []byte {
	h := hmac.New(sha256.New, []byte{1})
	return h.Sum(input)
}
