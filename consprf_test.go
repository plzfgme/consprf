package consprf_test

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/plzfgme/consprf"
)

func TestConstrain(t *testing.T) {
	ggm := consprf.NewGGM(16)
	mk := make([]byte, 32)
	rand.Read(mk)
	ck := ggm.Constrain(mk, big.NewInt(4555), big.NewInt(9888))
	if ggm.EvalCK(ck, big.NewInt(1234)) != nil {
		t.Error("Evaluation on out-of-range input should returns nil.")
	}
	if !bytes.Equal(ggm.EvalCK(ck, big.NewInt(6001)), ggm.EvalMK(mk, big.NewInt(6001))) {
		t.Error("Evaluation on in-range input should be equal.")
	}
}
