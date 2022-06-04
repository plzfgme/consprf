package consprf_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/plzfgme/consprf"
)

func TestConstrain(t *testing.T) {
	ggm := consprf.NewGGM(16)
	mk := make([]byte, 32)
	rand.Read(mk)
	ck := ggm.Constrain(mk, 2, 7)
	if ggm.EvalCK(ck, 8) != nil {
		t.Error("Evaluation on out-of-range input should returns nil.")
	}
	if !bytes.Equal(ggm.EvalCK(ck, 5), ggm.EvalMK(mk, 5)) {
		t.Error("Evaluation on in-range input should be equal.")
	}
}
