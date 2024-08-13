package test

import (
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	"testing"
)

func TestDummyMiddle(t *testing.T) {
	assert := test.NewAssert(t)
	_, err := goldilock_poseidon_agg.GetDummyMiddleNodeCcs()
	assert.NoError(err)
}
