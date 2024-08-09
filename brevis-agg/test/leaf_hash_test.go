package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"testing"
)

func TestLeafHashCircuit(t *testing.T) {

	assert := test.NewAssert(t)
	circuit := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          []gl.Variable{},
		MimcHash:         1,
		GoldilockHashOut: [poseidon.POSEIDON_GL_HASH_SIZE]gl.Variable{gl.One(), gl.One(), gl.One(), gl.One()},
	}

	w := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          []gl.Variable{},
		MimcHash:         1,
		GoldilockHashOut: [poseidon.POSEIDON_GL_HASH_SIZE]gl.Variable{gl.One(), gl.One(), gl.One(), gl.One()},
	}

	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	assert.NoError(err)

}
