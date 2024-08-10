package test

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"testing"
)

func TestGoldilockPoseidon(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &goldilock_poseidon_agg.GoldilockPoseidonDryRunCircuit{
		RawData: []gl.Variable{},
	}

	w := &goldilock_poseidon_agg.GoldilockPoseidonDryRunCircuit{
		RawData: []gl.Variable{},
	}

	for i := 0; i < 30; i++ {
		circuit.RawData = append(circuit.RawData, gl.NewVariable(2178309))
		w.RawData = append(circuit.RawData, gl.NewVariable(2178309))
	}

	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	assert.NoError(err)

}

func TestGetOneGoldilockPoseidonHash(t *testing.T) {
	assert := test.NewAssert(t)
	var data []uint64
	for i := 0; i < 30; i++ {
		data = append(data, 2178309)
	}

	res, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByUint64(data)
	assert.NoError(err)
	log.Infof("res: %v", res)
}
