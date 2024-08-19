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

func TestGetOneGoldilockPoseidonHash2(t *testing.T) {
	assert := test.NewAssert(t)
	data := []uint64{10934975891920367518, 4424308543009015085, 4179612347403588503, 9848538406279051766, 10934975891920367518, 4424308543009015085, 4179612347403588503, 9848538406279051766}

	res, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByUint64(data)
	assert.NoError(err)
	log.Infof("res: %v", res)

	var data2 []gl.Variable
	data2 = append(data2, res[:]...)
	data2 = append(data2, res[:]...)
	res, err = goldilock_poseidon_agg.GetGoldilockPoseidonHashByGl(data2)
	assert.NoError(err)
	log.Infof("res: %v", res)
}

func TestGetOneGoldilockPoseidonHash4(t *testing.T) {
	assert := test.NewAssert(t)
	data := []uint64{20539384}

	res, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByUint64(data)
	assert.NoError(err)
	log.Infof("res: %v", res)

	var data2 []gl.Variable
	data2 = append(data2, res[:]...)
	data2 = append(data2, res[:]...)
	res, err = goldilock_poseidon_agg.GetGoldilockPoseidonHashByGl(data2)
	assert.NoError(err)
	log.Infof("res: %v", res)
}
