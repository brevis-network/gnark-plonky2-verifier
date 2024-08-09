package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
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

	mimcHasher := mimc.NewMiMC()
	var mimcHashData []byte
	for i := 0; i < 30; i++ {
		circuit.RawData = append(circuit.RawData, gl.NewVariable(2178309))
		w.RawData = append(circuit.RawData, gl.NewVariable(2178309))

		var mimcBlockBuf [mimc.BlockSize]byte
		mimcHashData = append(mimcHashData, new(big.Int).SetUint64(2178309).FillBytes(mimcBlockBuf[:])...)
	}
	mimcHasher.Write(mimcHashData)
	mimcHash := mimcHasher.Sum(nil)
	circuit.MimcHash = mimcHash
	w.MimcHash = mimcHash

	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	assert.NoError(err)

}
