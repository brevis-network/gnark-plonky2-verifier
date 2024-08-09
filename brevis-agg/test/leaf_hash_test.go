package test

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"math/big"
	"testing"
)

func TestLeafHashCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	mimcHasher := mimc.NewMiMC()
	var data []uint64
	var rawData []gl.Variable
	var mimcHashData []byte
	for i := 0; i < 30; i++ {
		data = append(data, 2178309)
		rawData = append(rawData, gl.NewVariable(2178309))
		var mimcBlockBuf [mimc.BlockSize]byte
		mimcHashData = append(mimcHashData, new(big.Int).SetUint64(2178309).FillBytes(mimcBlockBuf[:])...)
	}
	mimcHasher.Write(mimcHashData)
	mimcHash := mimcHasher.Sum(nil)

	res, err := goldilock_poseidon_agg.GetGoldilockPoseidonHash(data)
	assert.NoError(err)
	log.Infof("res: %v", res)
	log.Infof("mimc: %x", mimcHash)

	circuitMimcHash := new(big.Int).SetBytes(mimcHash)

	circuit := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          rawData,
		MimcHash:         circuitMimcHash,
		GoldilockHashOut: res,
	}

	w := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          rawData,
		MimcHash:         circuitMimcHash,
		GoldilockHashOut: res,
	}

	err = test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	assert.NoError(err)
}
