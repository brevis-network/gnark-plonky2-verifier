package test

import (
	"github.com/celer-network/goutils/log"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"math/big"
	"testing"
)

/*
mimc 108aa9c7e7c5e484f8b178ed2a6291f94e51eb2727df1c287b826622c8ba4ffd
gl: [{3184190347962303346} {2227170885614277709} {15479923318536672341} {568102048796813973}]


3 dummy:

mimc: 2e8b362edd870a14dd6ffe10be6e42d87718036538edf740abe5104924685f77
gl: [{7544075957751693767} {11609535206204781183} {6112371860259757379} {12359656023993954792}]
*/

func TestGetRootHash(t *testing.T) {
	assert := test.NewAssert(t)
	m0 := new(big.Int).SetBytes(common.Hex2Bytes("108aa9c7e7c5e484f8b178ed2a6291f94e51eb2727df1c287b826622c8ba4ffd"))
	m1 := new(big.Int).SetBytes(common.Hex2Bytes("2e8b362edd870a14dd6ffe10be6e42d87718036538edf740abe5104924685f77"))
	m2 := new(big.Int).SetBytes(common.Hex2Bytes("2e8b362edd870a14dd6ffe10be6e42d87718036538edf740abe5104924685f77"))
	m3 := new(big.Int).SetBytes(common.Hex2Bytes("2e8b362edd870a14dd6ffe10be6e42d87718036538edf740abe5104924685f77"))

	var mimcBlockBuf [mimc_bn254.BlockSize]byte
	mimcHasher := mimc_bn254.NewMiMC()
	m0.FillBytes(mimcBlockBuf[:])
	_, err := mimcHasher.Write(mimcBlockBuf[:])
	m1.FillBytes(mimcBlockBuf[:])
	_, err = mimcHasher.Write(mimcBlockBuf[:])
	assert.NoError(err)
	m01 := mimcHasher.Sum(nil)
	mimcHasher.Reset()

	m2.FillBytes(mimcBlockBuf[:])
	_, err = mimcHasher.Write(mimcBlockBuf[:])
	m3.FillBytes(mimcBlockBuf[:])
	_, err = mimcHasher.Write(mimcBlockBuf[:])
	assert.NoError(err)
	m23 := mimcHasher.Sum(nil)
	mimcHasher.Reset()

	new(big.Int).SetBytes(m01).FillBytes(mimcBlockBuf[:])
	_, err = mimcHasher.Write(mimcBlockBuf[:])
	new(big.Int).SetBytes(m23).FillBytes(mimcBlockBuf[:])
	_, err = mimcHasher.Write(mimcBlockBuf[:])
	assert.NoError(err)
	m0123 := mimcHasher.Sum(nil)
	mimcHasher.Reset()

	log.Infof("m0123: %x", m0123)

	gl0 := [4]gl.Variable{gl.NewVariable(uint64(3184190347962303346)), gl.NewVariable(uint64(2227170885614277709)), gl.NewVariable(uint64(15479923318536672341)), gl.NewVariable(uint64(568102048796813973))}
	gl1 := [4]gl.Variable{gl.NewVariable(uint64(7544075957751693767)), gl.NewVariable(uint64(11609535206204781183)), gl.NewVariable(uint64(6112371860259757379)), gl.NewVariable(uint64(12359656023993954792))}
	gl2 := [4]gl.Variable{gl.NewVariable(uint64(7544075957751693767)), gl.NewVariable(uint64(11609535206204781183)), gl.NewVariable(uint64(6112371860259757379)), gl.NewVariable(uint64(12359656023993954792))}
	gl3 := [4]gl.Variable{gl.NewVariable(uint64(7544075957751693767)), gl.NewVariable(uint64(11609535206204781183)), gl.NewVariable(uint64(6112371860259757379)), gl.NewVariable(uint64(12359656023993954792))}

	var data [8]gl.Variable
	data[0] = gl0[0]
	data[1] = gl0[1]
	data[2] = gl0[2]
	data[3] = gl0[3]
	data[4] = gl1[0]
	data[5] = gl1[1]
	data[6] = gl1[2]
	data[7] = gl1[3]

	gl01, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByGl(data[:])
	assert.NoError(err)

	data[0] = gl2[0]
	data[1] = gl2[1]
	data[2] = gl2[2]
	data[3] = gl2[3]
	data[4] = gl3[0]
	data[5] = gl3[1]
	data[6] = gl3[2]
	data[7] = gl3[3]
	gl23, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByGl(data[:])
	assert.NoError(err)

	data[0] = gl01[0]
	data[1] = gl01[1]
	data[2] = gl01[2]
	data[3] = gl01[3]
	data[4] = gl23[0]
	data[5] = gl23[1]
	data[6] = gl23[2]
	data[7] = gl23[3]

	gl0123, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByGl(data[:])
	assert.NoError(err)

	log.Infof("gl root: %v", gl0123)

}
