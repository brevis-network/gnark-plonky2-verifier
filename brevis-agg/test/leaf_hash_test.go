package test

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
	"os"
	"testing"
)

func TestLeafHashCircuit(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)
	var data []uint64
	for i := 0; i < 30; i++ {
		data = append(data, 2178309)
	}
	GetLeafProof(assert, data)
}

func GetLeafProof(assert *test.Assert, datas []uint64) (constraint.ConstraintSystem, groth16.Proof, groth16.VerifyingKey, witness.Witness, *big.Int, poseidon.GoldilocksHashOut) {
	var gldatas []gl.Variable
	var mimcHashData []byte
	for i := 0; i < len(datas); i++ {
		gldatas = append(gldatas, gl.NewVariable(datas[i]))
		var mimcBlockBuf [mimc.BlockSize]byte
		mimcHashData = append(mimcHashData, new(big.Int).SetUint64(datas[i]).FillBytes(mimcBlockBuf[:])...)
	}

	mimcHasher := mimc.NewMiMC()
	_, err := mimcHasher.Write(mimcHashData)
	assert.NoError(err)
	mimcHash := mimcHasher.Sum(nil)

	glHash, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByUint64(datas)
	assert.NoError(err)
	log.Infof("glHash: %v", glHash)
	log.Infof("mimc: %x", mimcHash)

	circuitMimcHash := new(big.Int).SetBytes(mimcHash)

	circuit := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          gldatas,
		MimcHash:         circuitMimcHash,
		GoldilockHashOut: glHash,
		PrivateI:         1,
	}

	assigment := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          gldatas,
		MimcHash:         circuitMimcHash,
		GoldilockHashOut: glHash,
		PrivateI:         1,
	}

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	log.Infof("leaf circuit solve done")

	fullWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	pubWitness, err := fullWitness.Public()
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	for i := 0; i < 4; i++ {
		groth16.Prove(ccs, pk, fullWitness, regroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()), backend.WithIcicleAcceleration())
	}

	proof, err := groth16.Prove(ccs, pk, fullWitness, regroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()), backend.WithIcicleAcceleration())
	assert.NoError(err)

	err = groth16.Verify(proof, vk, pubWitness, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	log.Infof("leaf prove done ccs: %d", ccs.GetNbConstraints())

	return ccs, proof, vk, pubWitness, circuitMimcHash, glHash
}
