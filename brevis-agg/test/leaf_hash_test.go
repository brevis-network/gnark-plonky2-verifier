package test

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	bn254_groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
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
	var gldatas [goldilock_poseidon_agg.LeafRawPubGlCount]gl.Variable
	var mimcHashData []byte
	for i := 0; i < len(datas); i++ {
		gldatas[i] = gl.NewVariable(datas[i])
		var mimcBlockBuf [mimc_bn254.BlockSize]byte
		mimcHashData = append(mimcHashData, new(big.Int).SetUint64(datas[i]).FillBytes(mimcBlockBuf[:])...)
	}

	mimcHasher := mimc_bn254.NewMiMC()
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
	}

	assigment := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          gldatas,
		MimcHash:         circuitMimcHash,
		GoldilockHashOut: glHash,
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

	proof, err := groth16.Prove(ccs, pk, fullWitness, regroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	err = groth16.Verify(proof, vk, pubWitness, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	log.Infof("leaf prove done ccs: %d, proof commitment: %d", ccs.GetNbConstraints(), len(proof.(*bn254_groth16.Proof).Commitments))

	return ccs, proof, vk, pubWitness, circuitMimcHash, glHash
}

func GetLeafMimcGlHash(assert *test.Assert, datas []uint64) (*big.Int, poseidon.GoldilocksHashOut) {
	var gldatas []gl.Variable
	var mimcHashData []byte
	for i := 0; i < 1; i++ {
		gldatas = append(gldatas, gl.NewVariable(datas[i]))
		var mimcBlockBuf [mimc_bn254.BlockSize]byte
		mimcHashData = append(mimcHashData, new(big.Int).SetUint64(datas[i]).FillBytes(mimcBlockBuf[:])...)
	}

	mimcHasher := mimc_bn254.NewMiMC()
	_, err := mimcHasher.Write(mimcHashData)
	assert.NoError(err)
	mimcHash := mimcHasher.Sum(nil)

	glHash, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByUint64(datas)
	assert.NoError(err)
	log.Infof("glHash: %v", glHash)
	log.Infof("mimc: %x", mimcHash)

	circuitMimcHash := new(big.Int).SetBytes(mimcHash)

	return circuitMimcHash, glHash
}

func TestLeafHashCircuit2(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	datas := []uint64{13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837}
	log.Infof("pub input len: %d", len(datas))

	glHash, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByUint64(datas)
	assert.NoError(err)
	log.Infof("glHash: %v", glHash)

	var glDatas [goldilock_poseidon_agg.LeafRawPubGlCount]gl.Variable
	for x, d := range datas {
		glDatas[x] = gl.NewVariable(d)
	}

	receipts, err := goldilock_poseidon_agg.GetLeafReceipts(datas)
	assert.NoError(err)
	leafs := make([]*big.Int, goldilock_poseidon_agg.MaxReceiptPerLeaf)
	hasher := mimc_bn254.NewMiMC()

	for i, receipt := range receipts {
		//log.Infof("xx eventId: %x", sdk.ConstUint248(receipt.Fields[0].EventID[:6]).Val)
		receiptInput := sdk.Receipt{
			BlockNum: sdk.Uint248{Val: receipt.BlockNum},
			Fields:   sdk.BuildLogFields(receipt.Fields),
		}

		//log.Infof("start write one receipt %d", i)
		for _, v := range receiptInput.GoPack() {
			//log.Infof("write: %x", common.LeftPadBytes(v.Bytes(), 32))
			hasher.Write(common.LeftPadBytes(v.Bytes(), 32))
		}

		leafs[i] = new(big.Int).SetBytes(hasher.Sum(nil))
		//log.Infof("leaf %d: %x", i, leafs[i])
		hasher.Reset()
	}

	var inputCommitmentsRoot frontend.Variable
	elementCount := len(leafs)
	for {
		if elementCount == 1 {
			inputCommitmentsRoot = leafs[0]
			log.Infof("w.InputCommitmentsRoot: %x", inputCommitmentsRoot)
			break
		}
		log.Infof("calMerkelRoot(no circuit) with element size: %d", elementCount)
		for i := 0; i < elementCount/2; i++ {
			var mimcBlockBuf0, mimcBlockBuf1 [mimc_bn254.BlockSize]byte
			leafs[2*i].FillBytes(mimcBlockBuf0[:])
			leafs[2*i+1].FillBytes(mimcBlockBuf1[:])
			hasher.Reset()
			hasher.Write(mimcBlockBuf0[:])
			hasher.Write(mimcBlockBuf1[:])
			leafs[i] = new(big.Int).SetBytes(hasher.Sum(nil))
		}
		elementCount = elementCount / 2
	}

	//circuitMimcHash := new(big.Int).SetBytes(mimcHash)

	circuit := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          glDatas,
		MimcHash:         inputCommitmentsRoot,
		GoldilockHashOut: glHash,
	}

	assigment := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          glDatas,
		MimcHash:         inputCommitmentsRoot,
		GoldilockHashOut: glHash,
	}

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	log.Infof("leaf circuit solve done")
}
