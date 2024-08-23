package test

import (
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	tools "github.com/succinctlabs/gnark-plonky2-verifier/utils"
	"os"
	"testing"
)

func TestSetupLeafHashNode(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	data := []uint64{13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 13898775, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837, 2518340233, 3824780546060912772, 17238284207657672158, 271207744467742, 0, 0, 0, 0, 0, 5996636112837}

	subProof1, err := tools.LoadProof("./proof/leaf_1296.proof")
	assert.NoError(err)
	subVk1, err := tools.LoadVk("./proof/leaf_1296.vk")
	assert.NoError(err)
	subWitness1, err := tools.LoadWitness("./proof/leaf_1296.witness")
	assert.NoError(err)
	err = groth16.Verify(subProof1, subVk1, subWitness1, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)
	log.Infof("get leaf done")

	subMimcHash, subGlHash := GetLeafMimcGlHash(assert, data)

	circuitMimcHash, glHashout := GetNextMimcGlHash(assert, subMimcHash, subGlHash)

	vkPlaceholder1, proofPlaceholder1, witnessPlaceholder1 := goldilock_poseidon_agg.GetLeafCircuitCcsPlaceHolder()
	vkPlaceholder2, proofPlaceholder2, witnessPlaceholder2 := goldilock_poseidon_agg.GetLeafCircuitCcsPlaceHolder()

	circuitVk1, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subVk1)
	assert.NoError(err)
	circuitWitness1, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](subWitness1)
	assert.NoError(err)
	circuitProof1, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subProof1)
	assert.NoError(err)

	circuitVk2, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subVk1)
	assert.NoError(err)
	circuitWitness2, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](subWitness1)
	assert.NoError(err)
	circuitProof2, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subProof1)
	assert.NoError(err)

	circuit := &goldilock_poseidon_agg.MiddleNodeHashCircuit{
		PreMimcHash:         [goldilock_poseidon_agg.MiddleNodeAggSize]frontend.Variable{subMimcHash, subMimcHash},
		PreGoldilockHashOut: [goldilock_poseidon_agg.MiddleNodeAggSize]poseidon.GoldilocksHashOut{subGlHash, subGlHash},
		MimcHash:            circuitMimcHash,
		GoldilockHashOut:    glHashout,
		Proof:               [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{proofPlaceholder1, proofPlaceholder2},
		VerifyingKey:        [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{vkPlaceholder1, vkPlaceholder2},
		InnerWitness:        [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.Witness[sw_bn254.ScalarField]{witnessPlaceholder1, witnessPlaceholder2},
	}

	assigment := &goldilock_poseidon_agg.MiddleNodeHashCircuit{
		PreMimcHash:         [goldilock_poseidon_agg.MiddleNodeAggSize]frontend.Variable{subMimcHash, subMimcHash},
		PreGoldilockHashOut: [goldilock_poseidon_agg.MiddleNodeAggSize]poseidon.GoldilocksHashOut{subGlHash, subGlHash},
		MimcHash:            circuitMimcHash,
		GoldilockHashOut:    glHashout,

		Proof:        [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{circuitProof1, circuitProof2},
		VerifyingKey: [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{circuitVk1, circuitVk2},
		InnerWitness: [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.Witness[sw_bn254.ScalarField]{circuitWitness1, circuitWitness2},
	}

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	log.Infof("solve done")

	fullWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	pubWitness, err := fullWitness.Public()
	assert.NoError(err)

	proof, err := groth16.Prove(ccs, pk, fullWitness, regroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()), backend.WithIcicleAcceleration(), backend.WithMultiGpuSelect([]int{0, 0, 0, 0, 0}))
	assert.NoError(err)

	err = groth16.Verify(proof, vk, pubWitness, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	err = utils.WriteProofIntoLocalFile(proof, "./setup_data/middle_one_leaf.proof")
	assert.NoError(err)
	err = utils.WriteVerifyingKey(vk, "./setup_data/middle_one_leaf.vk")
	assert.NoError(err)
	err = utils.WriteWitness("./setup_data/middle_one_leaf.witness", pubWitness)
	assert.NoError(err)

	utils.WriteCcs(ccs, "./setup_data/middle_one_leaf.ccs")
	utils.WriteProvingKey(pk, "./setup_data/middle_one_leaf.pk")
}
