package test

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	bn254_groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
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

func TestMiddleNode(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)
	var data []uint64
	for i := 0; i < 30; i++ {
		data = append(data, 2178309)
	}
	subCcs1, subProof1, subVk1, subWitness1, mimc1, gl1 := GetLeafProof(assert, data)
	err := groth16.Verify(subProof1, subVk1, subWitness1, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)
	log.Infof("get leaf done")

	log.Infof("leaf ccs data: proof size: %d", len(subCcs1.GetCommitments().(constraint.Groth16Commitments)))
	log.Infof("leaf ccs data: proof size: %d", subCcs1.GetNbPublicVariables()-1)
	log.Infof("leaf ccs data: proof size: %d", subCcs1.GetNbPublicVariables()+len(subCcs1.GetCommitments().(constraint.Groth16Commitments)))
	commitments := subCcs1.GetCommitments().(constraint.Groth16Commitments)
	commitmentWires := commitments.CommitmentIndexes()
	log.Infof("leaf ccs data: proof size: %d", commitments.GetPublicAndCommitmentCommitted(commitmentWires, subCcs1.GetNbPublicVariables()))

	ccsRe, err := goldilock_poseidon_agg.GetDummyMiddleNodeCcs()
	assert.NoError(err)
	//subCcs1 = ccsRe

	log.Infof("leaf ccs data2: proof size: %d", len(ccsRe.GetCommitments().(constraint.Groth16Commitments)))
	log.Infof("leaf ccs data2: proof size: %d", ccsRe.GetNbPublicVariables()-1)
	log.Infof("leaf ccs data2: proof size: %d", ccsRe.GetNbPublicVariables()+len(ccsRe.GetCommitments().(constraint.Groth16Commitments)))
	commitments = ccsRe.GetCommitments().(constraint.Groth16Commitments)
	commitmentWires = commitments.CommitmentIndexes()
	log.Infof("leaf ccs data2: proof size: %d", commitments.GetPublicAndCommitmentCommitted(commitmentWires, ccsRe.GetNbPublicVariables()))

	subCcs2, subProof2, subVk2, subWitness2, mimc2, gl2 := GetOneMiddleNodeProof(assert, subCcs1, subProof1, subVk1, subWitness1, mimc1, gl1)
	err = groth16.Verify(subProof2, subVk2, subWitness2, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)
	log.Infof("get middle 1 done")

	log.Infof("middle ccs data2: proof size: %d", len(subCcs2.GetCommitments().(constraint.Groth16Commitments)))
	log.Infof("middle ccs data2: proof size: %d", subCcs2.GetNbPublicVariables()-1)
	log.Infof("middle ccs data2: proof size: %d", subCcs2.GetNbPublicVariables()+len(subCcs2.GetCommitments().(constraint.Groth16Commitments)))
	commitments = subCcs2.GetCommitments().(constraint.Groth16Commitments)
	commitmentWires = commitments.CommitmentIndexes()
	log.Infof("middle ccs data2: proof size: %d", commitments.GetPublicAndCommitmentCommitted(commitmentWires, subCcs2.GetNbPublicVariables()))

	subCcs3, subProof3, subVk3, subWitness3, _, _ := GetOneMiddleNodeProof(assert, subCcs2, subProof2, subVk2, subWitness2, mimc2, gl2)
	err = groth16.Verify(subProof3, subVk3, subWitness3, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	log.Infof("middle ccs data3: proof size: %d", len(subCcs3.GetCommitments().(constraint.Groth16Commitments)))
	log.Infof("middle ccs data3: proof size: %d", subCcs3.GetNbPublicVariables()-1)
	log.Infof("middle ccs data3: proof size: %d", subCcs3.GetNbPublicVariables()+len(subCcs3.GetCommitments().(constraint.Groth16Commitments)))
	commitments = subCcs3.GetCommitments().(constraint.Groth16Commitments)
	commitmentWires = commitments.CommitmentIndexes()
	log.Infof("middle ccs data3: proof size: %d", commitments.GetPublicAndCommitmentCommitted(commitmentWires, subCcs3.GetNbPublicVariables()))

	log.Infof("get middle 2 done")

}

func GetOneMiddleNodeProof(assert *test.Assert, innerCcs constraint.ConstraintSystem, innerProof groth16.Proof, innerVk groth16.VerifyingKey, innerWitness witness.Witness, innerMimcHash *big.Int, innerGPHash poseidon.GoldilocksHashOut) (constraint.ConstraintSystem, groth16.Proof, groth16.VerifyingKey, witness.Witness, *big.Int, poseidon.GoldilocksHashOut) {
	mimcHasher := mimc.NewMiMC()
	var mimcHashData []byte

	var mimcBlockBuf [mimc.BlockSize]byte
	mimcHashData = append(mimcHashData, innerMimcHash.FillBytes(mimcBlockBuf[:])...)
	mimcHashData = append(mimcHashData, innerMimcHash.FillBytes(mimcBlockBuf[:])...)
	_, err := mimcHasher.Write(mimcHashData)
	assert.NoError(err)

	mimcHashOut := mimcHasher.Sum(nil)
	circuitMimcHash := new(big.Int).SetBytes(mimcHashOut)

	var glPreimage []gl.Variable
	glPreimage = append(glPreimage, innerGPHash[:]...)
	glPreimage = append(glPreimage, innerGPHash[:]...)
	glHashout, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByGl(glPreimage)
	assert.NoError(err)

	proofPlaceholder1 := regroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
	witnessPlaceholder1 := regroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)
	vkPlaceholder1 := regroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs)

	proofPlaceholder2 := regroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
	witnessPlaceholder2 := regroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)
	vkPlaceholder2 := regroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs)

	circuitVk1, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	assert.NoError(err)
	circuitWitness1, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof1, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	circuitVk2, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	assert.NoError(err)
	circuitWitness2, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof2, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	circuit := &goldilock_poseidon_agg.MiddleNodeHashCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		PreMimcHash:         [goldilock_poseidon_agg.MiddleNodeAggSize]frontend.Variable{innerMimcHash, innerMimcHash},
		PreGoldilockHashOut: [goldilock_poseidon_agg.MiddleNodeAggSize]poseidon.GoldilocksHashOut{innerGPHash, innerGPHash},
		MimcHash:            circuitMimcHash,
		GoldilockHashOut:    glHashout,
		Proof:               [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{proofPlaceholder1, proofPlaceholder2},
		VerifyingKey:        [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{vkPlaceholder1, vkPlaceholder2},
		InnerWitness:        [goldilock_poseidon_agg.MiddleNodeAggSize]regroth16.Witness[sw_bn254.ScalarField]{witnessPlaceholder1, witnessPlaceholder2},
	}

	assigment := &goldilock_poseidon_agg.MiddleNodeHashCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		PreMimcHash:         [goldilock_poseidon_agg.MiddleNodeAggSize]frontend.Variable{innerMimcHash, innerMimcHash},
		PreGoldilockHashOut: [goldilock_poseidon_agg.MiddleNodeAggSize]poseidon.GoldilocksHashOut{innerGPHash, innerGPHash},
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

	proof, err := groth16.Prove(ccs, pk, fullWitness, regroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	err = groth16.Verify(proof, vk, pubWitness, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	log.Infof("middle node prove done ccs: %d, proof commitment: %d", ccs.GetNbConstraints(), len(proof.(*bn254_groth16.Proof).Commitments))
	return ccs, proof, vk, pubWitness, circuitMimcHash, glHashout
}
