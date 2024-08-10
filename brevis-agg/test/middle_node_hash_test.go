package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
	"testing"
)

func TestMiddleNode(t *testing.T) {
	assert := test.NewAssert(t)
	var data []uint64
	for i := 0; i < 30; i++ {
		data = append(data, 2178309)
	}
	subCcs1, subProof1, subVk1, subWitness1, mimc1, gl1 := GetLeafProof(assert, data)
	err := groth16.Verify(subProof1, subVk1, subWitness1)
	assert.NoError(err)

	subCcs2, subProof2, subVk2, subWitness2, mimc2, gl2 := GetLeafProof(assert, data)
	err = groth16.Verify(subProof2, subVk2, subWitness2)
	assert.NoError(err)

	mimcHasher := mimc.NewMiMC()
	var mimcHashData []byte

	var mimcBlockBuf [mimc.BlockSize]byte
	mimcHashData = append(mimcHashData, mimc1.FillBytes(mimcBlockBuf[:])...)
	mimcHashData = append(mimcHashData, mimc2.FillBytes(mimcBlockBuf[:])...)
	_, err = mimcHasher.Write(mimcHashData)
	assert.NoError(err)

	mimcHashOut := mimcHasher.Sum(nil)
	circuitMimcHash := new(big.Int).SetBytes(mimcHashOut)

	var glPreimage []gl.Variable
	glPreimage = append(glPreimage, gl1[:]...)
	glPreimage = append(glPreimage, gl2[:]...)
	glHashout, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByGl(glPreimage)
	assert.NoError(err)

	/*
		Proof:        PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
				InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
				VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	*/
	proofPlaceholder1 := regroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subCcs1)
	witnessPlaceholder1 := regroth16.PlaceholderWitness[sw_bn254.ScalarField](subCcs1)
	vkPlaceholder1 := regroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subCcs1)

	proofPlaceholder2 := regroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subCcs2)
	witnessPlaceholder2 := regroth16.PlaceholderWitness[sw_bn254.ScalarField](subCcs2)
	vkPlaceholder2 := regroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subCcs2)

	circuit := &goldilock_poseidon_agg.MiddleNodeHashCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		PreMimcHash:         []frontend.Variable{mimc1, mimc2},
		PreGoldilockHashOut: []poseidon.GoldilocksHashOut{gl1, gl2},
		MimcHash:            circuitMimcHash,
		GoldilockHashOut:    glHashout,
		Proof:               []regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{proofPlaceholder1, proofPlaceholder2},
		VerifyingKey:        []regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{vkPlaceholder1, vkPlaceholder2},
		InnerWitness:        []regroth16.Witness[sw_bn254.ScalarField]{witnessPlaceholder1, witnessPlaceholder2},
	}

	circuitVk1, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subVk1)
	assert.NoError(err)
	circuitWitness1, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](subWitness1)
	assert.NoError(err)
	circuitProof1, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subProof1)
	assert.NoError(err)

	circuitVk2, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subVk2)
	assert.NoError(err)
	circuitWitness2, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](subWitness2)
	assert.NoError(err)
	circuitProof2, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subProof2)
	assert.NoError(err)

	assigment := &goldilock_poseidon_agg.MiddleNodeHashCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		PreMimcHash:         []frontend.Variable{mimc1, mimc2},
		PreGoldilockHashOut: []poseidon.GoldilocksHashOut{gl1, gl2},
		MimcHash:            circuitMimcHash,
		GoldilockHashOut:    glHashout,

		Proof:        []regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]{circuitProof1, circuitProof2},
		VerifyingKey: []regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{circuitVk1, circuitVk2},
		InnerWitness: []regroth16.Witness[sw_bn254.ScalarField]{circuitWitness1, circuitWitness2},
	}

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
