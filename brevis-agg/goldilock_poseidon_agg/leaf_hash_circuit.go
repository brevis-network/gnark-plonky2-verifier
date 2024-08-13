package goldilock_poseidon_agg

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/mimc"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type LeafHashCircuit struct {
	RawData []gl.Variable

	MimcHash         frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`
}

func (c *LeafHashCircuit) Define(api frontend.API) error {
	glAPI := gl.New(api)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	output := poseidonGlChip.HashNoPad(c.RawData)

	var placeholder []gl.Variable
	for i := 0; i < 30; i++ {
		placeholder = append(placeholder, gl.NewVariable(100))
	}
	for i := 0; i < 4; i++ {
		poseidonGlChip.HashNoPad(placeholder)
	}

	// Check that output is correct
	for i := 0; i < 4; i++ {
		glAPI.AssertIsEqual(output[i], c.GoldilockHashOut[i])
	}

	mimcHasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for i := 0; i < len(c.RawData); i++ {
		mimcHasher.Write(c.RawData[i].Limb)
	}

	mimcHashOutput := mimcHasher.Sum()
	api.AssertIsEqual(mimcHashOutput, c.MimcHash)
	log.Infof("c.MimcHash: %x, mimcHashOutput: %x", c.MimcHash, mimcHashOutput)

	return nil
}

func GetLeafCircuitCcsPlaceHolder() (regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], regroth16.Witness[sw_bn254.ScalarField]) {
	nbPublicVariables := 6
	commitmentsLen := 1
	publicAndCommitmentCommitted := [][]int{{}}

	batchVkPlaceHolder := regroth16.PlaceholderVerifyingKeyWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](nbPublicVariables, commitmentsLen, publicAndCommitmentCommitted)
	batchProofPlaceHolder := regroth16.PlaceholderProofWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine](commitmentsLen)
	batchWitnessPlaceHolder := regroth16.PlaceholderWitnessWithParam[sw_bn254.ScalarField](nbPublicVariables)

	return batchVkPlaceHolder, batchProofPlaceHolder, batchWitnessPlaceHolder
}
