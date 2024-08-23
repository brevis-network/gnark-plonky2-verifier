package goldilock_poseidon_agg

import (
	"fmt"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/mimc"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
)

const MiddleNodeAggSize = 2

// normal, 2 to 1
type MiddleNodeHashCircuit struct {
	PreMimcHash         [MiddleNodeAggSize]frontend.Variable
	PreGoldilockHashOut [MiddleNodeAggSize]poseidon.GoldilocksHashOut

	MimcHash         frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`

	Proof        [MiddleNodeAggSize]regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey [MiddleNodeAggSize]regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness [MiddleNodeAggSize]regroth16.Witness[sw_bn254.ScalarField]
}

func (c *MiddleNodeHashCircuit) Define(api frontend.API) error {
	glAPI := gl.New(api)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	var goldilockPreImage []gl.Variable
	for i := 0; i < len(c.PreGoldilockHashOut); i++ {
		goldilockPreImage = append(goldilockPreImage, c.PreGoldilockHashOut[i][:]...)
	}
	goldiLockOut := poseidonGlChip.HashNoPad(goldilockPreImage)
	for i := 0; i < len(goldiLockOut); i++ {
		glAPI.AssertIsEqual(c.GoldilockHashOut[i], goldiLockOut[i])
	}

	var placeholder []gl.Variable
	for i := 0; i < 30; i++ {
		placeholder = append(placeholder, gl.NewVariable(100))
	}
	for i := 0; i < 4; i++ {
		poseidonGlChip.HashNoPad(placeholder)
	}

	mimcHasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mimcHasher.Write(c.PreMimcHash[0])
	mimcHasher.Write(c.PreMimcHash[1])
	mimcOutput := mimcHasher.Sum()
	api.AssertIsEqual(mimcOutput, c.MimcHash)

	for x, cm := range c.InnerWitness {
		h0 := cm.Public[0].Limbs[3]
		h1 := cm.Public[0].Limbs[2]
		h2 := cm.Public[0].Limbs[1]
		h3 := cm.Public[0].Limbs[0]

		h0 = api.Mul(h0, big.NewInt(1).Lsh(big.NewInt(1), 192))
		h1 = api.Mul(h1, big.NewInt(1).Lsh(big.NewInt(1), 128))
		h2 = api.Mul(h2, big.NewInt(1).Lsh(big.NewInt(1), 64))
		res := api.Add(h0, h1, h2, h3)
		api.AssertIsEqual(res, c.PreMimcHash[x])

		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[1].Limbs[0]), c.PreGoldilockHashOut[x][0])
		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[2].Limbs[0]), c.PreGoldilockHashOut[x][1])
		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[3].Limbs[0]), c.PreGoldilockHashOut[x][2])
		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[4].Limbs[0]), c.PreGoldilockHashOut[x][3])
	}

	verifier, err := regroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	err = verifier.BatchAssertProofBrevis(c.VerifyingKey[:], c.Proof[:], c.InnerWitness[:])
	if err != nil {
		return err
	}

	return nil
}

func GetMiddleNodeCircuitCcsPlaceHolder() (regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], regroth16.Witness[sw_bn254.ScalarField]) {
	nbPublicVariables := 6
	commitmentsLen := 1
	publicAndCommitmentCommitted := [][]int{{}}

	batchVkPlaceHolder := regroth16.PlaceholderVerifyingKeyWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](nbPublicVariables, commitmentsLen, publicAndCommitmentCommitted)
	batchProofPlaceHolder := regroth16.PlaceholderProofWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine](commitmentsLen)
	batchWitnessPlaceHolder := regroth16.PlaceholderWitnessWithParam[sw_bn254.ScalarField](nbPublicVariables)

	return batchVkPlaceHolder, batchProofPlaceHolder, batchWitnessPlaceHolder
}

func GetNextMimcGlHash(subMimcHash *big.Int, subGlHash poseidon.GoldilocksHashOut) (*big.Int, poseidon.GoldilocksHashOut, error) {
	mimcHasher := mimc_bn254.NewMiMC()
	var mimcHashData []byte

	var mimcBlockBuf [mimc_bn254.BlockSize]byte
	mimcHashData = append(mimcHashData, subMimcHash.FillBytes(mimcBlockBuf[:])...)
	mimcHashData = append(mimcHashData, subMimcHash.FillBytes(mimcBlockBuf[:])...)
	_, err := mimcHasher.Write(mimcHashData)
	if err != nil {
		return nil, poseidon.GoldilocksHashOut{}, err
	}

	mimcHashOut := mimcHasher.Sum(nil)
	circuitMimcHash := new(big.Int).SetBytes(mimcHashOut)

	var glPreimage []gl.Variable
	glPreimage = append(glPreimage, subGlHash[:]...)
	glPreimage = append(glPreimage, subGlHash[:]...)
	glHashout, err := GetGoldilockPoseidonHashByGl(glPreimage)
	if err != nil {
		return nil, poseidon.GoldilocksHashOut{}, err
	}

	return circuitMimcHash, glHashout, err
}
