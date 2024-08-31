package goldilock_poseidon_agg

import (
	poseidon_c_bn254 "github.com/brevis-network/zk-utils/circuits/gadgets/poseidon"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
)

const MiddleNodeAggSize = 2

// normal, 2 to 1
type MiddleNodeHashCircuit struct {
	PreCommitmentHash   [MiddleNodeAggSize]frontend.Variable
	PreGoldilockHashOut [MiddleNodeAggSize]poseidon.GoldilocksHashOut
	PreToggleHash       [MiddleNodeAggSize]frontend.Variable

	CommitmentHash   frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`
	ToggleHash       frontend.Variable          `gnark:",public"`

	Proof        [MiddleNodeAggSize]regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey [MiddleNodeAggSize]regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness [MiddleNodeAggSize]regroth16.Witness[sw_bn254.ScalarField]
}

func (c *MiddleNodeHashCircuit) Define(api frontend.API) error {
	err := c.checkSdkCommitment(api)
	if err != nil {
		return err
	}
	c.checkGlHash(api)
	err = c.checkSdkToggles(api)
	if err != nil {
		return err
	}
	err = c.VerifyInnerProof(api)
	if err != nil {
		return err
	}

	return nil
}

func (c *MiddleNodeHashCircuit) VerifyInnerProof(api frontend.API) error {
	verifier, err := regroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}

	err = verifier.BatchAssertProofBrevis(c.VerifyingKey[:], c.Proof[:], c.InnerWitness[:])
	if err != nil {
		return err
	}
	return nil
}

func (c *MiddleNodeHashCircuit) checkSdkToggles(api frontend.API) error {
	hasher, err := poseidon_c_bn254.NewBn254PoseidonCircuit(api)
	if err != nil {
		return err
	}

	hasher.Write(c.PreToggleHash[0])
	hasher.Write(c.PreToggleHash[1])
	sum := hasher.Sum()
	api.AssertIsEqual(sum, c.ToggleHash)
	return nil
}

func (c *MiddleNodeHashCircuit) checkSdkCommitment(api frontend.API) error {
	hasher, err := poseidon_c_bn254.NewBn254PoseidonCircuit(api)
	if err != nil {
		return err
	}

	hasher.Write(c.PreCommitmentHash[0])
	hasher.Write(c.PreCommitmentHash[1])
	sum := hasher.Sum()
	api.AssertIsEqual(sum, c.CommitmentHash)
	return nil
}

func (c *MiddleNodeHashCircuit) checkGlHash(api frontend.API) {
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

	for x, cm := range c.InnerWitness {
		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[1].Limbs[0]), c.PreGoldilockHashOut[x][0])
		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[2].Limbs[0]), c.PreGoldilockHashOut[x][1])
		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[3].Limbs[0]), c.PreGoldilockHashOut[x][2])
		glAPI.AssertIsEqual(gl.NewVariable(cm.Public[4].Limbs[0]), c.PreGoldilockHashOut[x][3])
	}
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

func GetNextMimcGlHash(subMimcHash1, subMimcHash2 *big.Int, subGlHash1, subGlHash2 poseidon.GoldilocksHashOut) (*big.Int, poseidon.GoldilocksHashOut, error) {
	mimcHasher := mimc_bn254.NewMiMC()
	var mimcHashData []byte

	var mimcBlockBuf [mimc_bn254.BlockSize]byte
	mimcHashData = append(mimcHashData, subMimcHash1.FillBytes(mimcBlockBuf[:])...)
	mimcHashData = append(mimcHashData, subMimcHash2.FillBytes(mimcBlockBuf[:])...)
	_, err := mimcHasher.Write(mimcHashData)
	if err != nil {
		return nil, poseidon.GoldilocksHashOut{}, err
	}

	mimcHashOut := mimcHasher.Sum(nil)
	circuitMimcHash := new(big.Int).SetBytes(mimcHashOut)

	var glPreimage []gl.Variable
	glPreimage = append(glPreimage, subGlHash1[:]...)
	glPreimage = append(glPreimage, subGlHash2[:]...)
	glHashout, err := GetGoldilockPoseidonHashByGl(glPreimage)
	if err != nil {
		return nil, poseidon.GoldilocksHashOut{}, err
	}

	return circuitMimcHash, glHashout, err
}
