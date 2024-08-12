package goldilock_poseidon_agg

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

// normal, 2 to 1
type MiddleNodeHashCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreMimcHash         []frontend.Variable
	PreGoldilockHashOut []poseidon.GoldilocksHashOut

	MimcHash         frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`

	Proof        []regroth16.Proof[G1El, G2El]
	VerifyingKey []regroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness []regroth16.Witness[FR]
}

func (c *MiddleNodeHashCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
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

	verifier, err := regroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	err = verifier.AssertProof(c.VerifyingKey[0], c.Proof[0], c.InnerWitness[0])
	if err != nil {
		return err
	}
	err = verifier.AssertProof(c.VerifyingKey[1], c.Proof[1], c.InnerWitness[1])
	if err != nil {
		return err
	}
	/*err = verifier.BatchAssertProofBrevis(c.VerifyingKey, c.Proof, c.InnerWitness)
	if err != nil {
		return err
	}*/

	return nil
}
