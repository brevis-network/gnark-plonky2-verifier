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
	verifier, err := regroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.BatchAssertProofBrevis(c.VerifyingKey, c.Proof, c.InnerWitness)
	if err != nil {
		return err
	}

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

	mimcHasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	mimcHasher.Write(c.PreMimcHash)
	mimcOutput := mimcHasher.Sum()
	api.AssertIsEqual(mimcOutput, c.MimcHash)

	return nil
}
