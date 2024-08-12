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
	"math/big"
)

const MiddleNodeAggSize = 2

// normal, 2 to 1
type MiddleNodeHashCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreMimcHash         [MiddleNodeAggSize]frontend.Variable
	PreGoldilockHashOut [MiddleNodeAggSize]poseidon.GoldilocksHashOut

	MimcHash         frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`

	Proof        [MiddleNodeAggSize]regroth16.Proof[G1El, G2El]
	VerifyingKey [MiddleNodeAggSize]regroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness [MiddleNodeAggSize]regroth16.Witness[FR]
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

	verifier, err := regroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	err = verifier.BatchAssertProofBrevis(c.VerifyingKey[:], c.Proof[:], c.InnerWitness[:])
	if err != nil {
		return err
	}

	return nil
}
