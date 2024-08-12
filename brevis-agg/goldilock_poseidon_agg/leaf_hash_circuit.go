package goldilock_poseidon_agg

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type LeafHashCircuit struct {
	RawData []gl.Variable

	MimcHash         frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`

	PrivateI frontend.Variable
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

	/*commitment, err := api.Compiler().(frontend.Committer).Commit(mimcHashOutput)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)*/

	api.AssertIsEqual(c.PrivateI, 1)

	/*commitment, err := api.Compiler().(frontend.Committer).Commit(c.PrivateI)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commitment, 0)*/

	return nil
}
