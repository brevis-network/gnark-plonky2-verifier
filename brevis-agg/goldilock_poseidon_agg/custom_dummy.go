package goldilock_poseidon_agg

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/multicommit"
)

type BatchPlonkCircuit struct {
	batchSize int

	InputCommitments  []frontend.Variable  `gnark:",public"`
	TogglesCommitment frontend.Variable    `gnark:",public"`
	OutputCommitment  [2]frontend.Variable `gnark:",public"`
}

func (c *BatchPlonkCircuit) Define(api frontend.API) error {
	for i := 0; i < c.batchSize; i++ {
		api.AssertIsEqual(c.InputCommitments[i], c.InputCommitments[0])
		//api.AssertIsEqual(c.TogglesCommitment, 1)
		api.AssertIsEqual(c.OutputCommitment[0], 1)
		api.AssertIsEqual(c.OutputCommitment[1], 1)
	}
	toggles := make([]frontend.Variable, c.batchSize)
	for i := 0; i < c.batchSize; i++ {
		toggles[i] = 1
	}
	toggles[c.batchSize-1] = 0
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	multicommit.WithCommitment(api, func(api frontend.API, gamma frontend.Variable) error {
		api.AssertIsDifferent(gamma, c.InputCommitments[0])
		return nil
	}, c.InputCommitments[:]...)

	packed := packBitsToFr(api, toggles[:])
	hasher.Write(packed...)
	togglesCommit := hasher.Sum()
	log.Infof("toggles hash: %x", togglesCommit)
	api.AssertIsEqual(togglesCommit, c.TogglesCommitment)
	log.Infof("out commit hash: %x", c.OutputCommitment)
	return nil
}

func packBitsToFr(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	bitSize := api.Compiler().FieldBitLen() - 1
	var r []frontend.Variable
	for i := 0; i < len(bits); i += bitSize {
		end := i + bitSize
		if end > len(bits) {
			end = len(bits)
		}
		z := api.FromBinary(bits[i:end]...)
		r = append(r, z)
	}
	return r
}
