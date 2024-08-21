package goldilock_poseidon_agg

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
	"math/big"
)

type CustomPlonkCircuit struct {
	InputCommitmentsRoot frontend.Variable    `gnark:",public"`
	TogglesCommitment    frontend.Variable    `gnark:",public"`
	OutputCommitment     [2]frontend.Variable `gnark:",public"`
}

func (c *CustomPlonkCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.InputCommitmentsRoot, c.TogglesCommitment)
	api.AssertIsEqual(c.InputCommitmentsRoot, c.OutputCommitment[0])
	api.AssertIsEqual(c.InputCommitmentsRoot, c.OutputCommitment[1])

	multicommit.WithCommitment(api, func(api frontend.API, gamma frontend.Variable) error {
		api.AssertIsDifferent(gamma, 1)
		return nil
	}, c.InputCommitmentsRoot)
	return nil
}

func GetCustomDummyProof(rootHash *big.Int) {

}
