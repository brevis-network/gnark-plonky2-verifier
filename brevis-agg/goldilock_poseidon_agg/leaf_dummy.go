package goldilock_poseidon_agg

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type LeafDummyCircuit struct {
	PrivateI frontend.Variable
	MimcHash [5]frontend.Variable `gnark:",public"`
}

func (c *LeafDummyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.MimcHash[0], 1)
	api.AssertIsEqual(c.MimcHash[1], 1)
	api.AssertIsEqual(c.MimcHash[2], 1)
	api.AssertIsEqual(c.MimcHash[3], 1)
	api.AssertIsEqual(c.MimcHash[4], 1)
	api.AssertIsEqual(c.PrivateI, 1)

	commitment, err := api.Compiler().(frontend.Committer).Commit(c.PrivateI)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)

	return nil
}

func GetDummyLeafCcs() (constraint.ConstraintSystem, error) {
	circuit := &LeafDummyCircuit{
		PrivateI: 1,
		MimcHash: [5]frontend.Variable{1, 1, 1, 1, 1},
	}

	assigment := &LeafDummyCircuit{
		PrivateI: 1,
		MimcHash: [5]frontend.Variable{1, 1, 1, 1, 1},
	}

	err := test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
}
