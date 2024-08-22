package goldilock_poseidon_agg

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/multicommit"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
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

func GetCustomDummyProof() (constraint.ConstraintSystem, plonk.Proof, plonk.VerifyingKey, witness.Witness, error) {
	circuit := &CustomPlonkCircuit{
		InputCommitmentsRoot: 100,
		TogglesCommitment:    100,
		OutputCommitment:     [2]frontend.Variable{100, 100},
	}

	assigment := &CustomPlonkCircuit{
		InputCommitmentsRoot: 100,
		TogglesCommitment:    100,
		OutputCommitment:     [2]frontend.Variable{100, 100},
	}

	err := test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	witnessFull, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	witnessPublic, err := witnessFull.Public()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	canonical, lagrange, err := unsafekzg.NewSRS(ccs)

	pk, vk, err := plonk.Setup(ccs, canonical, lagrange)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	plonkProof, err := plonk.Prove(ccs, pk, witnessFull, replonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	fmt.Println(">> verify")
	err = plonk.Verify(plonkProof, vk, witnessPublic, replonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return ccs, plonkProof, vk, witnessPublic, nil
}
