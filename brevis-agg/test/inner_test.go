package test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"math/big"
	"os"
	"testing"
)

func TestBN254InBN254Commitment(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)

	innerCcs, innerVK, innerWitness, innerProof := getInnerCommitment(assert, ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
	assert.Equal(len(innerCcs.GetCommitments().CommitmentIndexes()), 1)

	// outer proof
	circuitVk, err := regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitWitness, err := regroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		Proof:        regroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs),
		InnerWitness: regroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: regroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)

	fmt.Println(fmt.Sprintf("ccs constraint: %d", ccs.GetNbConstraints()))
}

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        regroth16.Proof[G1El, G2El]
	VerifyingKey regroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness regroth16.Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := regroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	vks := []regroth16.VerifyingKey[G1El, G2El, GtEl]{c.VerifyingKey, c.VerifyingKey}
	proofs := []regroth16.Proof[G1El, G2El]{c.Proof, c.Proof}
	witnesses := []regroth16.Witness[FR]{c.InnerWitness, c.InnerWitness}

	return verifier.BatchAssertProofBrevis(vks, proofs, witnesses)

	//return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

func getInnerCommitment(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCircuitCommitment{})
	assert.NoError(err)
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitCommitment{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, regroth16.GetNativeProverOptions(outer, field))
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = groth16.Verify(innerProof, innerVK, innerPubWitness, regroth16.GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type InnerCircuitCommitment struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitCommitment) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)

	commitment, err := api.Compiler().(frontend.Committer).Commit(c.P, c.Q, c.N)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commitment, 0)

	return nil
}

type OuterCircuitDemo[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        [2]regroth16.Proof[G1El, G2El]
	VerifyingKey [2]regroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness [2]regroth16.Witness[FR]
}

func (c *OuterCircuitDemo[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := regroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	return verifier.BatchAssertProofBrevis(c.VerifyingKey[:], c.Proof[:], c.InnerWitness[:])
}
