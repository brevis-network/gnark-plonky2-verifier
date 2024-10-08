package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"testing"
)

func TestSolveSmtCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	SolveSmtCircuit(assert)
}

func SolveSmtCircuit(assert *test.Assert) (circuit *Poseidon2Circuit, assigment *Poseidon2Circuit) {
	commonCircuitData := types.ReadCommonCircuitData("/Users/liuxiao/code/brevis-core/block_syncer/common_circuit_data.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("/Users/liuxiao/code/brevis-core/block_syncer/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("/Users/liuxiao/code/brevis-core/block_syncer/verifier_only_circuit_data.json"))

	circuit = &Poseidon2Circuit{
		Plonky2Proof:                   proofWithPis.Proof,
		Plonky2PublicInputs:            proofWithPis.PublicInputs,
		Plonky2VerifierOnlyCircuitData: verifierOnlyCircuitData,
		Plonky2CommonCircuitData:       commonCircuitData,
	}

	assigment = &Poseidon2Circuit{
		Plonky2Proof:                   proofWithPis.Proof,
		Plonky2PublicInputs:            proofWithPis.PublicInputs,
		Plonky2VerifierOnlyCircuitData: verifierOnlyCircuitData,
		Plonky2CommonCircuitData:       commonCircuitData,
	}

	err := test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	return circuit, assigment
}

type Poseidon2Circuit struct {
	// plonky2
	Plonky2PublicInputs            []gl.Variable // should be 4, equal to one goldilock poseidon hash
	Plonky2Proof                   variables.Proof
	Plonky2VerifierOnlyCircuitData variables.VerifierOnlyCircuitData
	// This is configuration for the circuit, it is a constant not a variable
	Plonky2CommonCircuitData types.CommonCircuitData
}

func (c *Poseidon2Circuit) Define(api frontend.API) error {
	c.AssertPlonky2Proof(api)
	return nil
}

func (c *Poseidon2Circuit) AssertPlonky2Proof(api frontend.API) {
	verifierChip := verifier.NewVerifierChip(api, c.Plonky2CommonCircuitData)
	verifierChip.Verify(c.Plonky2Proof, c.Plonky2PublicInputs, c.Plonky2VerifierOnlyCircuitData)
}
