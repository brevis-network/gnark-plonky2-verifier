package goldilock_poseidon_agg

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type AggAllCircuit struct {
	CommitHash frontend.Variable `gnark:",public"`
	SmtRoot    frontend.Variable `gnark:",public"`

	AppCommitHash frontend.Variable `gnark:",public"` // keccak
	AppVkHash     frontend.Variable `gnark:",public"`

	// plonky2
	Plonky2PublicInputs            []gl.Variable // should be 4, equal to one goldilock poseidon hash
	Plonky2Proof                   variables.Proof
	Plonky2VerifierOnlyCircuitData variables.VerifierOnlyCircuitData
	// This is configuration for the circuit, it is a constant not a variable
	Plonky2CommonCircuitData types.CommonCircuitData

	MimcHash         frontend.Variable          // the hash custom circuit use
	GoldilockHashOut poseidon.GoldilocksHashOut // the hash equal to plonky2 public input

	HashProof        regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	HashVerifyingKey regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	HashInnerWitness regroth16.Witness[sw_bn254.ScalarField]

	CustomProof        replonk.Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	CustomVerifyingKey replonk.VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	CustomInnerWitness replonk.Witness[sw_bls12377.ScalarField]
}

func (c *AggAllCircuit) Define(api frontend.API) error {
	return nil
}
