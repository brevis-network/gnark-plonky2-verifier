package goldilock_poseidon_agg

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	plonky2verifier "github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"math/big"
)

type AggAllCircuit struct {
	//CommitHash frontend.Variable `gnark:",public"`
	//SmtRoot    frontend.Variable `gnark:",public"`

	//AppCommitHash frontend.Variable `gnark:",public"` // keccak
	//AppVkHash     frontend.Variable `gnark:",public"`

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
	glAPI := gl.New(api)

	h0 := c.HashInnerWitness.Public[0].Limbs[3]
	h1 := c.HashInnerWitness.Public[0].Limbs[2]
	h2 := c.HashInnerWitness.Public[0].Limbs[1]
	h3 := c.HashInnerWitness.Public[0].Limbs[0]

	h0 = api.Mul(h0, big.NewInt(1).Lsh(big.NewInt(1), 192))
	h1 = api.Mul(h1, big.NewInt(1).Lsh(big.NewInt(1), 128))
	h2 = api.Mul(h2, big.NewInt(1).Lsh(big.NewInt(1), 64))
	res := api.Add(h0, h1, h2, h3)
	api.AssertIsEqual(res, c.MimcHash)

	//
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	var placeholder []gl.Variable
	for i := 0; i < 30; i++ {
		placeholder = append(placeholder, gl.NewVariable(100))
	}
	for i := 0; i < 5; i++ {
		poseidonGlChip.HashNoPad(placeholder)
	}
	//

	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[1].Limbs[0]), c.GoldilockHashOut[0])
	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[2].Limbs[0]), c.GoldilockHashOut[1])
	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[3].Limbs[0]), c.GoldilockHashOut[2])
	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[4].Limbs[0]), c.GoldilockHashOut[3])

	verifier, err := regroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	err = verifier.AssertProof(c.HashVerifyingKey, c.HashProof, c.HashInnerWitness)
	if err != nil {
		return err
	}

	verifierChip := plonky2verifier.NewVerifierChip(api, c.Plonky2CommonCircuitData)
	verifierChip.Verify(c.Plonky2Proof, c.Plonky2PublicInputs, c.Plonky2VerifierOnlyCircuitData)

	plonkVerifier, err := replonk.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return err
	}
	err = plonkVerifier.AssertProof(c.CustomVerifyingKey, c.CustomProof, c.CustomInnerWitness)
	if err != nil {
		return err
	}

	return nil
}
