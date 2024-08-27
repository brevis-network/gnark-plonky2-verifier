package goldilock_poseidon_agg

import (
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
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
	CommitHash frontend.Variable `gnark:",public"` //TODO
	SmtRoot    frontend.Variable `gnark:",public"` // TODO

	AppCommitHash [2]frontend.Variable `gnark:",public"` // keccak // TODO
	AppVkHash     frontend.Variable    `gnark:",public"` // TODO

	// plonky2
	Plonky2PublicInputs            []gl.Variable // should be 4, equal to one goldilock poseidon hash
	Plonky2Proof                   variables.Proof
	Plonky2VerifierOnlyCircuitData variables.VerifierOnlyCircuitData
	// This is configuration for the circuit, it is a constant not a variable
	Plonky2CommonCircuitData types.CommonCircuitData

	HashProof        regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	HashVerifyingKey regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	HashInnerWitness regroth16.Witness[sw_bn254.ScalarField]

	CustomProof        replonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	CustomVerifyingKey replonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	CustomInnerWitness replonk.Witness[sw_bn254.ScalarField]
}

func (c *AggAllCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.CommitHash, 0)
	api.AssertIsEqual(c.SmtRoot, 0)
	api.AssertIsEqual(c.AppCommitHash[0], 0)
	api.AssertIsEqual(c.AppCommitHash[1], 0)
	api.AssertIsEqual(c.AppVkHash, 0)

	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	var placeholder []gl.Variable
	for i := 0; i < 30; i++ {
		placeholder = append(placeholder, gl.NewVariable(100))
	}
	for i := 0; i < 4; i++ {
		poseidonGlChip.HashNoPad(placeholder)
	}

	if err := c.AssertHashToHashGroth16proof(api); err != nil {
		return err
	}

	c.AssertPlonky2Proof(api)

	if err := c.AssertCustomProof(api); err != nil {
		return err
	}

	return nil
}

func (c *AggAllCircuit) AssertMimcHash(api frontend.API) {
	h0 := c.HashInnerWitness.Public[0].Limbs[3]
	h1 := c.HashInnerWitness.Public[0].Limbs[2]
	h2 := c.HashInnerWitness.Public[0].Limbs[1]
	h3 := c.HashInnerWitness.Public[0].Limbs[0]

	h0 = api.Mul(h0, big.NewInt(1).Lsh(big.NewInt(1), 192))
	h1 = api.Mul(h1, big.NewInt(1).Lsh(big.NewInt(1), 128))
	h2 = api.Mul(h2, big.NewInt(1).Lsh(big.NewInt(1), 64))
	res := api.Add(h0, h1, h2, h3)

	// TODO check
	api.AssertIsEqual(res, c.CustomInnerWitness.Public[0].Limbs[0])
}

func (c *AggAllCircuit) AssertGlHash(api frontend.API) {
	glAPI := gl.New(api)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	var placeholder []gl.Variable
	for i := 0; i < 30; i++ {
		placeholder = append(placeholder, gl.NewVariable(100))
	}
	for i := 0; i < 5; i++ {
		poseidonGlChip.HashNoPad(placeholder)
	}
	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[1].Limbs[0]), c.Plonky2PublicInputs[0])
	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[2].Limbs[0]), c.Plonky2PublicInputs[1])
	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[3].Limbs[0]), c.Plonky2PublicInputs[2])
	glAPI.AssertIsEqual(gl.NewVariable(c.HashInnerWitness.Public[4].Limbs[0]), c.Plonky2PublicInputs[3])
}

func (c *AggAllCircuit) AssertHashToHashGroth16proof(api frontend.API) error {
	verifier, err := regroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	err = verifier.AssertProof(c.HashVerifyingKey, c.HashProof, c.HashInnerWitness)
	if err != nil {
		return err
	}
	return nil
}

func (c *AggAllCircuit) AssertPlonky2Proof(api frontend.API) {
	verifierChip := plonky2verifier.NewVerifierChip(api, c.Plonky2CommonCircuitData)
	verifierChip.Verify(c.Plonky2Proof, c.Plonky2PublicInputs, c.Plonky2VerifierOnlyCircuitData)
}

func (c *AggAllCircuit) AssertCustomProof(api frontend.API) error {
	plonkVerifier, err := replonk.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	err = plonkVerifier.AssertProof(c.CustomVerifyingKey, c.CustomProof, c.CustomInnerWitness)
	if err != nil {
		return err
	}
	return nil
}

func NewAggAllCircuitAssigment(
	commitHash *big.Int,
	smtRoot *big.Int,
	appCommitHash [2]*big.Int,
	appVkHash *big.Int,

	plonky2VerifyOnlyJson string,
	plonky2ProofJson string,
	plonky2CommonOnlyJson string,

	hashProof groth16.Proof,
	hashWitness witness.Witness,
	hashVerifyKey groth16.VerifyingKey,

	customProof plonk.Proof,
	customWitness witness.Witness,
	customVk plonk.VerifyingKey) (*AggAllCircuit, error) {

	assigment := &AggAllCircuit{}

	// DO plonky2 assigment
	commonCircuitData, err := types.ReadCommonCircuitDataFromJson([]byte(plonky2CommonOnlyJson))
	if err != nil {
		return nil, err
	}
	proofWithPublicInputsRaw, err := types.ReadProofWithPublicInputsByJson([]byte(plonky2ProofJson))
	if err != nil {
		return nil, err
	}
	proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPublicInputsRaw)

	verifierOnlyCircuitDataRaw, err := types.ReadVerifierOnlyCircuitDataByJsonData([]byte(plonky2VerifyOnlyJson))
	if err != nil {
		return nil, err
	}
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitDataRaw)

	// do hash to hash groth16 proof assigment
	assigment.Plonky2CommonCircuitData = commonCircuitData
	assigment.Plonky2Proof = proofWithPis.Proof
	assigment.Plonky2PublicInputs = proofWithPis.PublicInputs
	assigment.Plonky2VerifierOnlyCircuitData = verifierOnlyCircuitData

	assigment.HashVerifyingKey, err = regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](hashVerifyKey)
	if err != nil {
		return nil, err
	}
	assigment.HashInnerWitness, err = regroth16.ValueOfWitness[sw_bn254.ScalarField](hashWitness)
	if err != nil {
		return nil, err
	}
	assigment.HashProof, err = regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](hashProof)
	if err != nil {
		return nil, err
	}

	// custom plonk
	assigment.CustomProof, err = replonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](customProof)
	assigment.CustomVerifyingKey, err = replonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](customVk)
	assigment.CustomInnerWitness, err = replonk.ValueOfWitness[sw_bn254.ScalarField](customWitness)

	assigment.CommitHash = commitHash
	assigment.SmtRoot = smtRoot
	assigment.AppCommitHash[0] = appCommitHash[0]
	assigment.AppCommitHash[1] = appCommitHash[1]
	assigment.AppVkHash = appVkHash

	return assigment, nil
}
