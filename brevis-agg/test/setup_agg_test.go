package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	tools "github.com/succinctlabs/gnark-plonky2-verifier/utils"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"os"
	"testing"
)

func TestSetupAggCircuit(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	circuit := &goldilock_poseidon_agg.AggAllCircuit{
		CommitHash:    0,
		SmtRoot:       0,
		AppCommitHash: [2]frontend.Variable{0, 0},
		AppVkHash:     0,
	}

	assigment := &goldilock_poseidon_agg.AggAllCircuit{
		CommitHash:    0,
		SmtRoot:       0,
		AppCommitHash: [2]frontend.Variable{0, 0},
		AppVkHash:     0,
	}

	//custom circuit
	cusCcs, cusProof, cusVk, cusWitness, err := goldilock_poseidon_agg.GetCustomDummyProof()
	assert.NoError(err)

	circuit.CustomProof = replonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](cusCcs)
	circuit.CustomVerifyingKey = replonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](cusCcs)
	circuit.CustomInnerWitness = replonk.PlaceholderWitness[sw_bn254.ScalarField](cusCcs)

	assigment.CustomProof, err = replonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](cusProof)
	assert.NoError(err)
	assigment.CustomVerifyingKey, err = replonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](cusVk)
	assert.NoError(err)
	assigment.CustomInnerWitness, err = replonk.ValueOfWitness[sw_bn254.ScalarField](cusWitness)
	assert.NoError(err)

	// groth16 hash2hash
	subProof1, err := tools.LoadProof("./proof/middle_from_middle_from_leaf_30.proof")
	assert.NoError(err)
	subVk1, err := tools.LoadVk("./proof/middle_from_middle_from_leaf_30.vk")
	assert.NoError(err)
	subWitness1, err := tools.LoadWitness("./proof/middle_from_middle_from_leaf_30.witness")
	assert.NoError(err)
	err = groth16.Verify(subProof1, subVk1, subWitness1, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	circuit.HashVerifyingKey, circuit.HashProof, circuit.HashInnerWitness = goldilock_poseidon_agg.GetMiddleNodeCircuitCcsPlaceHolder()

	assigment.HashVerifyingKey, err = regroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](subVk1)
	assert.NoError(err)
	assigment.HashInnerWitness, err = regroth16.ValueOfWitness[sw_bn254.ScalarField](subWitness1)
	assert.NoError(err)
	assigment.HashProof, err = regroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](subProof1)
	assert.NoError(err)

	plonky2Circuit := "plonky023"

	assigment.Plonky2CommonCircuitData = types.ReadCommonCircuitData("../../testdata/" + plonky2Circuit + "/common_circuit_data.json")
	assigment.Plonky2Proof = variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json")).Proof
	assigment.Plonky2PublicInputs = variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json")).PublicInputs
	assigment.Plonky2VerifierOnlyCircuitData = variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit.Plonky2CommonCircuitData = types.ReadCommonCircuitData("../../testdata/" + plonky2Circuit + "/common_circuit_data.json")
	circuit.Plonky2Proof = variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json")).Proof
	circuit.Plonky2PublicInputs = variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json")).PublicInputs
	circuit.Plonky2VerifierOnlyCircuitData = variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
