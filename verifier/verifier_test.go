package verifier_test

import (
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"log"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

func TestStepVerifier(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)

	//plonky2Circuit := "decode_block"
	//plonky2Circuit := "step"
	//plonky2Circuit := "resursion_plonky2"
	//plonky2Circuit := "dummy"
	//plonky2Circuit := "origin_recursion"
	//plonky2Circuit := "plonky023"
	//plonky2Circuit := "plonky2_agg_wrapper"
	plonky2Circuit := "plonky022"
	commonCircuitData := types.ReadCommonCircuitData("../testdata/" + plonky2Circuit + "/common_circuit_data.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	witness := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	log.Println("solve done")

	//circuitWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	//assert.NoError(err)

	//pubW, err := circuitWitness.Public()
	//assert.NoError(err)

	//ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	//assert.NoError(err)
	//fmt.Printf("nb constraint: %d\n", ccs.GetNbConstraints())

	/*pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalln(err)
	}

	pf, err := groth16.Prove(ccs, pk, circuitWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(err)

	rp := pf.(*groth162.Proof)
	fmt.Printf("rp.CommitmentPok: %+v", rp.CommitmentPok)
	fmt.Printf("rp.Commitments: %+v", rp.Commitments)

	err = groth16.Verify(pf, vk, pubW, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(err)*/
}
