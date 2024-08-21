package test

import (
	"fmt"
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/rs/zerolog"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	"math/big"
	"os"
	"testing"
)

func TestDemo(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)
	app, err := sdk.NewBrevisApp()
	assert.NoError(err)

	logFiledFata := sdk.LogFieldData{
		Contract:   utils.Hex2Addr("0x961ad289351459a45fc90884ef3ab0278ea95dde"),
		LogIndex:   0,
		EventID:    utils.Hex2Hash("0xf6a97944f31ea060dfde0566e4167c1a1082551e64b60ecb14d599a9d023d451"),
		IsTopic:    false,
		FieldIndex: 0,
		Value:      utils.Hex2Hash("0x00000000000000000000000000000000000000000000000000000574335d87c5"),
	}

	receipt := sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(13898775),
		TxHash:   utils.Hex2Hash("0xbef5e22dec94fd5ed9630f3cee52d7d914ad796f5a31048086f8a956892db05e"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
		},
	}

	for i := 0; i < 16; i++ {
		app.AddReceipt(receipt)
	}

	guest := &AppCircuit{}
	guestAssignment := &AppCircuit{}

	circuitInput, err := app.BuildCircuitInput(guest)
	assert.NoError(err)

	host := sdk.DefaultHostCircuit(guest)
	assignment := sdk.NewHostCircuit(circuitInput.Clone(), guestAssignment)

	err = test.IsSolved(host, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	witnessFull, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	witnessPublic, err := witnessFull.Public()
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, host)
	assert.NoError(err)

	canonical, lagrange, err := unsafekzg.NewSRS(ccs)

	pk, vk, err := plonk.Setup(ccs, canonical, lagrange)
	assert.NoError(err)

	plonkProof, err := plonk.Prove(ccs, pk, witnessFull, replonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	fmt.Println(">> verify")
	err = plonk.Verify(plonkProof, vk, witnessPublic, replonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	//test2.ProverSucceeded(t, guest, guestAssignment, circuitInput)
}

type AppCircuit struct{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// Our app is only ever going to use one storage data at a time so
	// we can simply limit the max number of data for storage to 1 and
	// 0 for all others
	return 16, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	return nil
}

func TestDummy(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)

	circuit := &goldilock_poseidon_agg.CustomPlonkCircuit{
		InputCommitmentsRoot: 100,
		TogglesCommitment:    100,
		OutputCommitment:     [2]frontend.Variable{100, 100},
	}

	assigment := &goldilock_poseidon_agg.CustomPlonkCircuit{
		InputCommitmentsRoot: 100,
		TogglesCommitment:    100,
		OutputCommitment:     [2]frontend.Variable{100, 100},
	}

	err := test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	witnessFull, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	assert.NoError(err)

	witnessPublic, err := witnessFull.Public()
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)

	canonical, lagrange, err := unsafekzg.NewSRS(ccs)

	pk, vk, err := plonk.Setup(ccs, canonical, lagrange)
	assert.NoError(err)

	plonkProof, err := plonk.Prove(ccs, pk, witnessFull, replonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	fmt.Println(">> verify")
	err = plonk.Verify(plonkProof, vk, witnessPublic, replonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)
}
