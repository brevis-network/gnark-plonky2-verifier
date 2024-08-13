package test

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	"testing"
)

func TestDummyMiddle(t *testing.T) {
	assert := test.NewAssert(t)
	ccs, err := goldilock_poseidon_agg.GetDummyMiddleNodeCcs()
	assert.NoError(err)

	log.Infof("leaf ccs data2: proof size: %d", len(ccs.GetCommitments().(constraint.Groth16Commitments)))
	log.Infof("leaf ccs data2: proof size: %d", ccs.GetNbPublicVariables()-1)
	log.Infof("leaf ccs data2: proof size: %d", ccs.GetNbPublicVariables()+len(ccs.GetCommitments().(constraint.Groth16Commitments)))
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	commitmentWires := commitments.CommitmentIndexes()
	log.Infof("leaf ccs data2: proof size: %d", commitments.GetPublicAndCommitmentCommitted(commitmentWires, ccs.GetNbPublicVariables()))
}
