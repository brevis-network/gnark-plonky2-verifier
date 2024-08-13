package test

import (
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestGenLeafProof(t *testing.T) {
	assert := test.NewAssert(t)
	var data []uint64
	for i := 0; i < 30; i++ {
		data = append(data, 2178309)
	}
	_, subProof1, subVk1, subWitness1, _, _ := GetLeafProof(assert, data)
	err := groth16.Verify(subProof1, subVk1, subWitness1, regroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)
	log.Infof("get leaf done")

	err = utils.WriteProofIntoLocalFile(subProof1, "./proof/leaf_30.proof")
	assert.NoError(err)
	err = utils.WriteVerifyingKey(subVk1, "./proof/leaf_30.vk")
	assert.NoError(err)
	err = utils.WriteWitness("./proof/leaf_30.witness", subWitness1)
	assert.NoError(err)
}
