package test

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/goldilock_poseidon_agg"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"math/big"
	"os"
	"testing"
)

func TestDummyLeaf(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)
	var datas [goldilock_poseidon_agg.LeafRawPubGlCount]uint64
	var glDatas [goldilock_poseidon_agg.LeafRawPubGlCount]gl.Variable
	for i := 0; i < goldilock_poseidon_agg.LeafRawPubGlCount; i++ {
		glDatas[i] = gl.NewVariable(0)
		datas[i] = 0
	}

	glHash, err := goldilock_poseidon_agg.GetGoldilockPoseidonHashByUint64(datas[:])
	assert.NoError(err)
	log.Infof("glHash: %v", glHash)

	receipts, err := goldilock_poseidon_agg.GetLeafReceipts(datas[:])
	assert.NoError(err)
	leafs := make([]*big.Int, goldilock_poseidon_agg.MaxReceiptPerLeaf)
	hasher := mimc_bn254.NewMiMC()

	for i, receipt := range receipts {
		//log.Infof("xx eventId: %x", sdk.ConstUint248(receipt.Fields[0].EventID[:6]).Val)
		receiptInput := sdk.Receipt{
			BlockNum: sdk.Uint248{Val: receipt.BlockNum},
			Fields:   sdk.BuildLogFields(receipt.Fields),
		}

		//log.Infof("start write one receipt %d", i)
		for _, v := range receiptInput.GoPack() {
			//log.Infof("write: %x", common.LeftPadBytes(v.Bytes(), 32))
			hasher.Write(common.LeftPadBytes(v.Bytes(), 32))
		}

		leafs[i] = new(big.Int).SetBytes(hasher.Sum(nil))
		//log.Infof("leaf %d: %x", i, leafs[i])
		hasher.Reset()
	}

	var inputCommitmentsRoot frontend.Variable
	elementCount := len(leafs)
	for {
		if elementCount == 1 {
			inputCommitmentsRoot = leafs[0]
			log.Infof("w.InputCommitmentsRoot: %x", inputCommitmentsRoot)
			break
		}
		log.Infof("calMerkelRoot(no circuit) with element size: %d", elementCount)
		for i := 0; i < elementCount/2; i++ {
			var mimcBlockBuf0, mimcBlockBuf1 [mimc_bn254.BlockSize]byte
			leafs[2*i].FillBytes(mimcBlockBuf0[:])
			leafs[2*i+1].FillBytes(mimcBlockBuf1[:])
			hasher.Reset()
			hasher.Write(mimcBlockBuf0[:])
			hasher.Write(mimcBlockBuf1[:])
			leafs[i] = new(big.Int).SetBytes(hasher.Sum(nil))
		}
		elementCount = elementCount / 2
	}

	//circuitMimcHash := new(big.Int).SetBytes(mimcHash)

	circuit := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          glDatas,
		MimcHash:         inputCommitmentsRoot,
		GoldilockHashOut: glHash,
	}

	assigment := &goldilock_poseidon_agg.LeafHashCircuit{
		RawData:          glDatas,
		MimcHash:         inputCommitmentsRoot,
		GoldilockHashOut: glHash,
	}

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	log.Infof("leaf circuit solve done")
}
