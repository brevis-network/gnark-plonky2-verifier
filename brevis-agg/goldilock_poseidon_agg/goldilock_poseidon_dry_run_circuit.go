package goldilock_poseidon_agg

import (
	"fmt"
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
	"sync"
)

var (
	getGpHashLock sync.Mutex
	localPh       poseidon.GoldilocksHashOut
)

// only be used to cal poseidon hash
type GoldilockPoseidonDryRunCircuit struct {
	RawData []gl.Variable `gnark:",public"`
}

func (c *GoldilockPoseidonDryRunCircuit) Define(api frontend.API) error {
	poseidonGlChip := poseidon.NewGoldilocksChip(api)

	var placeholder []gl.Variable
	for i := 0; i < 129-len(c.RawData); i++ {
		placeholder = append(placeholder, gl.NewVariable(100))
	}
	poseidonGlChip.HashNoPad(placeholder)

	output := poseidonGlChip.HashNoPad(c.RawData)
	log.Infof("dry run gp hash result %v", output)
	localPh = output
	return nil
}

func GetGoldilockPoseidonHashByUint64(datas []uint64) (poseidon.GoldilocksHashOut, error) {
	var rawData []gl.Variable
	for i := 0; i < len(datas); i++ {
		rawData = append(rawData, gl.NewVariable(datas[i]))
	}
	return GetGoldilockPoseidonHashByGl(rawData)
}

func GetGoldilockPoseidonHashByGl(rawData []gl.Variable) (poseidon.GoldilocksHashOut, error) {
	getGpHashLock.Lock()
	defer getGpHashLock.Unlock()

	circuit := &GoldilockPoseidonDryRunCircuit{
		RawData: rawData,
	}

	w := &GoldilockPoseidonDryRunCircuit{
		RawData: rawData,
	}

	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())

	if err != nil {
		return [4]gl.Variable{}, err
	}

	res := [4]gl.Variable{localPh[0], localPh[1], localPh[2], localPh[3]}
	return res, err
}

func GetLeafReceipts(rawData []uint64) ([]*sdk.ReceiptData, error) {
	if len(rawData) != LeafRawPubGlCount {
		return nil, fmt.Errorf("invalid receipts data len: %d != %d", len(rawData), LeafRawPubGlCount)
	}
	var res []*sdk.ReceiptData
	for i := 0; i < MaxReceiptPerLeaf; i++ {
		oneReceipt, err := GetReceipt(rawData[i*GlCountPerReceipt : (i+1)*GlCountPerReceipt])
		if err != nil {
			log.Errorf("decode receipt %d fail, rawData:%v", i, rawData)
			return nil, err
		}
		res = append(res, oneReceipt)
	}
	return res, nil
}

func GetReceipt(rawData []uint64) (*sdk.ReceiptData, error) {
	if len(rawData) != GlCountPerReceipt {
		return nil, fmt.Errorf("invalid receipt data len: %d != %d", len(rawData), GlCountPerReceipt)
	}
	res := &sdk.ReceiptData{}
	res.BlockNum = new(big.Int).SetUint64(rawData[0])

	for j := 0; j < sdk.NumMaxLogFields; j++ {
		logStartOffset := 1 + j*GlCountPerReceiptLog // +1 is blk num
		var logField sdk.LogFieldData

		contractData := [GlContractLen]uint64{}
		for x := 0; x < GlContractLen; x++ {
			contractData[x] = rawData[logStartOffset]
			logStartOffset++
		}
		logField.Contract = BuildContract(contractData)

		logField.EventID = utils.Bytes2Hash(common.RightPadBytes(new(big.Int).SetUint64(rawData[logStartOffset]).Bytes(), 32))
		//log.Infof("logField.EventID: %x", logField.EventID)

		//log.Infof("logField.EventID: %x", logField.EventID)

		logStartOffset = logStartOffset + 1

		if rawData[logStartOffset] > 0 {
			logField.IsTopic = true
		} else {
			logField.IsTopic = false
		}
		logStartOffset = logStartOffset + 1

		logField.FieldIndex = uint(rawData[logStartOffset])
		logStartOffset = logStartOffset + 1

		valueData := [GlValueLen]uint64{}
		for x := 0; x < GlValueLen; x++ {
			valueData[x] = rawData[logStartOffset]
			logStartOffset++
		}

		logField.Value = BuildLogValue(valueData)

		res.Fields[j] = logField

		//log.Infof("receipt %d contract: %x", j, logField.Contract)
		//log.Infof("receipt %d event: %x", j, logField.EventID)
		//log.Infof("receipt %d value: %x", j, logField.Value)
	}
	return res, nil
}

func BuildContract(datas [GlContractLen]uint64) common.Address {
	h0 := new(big.Int).SetUint64(datas[0])
	h1 := new(big.Int).SetUint64(datas[1])
	h2 := new(big.Int).SetUint64(datas[2])

	h1 = new(big.Int).Mul(h1, big.NewInt(1).Lsh(big.NewInt(1), 64))
	h0 = new(big.Int).Mul(h0, big.NewInt(1).Lsh(big.NewInt(1), 128))

	return utils.Bytes2Addr(new(big.Int).Add(new(big.Int).Add(h0, h1), h2).Bytes())
}

// [0x, data0, data1, data2, data3]
func BuildLogValue(datas [GlValueLen]uint64) common.Hash {
	h0 := new(big.Int).SetUint64(datas[0])
	h1 := new(big.Int).SetUint64(datas[1])
	h2 := new(big.Int).SetUint64(datas[2])
	h3 := new(big.Int).SetUint64(datas[3])

	h2 = new(big.Int).Mul(h2, big.NewInt(1).Lsh(big.NewInt(1), 64))
	h1 = new(big.Int).Mul(h1, big.NewInt(1).Lsh(big.NewInt(1), 128))
	h0 = new(big.Int).Mul(h0, big.NewInt(1).Lsh(big.NewInt(1), 192))

	final := new(big.Int).Add(h3, h2)
	final = new(big.Int).Add(final, h1)
	final = new(big.Int).Add(final, h0)

	//data := sdk.ConstBytes32(utils.Bytes2Hash(final.Bytes()).Bytes())
	//log.Infof("%x %x", data.Val[0], data.Val[1])

	return utils.Bytes2Hash(final.Bytes())
}
