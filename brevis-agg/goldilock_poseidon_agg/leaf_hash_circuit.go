package goldilock_poseidon_agg

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/mimc"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
)

type LeafHashCircuit struct {
	RawData [LeafRawPubGlCount]gl.Variable

	MimcHash         frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`
}

func (c *LeafHashCircuit) Define(api frontend.API) error {
	glAPI := gl.New(api)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	output := poseidonGlChip.HashNoPad(c.RawData[:])

	/*var placeholder []gl.Variable
	for i := 0; i < 30; i++ {
		placeholder = append(placeholder, gl.NewVariable(100))
	}
	for i := 0; i < 4; i++ {
		poseidonGlChip.HashNoPad(placeholder)
	}*/

	// Check that output is correct
	for i := 0; i < 4; i++ {
		glAPI.AssertIsEqual(output[i], c.GoldilockHashOut[i])
	}

	receipts := BuildReceiptFromGlData(api, c.RawData)

	mimcHasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	var inputCommits []frontend.Variable
	for x, receipt := range receipts {
		packed := receipt.Pack(api)

		/*log.Infof("in circuit hash %d", x)
		for _, p := range packed {
			log.Infof("in circuit hash: %x", p)
		}*/

		mimcHasher.Write(packed...)
		sum := mimcHasher.Sum()
		mimcHasher.Reset()

		//log.Infof("in circuit receipt commitments %d: %x", x, sum)

		inputCommits = append(inputCommits, sum)
	}

	inputCommitmentsRoot, err := calMerkelRoot(api, inputCommits)
	if err != nil {
		return err
	}

	//log.Infof("inputCommitmentsRoot: %x", inputCommitmentsRoot)

	api.AssertIsEqual(inputCommitmentsRoot, c.MimcHash)
	//log.Infof("c.MimcHash: %x, mimcHashOutput: %x", c.MimcHash, mimcHashOutput)

	return nil
}

func calMerkelRoot(api frontend.API, datas []frontend.Variable) (frontend.Variable, error) {
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	elementCount := len(datas)
	leafs := make([]frontend.Variable, elementCount)
	copy(leafs, datas)
	for {
		if elementCount == 1 {
			log.Infof("in circuitnputCommitmentsRoot: %x", leafs[0])
			return leafs[0], nil
		}
		log.Infof("calMerkelRoot with element size: %d", elementCount)
		for i := 0; i < elementCount/2; i++ {
			hasher.Reset()
			hasher.Write(leafs[2*i])
			hasher.Write(leafs[2*i+1])
			leafs[i] = hasher.Sum()
		}
		elementCount = elementCount / 2
	}
}

func GetLeafCircuitCcsPlaceHolder() (regroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], regroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine], regroth16.Witness[sw_bn254.ScalarField]) {
	nbPublicVariables := 6
	commitmentsLen := 1
	publicAndCommitmentCommitted := [][]int{{}}

	batchVkPlaceHolder := regroth16.PlaceholderVerifyingKeyWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](nbPublicVariables, commitmentsLen, publicAndCommitmentCommitted)
	batchProofPlaceHolder := regroth16.PlaceholderProofWithParam[sw_bn254.G1Affine, sw_bn254.G2Affine](commitmentsLen)
	batchWitnessPlaceHolder := regroth16.PlaceholderWitnessWithParam[sw_bn254.ScalarField](nbPublicVariables)

	return batchVkPlaceHolder, batchProofPlaceHolder, batchWitnessPlaceHolder
}

const LeafRawPubGlCount = MaxReceiptPerLeaf * GlCountPerReceipt
const MaxReceiptPerLeaf = 16
const GlCountPerReceipt = GlCountPerReceiptLog*sdk.NumMaxLogFields + 1 // +1 is blk num
const GlCountPerReceiptLog = 10

const GlBlkNumLen = 1
const GlContractLen = 3
const GlEventIdLen = 1
const GlIsTopicLen = 1
const GlFieldIndexLen = 1
const GlValueLen = 4

func BuildReceiptFromGlData(api frontend.API, glDatas [LeafRawPubGlCount]gl.Variable) [MaxReceiptPerLeaf]sdk.Receipt {
	var receipts [MaxReceiptPerLeaf]sdk.Receipt
	for i := 0; i < MaxReceiptPerLeaf; i++ {
		startOffset := i * GlCountPerReceipt
		receipts[i] = sdk.Receipt{
			BlockNum: sdk.Uint248{Val: glDatas[startOffset].Limb},
		}
		//log.Infof("blk num in circuit: %x", receipts[i].BlockNum)
		for j := 0; j < sdk.NumMaxLogFields; j++ {
			logStartOffset := (startOffset + 1) + j*GlCountPerReceiptLog // +1 is blk num
			var logField sdk.LogField

			contractData := [GlContractLen]gl.Variable{}
			for x := 0; x < GlContractLen; x++ {
				contractData[x] = glDatas[logStartOffset]
				logStartOffset++
			}
			logField.Contract = BuildCircuitContract(api, contractData)

			//log.Infof("%d %d contract in circuit: %v", i, j, logField.Contract)

			//log.Infof("EventID: %x %v", glDatas[logStartOffset].Limb, glDatas[logStartOffset].Limb)

			logField.EventID = sdk.Uint248{Val: glDatas[logStartOffset].Limb}
			logStartOffset = logStartOffset + 1

			logField.IsTopic = sdk.Uint248{Val: glDatas[logStartOffset].Limb}
			logStartOffset = logStartOffset + 1

			logField.Index = sdk.Uint248{Val: glDatas[logStartOffset].Limb}
			logStartOffset = logStartOffset + 1

			valueData := [GlValueLen]gl.Variable{}
			for x := 0; x < GlValueLen; x++ {
				valueData[x] = glDatas[logStartOffset]
				logStartOffset++
			}
			logField.Value = BuildCircuitLogValue(api, valueData)

			receipts[i].Fields[j] = logField
		}
	}
	return receipts
}

func BuildCircuitContract(api frontend.API, data [GlContractLen]gl.Variable) sdk.Uint248 {
	h0 := data[0].Limb
	h1 := data[1].Limb
	h2 := data[2].Limb

	h1 = api.Mul(h1, big.NewInt(1).Lsh(big.NewInt(1), 64))
	h0 = api.Mul(h0, big.NewInt(1).Lsh(big.NewInt(1), 128))

	//log.Infof("%x", api.Add(h0, h1, h2))

	return sdk.Uint248{Val: api.Add(h0, h1, h2)}
}

func BuildCircuitLogValue(api frontend.API, data [GlValueLen]gl.Variable) sdk.Bytes32 {
	h0 := data[0].Limb
	h1 := data[1].Limb
	h2 := data[2].Limb
	h3 := data[3].Limb

	var all []frontend.Variable
	all = append(all, api.ToBinary(h3, 64)...)
	all = append(all, api.ToBinary(h2, 64)...)
	all = append(all, api.ToBinary(h1, 64)...)
	all = append(all, api.ToBinary(h0, 64)...)

	res := sdk.Bytes32{}
	res.Val[0] = api.FromBinary(all[:numBitsPerVar]...)
	res.Val[1] = api.FromBinary(all[numBitsPerVar:]...)

	return res
}

var numBitsPerVar = 248
