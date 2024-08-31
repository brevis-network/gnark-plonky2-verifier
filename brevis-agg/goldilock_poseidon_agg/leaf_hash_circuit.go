package goldilock_poseidon_agg

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	poseidon_c_bn254 "github.com/brevis-network/zk-utils/circuits/gadgets/poseidon"
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/celer-network/goutils/log"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	regroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/ethereum/go-ethereum/common"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"math/big"
)

type LeafHashCircuit struct {
	RawData [LeafRawPubGlCount]gl.Variable
	Toggles [LeafRawPubGlCount]frontend.Variable

	CommitmentHash   frontend.Variable          `gnark:",public"`
	GoldilockHashOut poseidon.GoldilocksHashOut `gnark:",public"`
	TogglesHash      frontend.Variable          `gnark:",public"`
}

func (c *LeafHashCircuit) Define(api frontend.API) error {
	// do goldilock hash
	c.checkGlPoseidonHash(api)

	// use
	err := c.checkSdkCommitments(api)
	if err != nil {
		return err
	}

	err = c.checkTogglesCommitment(api)
	if err != nil {
		return err
	}

	return nil
}

func (c *LeafHashCircuit) checkSdkCommitments(api frontend.API) error {
	receipts := BuildReceiptFromGlData(api, c.RawData)
	pHasher, err := poseidon_c_bn254.NewBn254PoseidonCircuit(api)
	if err != nil {
		return err
	}
	var inputCommits [MaxReceiptPerLeaf]frontend.Variable
	for x, receipt := range receipts {
		packed := receipt.Pack(api)
		for i := 0; i < len(packed); i++ {
			pHasher.Write(packed[i])
		}
		sum := pHasher.Sum()
		pHasher.Reset()
		inputCommits[x] = sum
	}

	return c.checkLeafMerkelRoot(api, inputCommits)
}

func (c *LeafHashCircuit) checkGlPoseidonHash(api frontend.API) {
	// do goldilock hash
	// if less than 130 gl, should pad
	glAPI := gl.New(api)
	poseidonGlChip := poseidon.NewGoldilocksChip(api)
	output := poseidonGlChip.HashNoPad(c.RawData[:])
	// Check that output is correct
	for i := 0; i < 4; i++ {
		glAPI.AssertIsEqual(output[i], c.GoldilockHashOut[i])
	}
}

func (c *LeafHashCircuit) checkTogglesCommitment(api frontend.API) error {
	hasher, err := poseidon_c_bn254.NewBn254PoseidonCircuit(api)
	if err != nil {
		return err
	}

	tc := utils.PackBitsToFr(api, c.Toggles[:])
	for i := 0; i < len(tc); i++ {
		hasher.Write(tc[i])
	}
	sum := hasher.Sum()
	api.AssertIsEqual(c.TogglesHash, sum)
	return err
}

func (c *LeafHashCircuit) checkLeafMerkelRoot(api frontend.API, commitHash [MaxReceiptPerLeaf]frontend.Variable) error {
	hasher, err := poseidon_c_bn254.NewBn254PoseidonCircuit(api)
	if err != nil {
		return err
	}
	elementCount := MaxReceiptPerLeaf
	for {
		if elementCount == 1 {
			log.Infof("in circuitnputCommitmentsRoot: %x", commitHash[0])
			api.AssertIsEqual(commitHash[0], c.CommitmentHash)
			return nil
		}
		log.Infof("calMerkelRoot with element size: %d", elementCount)
		for i := 0; i < elementCount/2; i++ {
			hasher.Reset()
			hasher.Write(commitHash[2*i])
			hasher.Write(commitHash[2*i+1])
			commitHash[i] = hasher.Sum()
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

func GetLeafMimcHash(datas []uint64) (*big.Int, error) {
	receipts, err := GetLeafReceipts(datas)
	if err != nil {
		return nil, err
	}
	leafs := make([]*big.Int, MaxReceiptPerLeaf)
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
	log.Infof("mimc: %x", inputCommitmentsRoot)
	return leafs[0], nil
}
