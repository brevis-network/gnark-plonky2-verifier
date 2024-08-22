package test

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/brevis-network/zk-utils/common/proof"
	"github.com/succinctlabs/gnark-plonky2-verifier/brevis-agg/utils"
)

func TestStarkyInfo(t *testing.T) {

	jsonFile, _ := os.Open("receipt_witness_data.json")

	data, _ := io.ReadAll(jsonFile)

	var receipt_info *proof.SDKQueryProvingInfoForReceipt
	_ = json.Unmarshal(data, &receipt_info)

	receipts := []*proof.SDKQueryProvingInfoForReceipt{
		receipt_info,
	}
	publicInputs := utils.GetReceiptData(receipts)
	fmt.Println("publicInputs:", publicInputs)
}
