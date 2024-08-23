package utils

import (
	"math/big"

	"github.com/brevis-network/zk-utils/common/proof"
)

func GetReceiptData(receipts []*proof.SDKQueryProvingInfoForReceipt) [][]uint64 {
	var result [][]uint64
	for _, receipt := range receipts {
		result = append(result, GetOneReceiptData(receipt))
	}
	return result
}

func GetOneReceiptData(receipt *proof.SDKQueryProvingInfoForReceipt) []uint64 {
	var res []uint64
	for _, logInfo := range receipt.LogExtractInfos {
		contractFields := parseHexStringToField(logInfo.ContractAddress)

		for len(contractFields) < 3 {
			contractFields = append(contractFields, 0)
		}
		reverseUint64Slice(contractFields)

		res = append(res, contractFields...)

		eventIDFields := parseHexStringToField(logInfo.LogTopic0[:14])
		res = append(res, eventIDFields...)

		if logInfo.ValueFromTopic {
			res = append(res, 1)
		} else {
			res = append(res, 0)
		}

		res = append(res, uint64(logInfo.ValueIndex))

		valueFields := parseHexStringToField(logInfo.Value)
		for len(valueFields) < 4 {
			valueFields = append(valueFields, 0)
		}
		reverseUint64Slice(valueFields)
		res = append(res, valueFields...)
	}

	for len(res) < 10*8 {
		res = append(res, 0)
	}
	res = append([]uint64{receipt.BlockNumber}, res...)
	return res
}

func reverseUint64Slice(slice []uint64) {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
}

func parseHexStringToField(hexStr string) []uint64 {
	hexStr = trimPrefix(hexStr, "0x")
	bigInt := new(big.Int)
	bigInt.SetString(hexStr, 16)

	chunkMask := new(big.Int)
	chunkMask.SetString("FFFFFFFFFFFFFFFF", 16)

	var chunks []uint64

	for bigInt.Cmp(big.NewInt(0)) > 0 {
		chunk := new(big.Int).And(bigInt, chunkMask)
		chunks = append(chunks, chunk.Uint64())
		bigInt.Rsh(bigInt, 64)
	}

	return chunks
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
