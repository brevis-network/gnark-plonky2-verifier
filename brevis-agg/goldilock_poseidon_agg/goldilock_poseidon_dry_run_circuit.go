package goldilock_poseidon_agg

import (
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
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
