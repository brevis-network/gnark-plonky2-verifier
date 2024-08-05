package poseidon

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"testing"
)

type GPCircuit struct {
	In  frontend.Variable
	Out frontend.Variable
}

func (c *GPCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.In, c.Out)

	poseidonGlChip := NewGoldilocksChip(api)

	one := []gl.Variable{}
	for i := 0; i < 100; i++ {
		one = append(one, gl.NewVariable(2178309))
	}
	poseidonGlChip.HashNoPad(one)

	return nil
}

func TestGp(t *testing.T) {
	assert := test.NewAssert(t)
	c := &GPCircuit{
		1, 1,
	}
	w := &GPCircuit{
		1, 1,
	}

	err := test.IsSolved(c, w, ecc.BN254.ScalarField())
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	assert.NoError(err)
	fmt.Printf("ccs: %d \n", ccs.GetNbConstraints())

	ccs2, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c)
	assert.NoError(err)
	fmt.Printf("ccs2: %d \n", ccs2.GetNbConstraints())
}
