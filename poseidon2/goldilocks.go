package poseidon2

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
)

const HALF_N_FULL_ROUNDS = 4
const SPONGE_WIDTH = 8
const N_PARTIAL_ROUNDS = 22

const POSEIDON2_GL_HASH_SIZE = 4

type GoldilocksState = [SPONGE_WIDTH]gl.Variable
type GoldilocksStateExtension = [SPONGE_WIDTH]gl.QuadraticExtensionVariable
type GoldilocksHashOut = [POSEIDON2_GL_HASH_SIZE]gl.Variable

type GoldilocksChip struct {
	api frontend.API `gnark:"-"`
	gl  *gl.Chip     `gnark:"-"`
}

func NewGoldilocksChip(api frontend.API) *GoldilocksChip {
	return &GoldilocksChip{api: api, gl: gl.New(api)}
}

func (c *GoldilocksChip) MatmulExternalField(state GoldilocksStateExtension) GoldilocksStateExtension {
	state = c.MatmulM4Field(state)

	//log.Infof("c.MatmulM4Field(state): %+v", state)

	stored := [4]gl.QuadraticExtensionVariable{
		gl.ZeroExtension(),
		gl.ZeroExtension(),
		gl.ZeroExtension(),
		gl.ZeroExtension(),
	}

	t4 := SPONGE_WIDTH / 4

	for l := 0; l < 4; l++ {
		stored[l] = state[l]
		for j := 1; j < t4; j++ {
			stored[l] = c.gl.AddExtension(stored[l], state[4*j+l])
		}

		//log.Infof("l: %d, stored: %+v", l, stored)
	}
	for i := 0; i < len(state); i++ {
		state[i] = c.gl.AddExtension(state[i], stored[i%4])
	}
	return state
}

func (c *GoldilocksChip) MatmulM4Field(state GoldilocksStateExtension) GoldilocksStateExtension {
	for i := 0; i < SPONGE_WIDTH/4; i++ {
		start_index := i * 4

		//log.Infof("MatmulM4Field input start_index %d %v", start_index, state[start_index])

		t0 := state[start_index]

		t0 = c.gl.AddExtension(t0, state[start_index+1])

		//log.Infof("MatmulM4Field t0 after add %d %v", start_index, state)

		t1 := state[start_index+2]

		t1 = c.gl.AddExtension(t1, state[start_index+3])

		//log.Infof("MatmulM4Field t1 after add %d %v", start_index, state)

		two := gl.NewQuadraticExtensionVariable(c.gl.Add(gl.One(), gl.One()), gl.Zero())
		four := c.gl.AddExtension(two, two)

		// t2
		t2 := t1
		t2 = c.gl.MulAddExtension(state[start_index+1], two, t2)

		//log.Infof("MatmulM4Field t2 after add %d %v", start_index, state)

		// t3
		t3 := t0
		t3 = c.gl.MulAddExtension(state[start_index+3], two, t3)

		//log.Infof("MatmulM4Field t3 after add %d %v", start_index, state)

		// t4
		t4 := t3
		t4 = c.gl.MulAddExtension(t1, four, t4)

		//log.Infof("MatmulM4Field t4 after add %d %v", start_index, state)

		// t5
		t5 := t2
		t5 = c.gl.MulAddExtension(t0, four, t5)
		//log.Infof("MatmulM4Field t5 after add %d %v", start_index, state)

		state[start_index] = c.gl.AddExtension(t3, t5)
		state[start_index+1] = t5
		state[start_index+2] = c.gl.AddExtension(t2, t4)
		state[start_index+3] = t4
	}

	return state
}

func (c *GoldilocksChip) ConstantLayerExtension(state GoldilocksStateExtension, roundCounter uint64) GoldilocksStateExtension {
	for i := 0; i < SPONGE_WIDTH; i++ {
		roundConstant := gl.NewVariable(RC[roundCounter][i])

		roundConstantQE := gl.NewQuadraticExtensionVariable(roundConstant, gl.Zero())
		state[i] = c.gl.AddExtension(state[i], roundConstantQE)
	}
	return state
}

func (c *GoldilocksChip) SBoxLayerExtension(state GoldilocksStateExtension) GoldilocksStateExtension {
	for i := 0; i < SPONGE_WIDTH; i++ {
		state[i] = c.SBoxMonomialExtension(state[i])
	}
	return state
}

func (c *GoldilocksChip) SBoxMonomialExtension(x gl.QuadraticExtensionVariable) gl.QuadraticExtensionVariable {
	x2 := c.gl.MulExtension(x, x)
	x4 := c.gl.MulExtension(x2, x2)
	x3 := c.gl.MulExtension(x, x2)
	return c.gl.MulExtension(x4, x3)
}

func (c *GoldilocksChip) MatmulInternalField(state GoldilocksStateExtension) GoldilocksStateExtension {
	sum := state[0]
	for i := 1; i < SPONGE_WIDTH; i++ {
		sum = c.gl.AddExtension(sum, state[i])
	}
	for i := 0; i < SPONGE_WIDTH; i++ {
		roundConstant := gl.NewVariable(c.api.Sub(MAT_DIAG_M_1[i], 1))
		roundConstantQE := gl.NewQuadraticExtensionVariable(roundConstant, gl.Zero())

		state[i] = c.gl.MulExtension(state[i], roundConstantQE)
		state[i] = c.gl.AddExtension(state[i], sum)
	}
	return state
}
