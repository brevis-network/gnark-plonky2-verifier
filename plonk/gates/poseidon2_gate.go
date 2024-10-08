package gates

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon2"
	"regexp"
)

var poseidon2GateRegex = regexp.MustCompile("Poseidon2Gate.*")

func deserializePoseidon2Gate(parameters map[string]string) Gate {
	// Has the format "Poseidon2Gate(PhantomData<plonky2_field::goldilocks_field::GoldilocksField>)<WIDTH=8>"
	return NewPoseidon2Gate()
}

type Poseidon2Gate struct {
}

func NewPoseidon2Gate() *Poseidon2Gate {
	return &Poseidon2Gate{}
}

func (g *Poseidon2Gate) Id() string {
	return "Poseidon2Gate"
}

func (g *Poseidon2Gate) WireInput(i uint64) uint64 {
	return i
}

func (g *Poseidon2Gate) WireOutput(i uint64) uint64 {
	return poseidon2.SPONGE_WIDTH + i
}

func (g *Poseidon2Gate) WireSwap() uint64 {
	return 2 * poseidon2.SPONGE_WIDTH
}

const POSEIDON2_START_DELTA = 2*poseidon2.SPONGE_WIDTH + 1

func (g *Poseidon2Gate) WireDelta(i uint64) uint64 {
	if i >= 4 {
		panic("Delta index out of range")
	}
	return POSEIDON2_START_DELTA + i
}

const POSEIDON2_START_FULL_0 = POSEIDON2_START_DELTA + 4

func (g *Poseidon2Gate) WireFullRoundBegin(round uint64, i uint64) uint64 {
	if round == 0 {
		panic("First-round S-box inputs are not stored as wires")
	}
	if round >= poseidon2.HALF_N_FULL_ROUNDS {
		panic("S-box input round out of range")
	}
	if i >= poseidon2.SPONGE_WIDTH {
		panic("S-box input index out of range")
	}

	return POSEIDON2_START_FULL_0 + (round-1)*poseidon2.SPONGE_WIDTH + i
}

const POSEIDON2_START_PARTIAL = POSEIDON2_START_FULL_0 + (poseidon2.HALF_N_FULL_ROUNDS-1)*poseidon2.SPONGE_WIDTH

func (g *Poseidon2Gate) WirePartialSBox(round uint64) uint64 {
	if round >= poseidon2.N_PARTIAL_ROUNDS {
		panic("S-box input round out of range")
	}
	return POSEIDON2_START_PARTIAL + round
}

const POSEIDON2_START_FULL_1 = POSEIDON2_START_PARTIAL + poseidon2.N_PARTIAL_ROUNDS

func (g *Poseidon2Gate) WireFullSBox1(round uint64, i uint64) uint64 {
	if round >= poseidon2.HALF_N_FULL_ROUNDS {
		panic("S-box input round out of range")
	}
	if i >= poseidon2.SPONGE_WIDTH {
		panic("S-box input index out of range")
	}

	return POSEIDON2_START_FULL_1 + round*poseidon2.SPONGE_WIDTH + i
}

func (g *Poseidon2Gate) WiresEnd() uint64 {
	return POSEIDON2_START_FULL_1 + poseidon2.HALF_N_FULL_ROUNDS*poseidon2.SPONGE_WIDTH
}

func (g *Poseidon2Gate) EvalUnfiltered(
	api frontend.API,
	glApi *gl.Chip,
	vars EvaluationVars,
) []gl.QuadraticExtensionVariable {
	constraints := []gl.QuadraticExtensionVariable{}

	poseidon2Chip := poseidon2.NewGoldilocksChip(api)

	// Assert that `swap` is binary.
	swap := vars.localWires[g.WireSwap()]
	swapMinusOne := glApi.SubExtension(swap, gl.OneExtension())
	constraints = append(constraints, glApi.MulExtension(swap, swapMinusOne))

	// Assert that each delta wire is set properly: `delta_i = swap * (rhs - lhs)`.
	for i := uint64(0); i < 4; i++ {
		inputLhs := vars.localWires[g.WireInput(i)]
		inputRhs := vars.localWires[g.WireInput(i+4)]
		deltaI := vars.localWires[g.WireDelta(i)]
		diff := glApi.SubExtension(inputRhs, inputLhs)
		expectedDeltaI := glApi.MulExtension(swap, diff)
		constraints = append(constraints, glApi.SubExtension(expectedDeltaI, deltaI))
	}

	//log.Infof("`delta_i = swap * (rhs - lhs)`. constraints:%+v", constraints)

	// Compute the possibly-swapped input layer.
	var state [poseidon2.SPONGE_WIDTH]gl.QuadraticExtensionVariable
	for i := uint64(0); i < 4; i++ {
		deltaI := vars.localWires[g.WireDelta(i)]
		inputLhs := vars.localWires[g.WireInput(i)]
		inputRhs := vars.localWires[g.WireInput(i+4)]
		state[i] = glApi.AddExtension(inputLhs, deltaI)
		state[i+4] = glApi.SubExtension(inputRhs, deltaI)
	}
	//log.Infof("Compute the possibly-swapped input layer. state:%+v", state)

	state = poseidon2Chip.MatmulExternalField(state)

	//log.Infof("M_E * X states. state:%+v", state)

	// External_i, i in {0 - R_F/2 -1}
	for r := uint64(0); r < poseidon2.HALF_N_FULL_ROUNDS; r++ {
		state = poseidon2Chip.ConstantLayerExtension(state, r)
		if r != 0 {
			for i := uint64(0); i < poseidon2.SPONGE_WIDTH; i++ {
				sBoxIn := vars.localWires[g.WireFullRoundBegin(r, i)]

				//log.Infof("External_i, sBoxIn, r: %d, i:%d  %+v %v", r, i, sBoxIn, state[i])
				//log.Infof("External_i, sBoxIn Sub, r: %d, i:%d  %+v", r, i, glApi.SubExtension(state[i], sBoxIn))

				constraints = append(constraints, glApi.SubExtension(state[i], sBoxIn))
				state[i] = sBoxIn
			}
		}
		state = poseidon2Chip.SBoxLayerExtension(state)
		state = poseidon2Chip.MatmulExternalField(state)
	}

	//log.Infof("External_i, i in 0 - R_F/2 -1 constraints: %v", constraints)
	//log.Infof("External_i, i in 0 - R_F/2 -1 states: %v", state)

	// Internal_i
	for r := uint64(0); r < poseidon2.N_PARTIAL_ROUNDS; r++ {
		roundConstant := gl.NewVariable(poseidon2.RC_MID[r])
		roundConstantQE := gl.NewQuadraticExtensionVariable(roundConstant, gl.Zero())
		state[0] = glApi.AddExtension(state[0], roundConstantQE)

		sBoxIn := vars.localWires[g.WirePartialSBox(r)]
		constraints = append(constraints, glApi.SubExtension(state[0], sBoxIn))

		state[0] = poseidon2Chip.SBoxMonomialExtension(sBoxIn)

		//log.Infof("Internal_i after sbox_monomial, r: %d, state: %+v", r, state)

		state = poseidon2Chip.MatmulInternalField(state)
	}
	//log.Infof("Internal_i states: %v", state)

	// External_i, i in {R_F/2 = R/F - 1}.
	for r := uint64(poseidon2.HALF_N_FULL_ROUNDS); r < poseidon2.HALF_N_FULL_ROUNDS*2; r++ {
		state = poseidon2Chip.ConstantLayerExtension(state, r)

		for i := uint64(0); i < poseidon2.SPONGE_WIDTH; i++ {
			sBoxIn := vars.localWires[g.WireFullSBox1(r-poseidon2.HALF_N_FULL_ROUNDS, i)]
			constraints = append(constraints, glApi.SubExtension(state[i], sBoxIn))
			state[i] = sBoxIn
		}
		state = poseidon2Chip.SBoxLayerExtension(state)
		state = poseidon2Chip.MatmulExternalField(state)
	}

	//log.Infof(" External_i, i in R_F/2 = R/F - 1.: %v", state)

	for i := uint64(0); i < poseidon2.SPONGE_WIDTH; i++ {
		constraints = append(constraints, glApi.SubExtension(state[i], vars.localWires[g.WireOutput(i)]))
	}

	//log.Infof("end constraints : %+v", constraints)

	return constraints
}
