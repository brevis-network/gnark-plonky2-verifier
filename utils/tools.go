package utils

import (
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

func LoadProof(path string) (groth16.Proof, error) {
	p := groth16.NewProof(ecc.BN254)
	err := utils.ReadProofFromLocalFile(path, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func LoadVk(path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	err := utils.ReadVerifyingKey(path, vk)
	if err != nil {
		return nil, err
	}
	return vk, nil
}

func LoadWitness(path string) (witness.Witness, error) {
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	err = utils.ReadWitness(path, w)
	if err != nil {
		return nil, err
	}
	return w, nil
}
