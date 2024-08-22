package main

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/zk-utils/common/utils"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/labstack/echo/v4"
	"net/http"
	"sync"
)

var (
	MiddleCircuitCcs constraint.ConstraintSystem
	MiddleCircuitPk  groth16.ProvingKey
	MiddleCircuitVk  groth16.VerifyingKey

	LeafCircuitVk groth16.VerifyingKey
)

type LeafProveRequest struct {
	MergeLeaf bool     `json:"merge_leaf"`
	RequestId string   `json:"request_id"`
	MimcHash  string   `json:"mimc_hash"`
	GlHash    []uint64 `json:"gl_hash"`

	SubNum     [2]uint64 `json:"sub_number"`
	SubProof   [2]string `json:"sub_proof"`
	SubWitness [2]string `json:"sub_witness"`
}

func main() {
	e := echo.New()

	var w sync.WaitGroup
	w.Add(2)
	// emulated over bn254
	go func() {
		defer w.Done()
		log.Infoln("start load emulated vk")
		tempEmulatedVk := groth16.NewVerifyingKey(ecc.BN254)
		err := utils.ReadVerifyingKey("", tempEmulatedVk)
		if err != nil {
			log.Errorf("no emulated file: %v", err)
		}
		MiddleCircuitVk = tempEmulatedVk

		log.Infoln("start compile emulated ccs")
		bn254Ccs := new(bn254cs.R1CS)
		err = utils.ReadCcs("", bn254Ccs)
		if err != nil {
			log.Errorln("no emulated ccs file")
			return
		}
		MiddleCircuitCcs = bn254Ccs
	}()

	go func() {
		defer w.Done()
		log.Infoln("start load emulated pk")
		tmpEmulatedPk := groth16.NewProvingKey(ecc.BN254)
		err := utils.ReadProvingKey("", tmpEmulatedPk)
		if err != nil {
			log.Errorf("no emulated file: %v", err)
		}
		MiddleCircuitPk = tmpEmulatedPk
	}()
	w.Wait()

	e.POST("/middle_prove", func(c echo.Context) error {
		payload := &LeafProveRequest{}
		if err := c.Bind(payload); err != nil { // here unmarshal request body into p
			return c.String(http.StatusInternalServerError, err.Error())
		}

		jsonData, merr := json.Marshal(payload)
		if merr != nil {
			log.Errorf("invalid json: %v", merr)
			return json.NewEncoder(c.Response()).Encode("invalid request")
		}
		log.Infof("get prove request: %s", string(jsonData))

		//client, _ := s3api.NewClient(os.Getenv("S3_BUCKET"))
		//log.Infof("S3_BUCKET:%s\n", os.Getenv("S3_BUCKET"))

		//go processEmulatePayload(*payload, client)

		return json.NewEncoder(c.Response()).Encode("success")
	})

	e.GET("/health", func(c echo.Context) error { return json.NewEncoder(c.Response()).Encode("success") })
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", 2001)))
}
