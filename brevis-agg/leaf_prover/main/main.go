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
	LeafCircuitCcs constraint.ConstraintSystem
	LeafCircuitPk  groth16.ProvingKey
	LeafCircuitVk  groth16.VerifyingKey
)

type LeafProveRequest struct {
	RequestId string   `json:"request_id"`
	LeafNum   uint64   `json:"leaf_num"` // num in array tree
	RawData   []uint64 `json:"raw_data"` //1296
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
		LeafCircuitVk = tempEmulatedVk

		log.Infoln("start compile emulated ccs")
		bn254Ccs := new(bn254cs.R1CS)
		err = utils.ReadCcs("", bn254Ccs)
		if err != nil {
			log.Errorln("no emulated ccs file")
			return
		}
		LeafCircuitCcs = bn254Ccs
	}()

	go func() {
		defer w.Done()
		log.Infoln("start load emulated pk")
		tmpEmulatedPk := groth16.NewProvingKey(ecc.BN254)
		err := utils.ReadProvingKey("", tmpEmulatedPk)
		if err != nil {
			log.Errorf("no emulated file: %v", err)
		}
		LeafCircuitPk = tmpEmulatedPk
	}()
	w.Wait()

	e.POST("/leaf_prove", func(c echo.Context) error {
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
