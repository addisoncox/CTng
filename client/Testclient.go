package client
/*
package main

import (
	"encoding/json"
	"fmt"
)

type CRV struct {
	CAID    string
	Payload [2]string
}
type SRH struct {
	RootHash string
	TreeSize int
	Period   string
}
type Revocation struct {
	Day       int
	Delta_CRV string
	SRH       SRH
}

func main() {
	REV := Revocation{
		Day:       1,
		Delta_CRV: "test_delta_CRV",
		SRH: SRH{
			RootHash: "randomhash",
			TreeSize: 5,
			Period:   "0",
		},
	}
	payload1, _ := json.Marshal(REV)
	payload := string(payload1)
	testCRV := CRV{
		CAID:    "1",
		Payload: [2]string{"", payload},
	}
	fmt.Println(testCRV)
	var REV1 Revocation
	json.Unmarshal([]byte(testCRV.Payload[1]), &REV1)
	fmt.Println(REV1.SRH.RootHash)
	var a bitarray.BitArray
	var b bitarray.BitArray
	a = bitarray.NewBitArray(60)
	b = bitarray.NewBitArray(30)
	a.SetBit(1)
	a.SetBit(10)
	a.SetBit(30)
	b.SetBit(20)
	a = a.Or(b)
	fmt.Println(a.Blocks)
	var x []byte
	x = make([]byte, 60, 60)
	for _, i := range a.ToNums() {
		x[i] = 1
	}
	fmt.Println(x)
}
*/
