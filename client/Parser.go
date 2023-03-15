package client

import (
	"CTng/CA"
	"CTng/gossip"
	"encoding/json"
	"fmt"

	"github.com/bits-and-blooms/bitset"
)

func Get_SRH_and_DCRV(rev gossip.Gossip_object) (string, bitset.BitSet) {
	var revocation CA.Revocation
	err := json.Unmarshal([]byte(rev.Payload[2]), &revocation)
	if err != nil {
		fmt.Println(err)
	}
	newSRH := revocation.SRH
	var newDCRV bitset.BitSet
	err = newDCRV.UnmarshalBinary(revocation.Delta_CRV)
	if err != nil {
		fmt.Println(err)
	}
	return newSRH, newDCRV
}
