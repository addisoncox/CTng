package CA
import (
	"github.com/bits-and-blooms/bitset"
	"CTng/gossip"
	"CTng/crypto"
	"encoding/json"


)

type CRV struct {
	CRV_pre_update *bitset.BitSet
	CRV_current *bitset.BitSet
	CRV_cache map[string]*bitset.BitSet
}

type Revocation struct {
	Period string
	Delta_CRV []byte
	SRH string
}

func CRV_init() *CRV{
	CRV := new(CRV)
	CRV.CRV_pre_update = bitset.New(0)
	CRV.CRV_current = bitset.New(0)
	CRV.CRV_cache = make(map[string]*bitset.BitSet)
	return CRV
}
// Compute delta between CRV_pre_update and CRV_current
func (crv *CRV) GetDeltaCRV() []byte{
	// compute delta between CRV_pre_update and CRV_current
	CRV_delta := crv.CRV_current.SymmetricDifference(crv.CRV_pre_update)
	bytes, err := CRV_delta.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return bytes
}

// Compute delta between one of the cached CRV and CRV_current
func (crv *CRV) GetDeltaCRVCache(LastUpdatePeriod string) []byte{
	// compute delta between CRV_pre_update and CRV_current
	CRV_delta := crv.CRV_current.SymmetricDifference(crv.CRV_cache[LastUpdatePeriod])
	bytes, err := CRV_delta.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return bytes
}

// revoke by revocation ID
func (crv *CRV) Revoke(index int){
	crv.CRV_current.Set(uint(index))
}


func Generate_Revocation (c *CAContext, Period string) gossip.Gossip_object{
	// hash c.CRV.CRVcurrent
	hashmsg, _ := c.CRV.CRV_current.MarshalJSON()
	hash,_ := crypto.GenerateSHA256(hashmsg)
	// hash delta CRV
	hashmsgdelta := c.CRV.GetDeltaCRV()
	hash_delta,_ := crypto.GenerateSHA256(hashmsgdelta)
	// hash Period||hash CRVcurrent||hash delta CRV
	hash_revocation,_ := crypto.GenerateSHA256([]byte(Period+string(hash)+string(hash_delta)))
	// sign hash_revocation
	signature,_ := crypto.RSASign(hash_revocation, &c.CA_crypto_config.RSAPrivateKey, c.CA_crypto_config.SelfID)
	// create revocation object
	revocation := Revocation{
		Period: Period,
		Delta_CRV: hashmsgdelta,
		SRH:  signature.String(),
	}
	// create gossip object
	payload3, _ := json.Marshal(revocation)
	payload := string(c.CA_private_config.Signer)+"CRV"+string(payload3)
	sig, _ := crypto.RSASign([]byte(payload), &c.CA_crypto_config.RSAPrivateKey, c.CA_crypto_config.SelfID)
	gossipREV := gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.REV,
		Period:      Period,
		Signer:      c.CA_private_config.Signer,
		Signature:   [2]string{sig.String(), ""},
		Crypto_Scheme: "RSA",
		Payload:     [3]string{c.CA_private_config.Signer,"CRV",string(payload3)},
	}
	return gossipREV
}
