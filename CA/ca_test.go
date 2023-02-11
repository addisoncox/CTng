
package CA
import (
	"fmt"
	"testing"
	"github.com/bits-and-blooms/bitset"
)

func testCRV(t *testing.T){
	newCRV := CRV_init()
	newCRV.Revoke(1)
	newCRV.Revoke(4)
	fmt.Println(newCRV.CRV_current)
	fmt.Println(newCRV.CRV_pre_update)
	var newbitset = new(bitset.BitSet)
	newbitset.UnmarshalJSON(newCRV.GetDeltaCRV())
	fmt.Println(newbitset)
}

func TestCAContext(t *testing.T){
	ctx := InitializeCAContext("../Gen/ca_testconfig/1/CA_public_config.json","../Gen/ca_testconfig/1/CA_private_config.json","../Gen/ca_testconfig/1/CA_crypto_config.json")
	ctx.CRV.Revoke(1)
	ctx.CRV.Revoke(4)
	fmt.Println(ctx.CRV.CRV_current)
	REV := Generate_Revocation(ctx,"0",0)
	REV_fake := Generate_Revocation(ctx,"0",1)
	fmt.Println(REV.Payload[2])
	fmt.Println(REV_fake.Payload[2])
	ctx.REV_storage["0"] = REV
	ctx.REV_storage_fake["0"] = REV_fake
	fmt.Println(ctx.REV_storage["0"].Payload[2])
	fmt.Println(ctx.REV_storage_fake["0"].Payload[2])
}

