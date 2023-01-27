
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
	REV := Generate_Revocation(ctx,"0")
	fmt.Println(REV)
}

