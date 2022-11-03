package client
import(
	"fmt"
	"CTng/gossip"
	"CTng/config"
	"CTng/crypto"
	"github.com/Workiva/go-datastructures/bitarray"
	//"github.com/gorilla/mux"
	"net/http"
)

type Client_config struct {
	Monitor_URLs            []string
	MaxMonitor             int
	Port                   string
	Crypto                 *crypto.CryptoConfig
	MMD                    int
}

type ClientContext struct {
	Storage_STH_FULL *gossip.Gossip_Storage
	Storage_REV_FULL *gossip.Gossip_Storage
	Storage_CONFLICT_POM *gossip.Gossip_Storage
	Storage_CRVRECORD *CRV_Storage
	Client            *http.Client
	Config            *Client_config
	LastUpdatePeriod string
}

type Clientquery struct{
	Client_URL string
	LastUpdatePeriod string
}

func LoadClientConfig(path string, cryptopath string) (Client_config, error) {
	c := new(Client_config)
	config.LoadConfiguration(c, path)
	crypto, err := crypto.ReadCryptoConfig(cryptopath)
	c.Crypto = crypto
	if err != nil {
		return *c, err
	}
	return *c, nil
}

type CRVRecord struct
{
	CAID string
	CRV bitarray.BitArray
	Length int
}

//the key would be the CA ID 
type CRV_Storage map[string]CRVRecord


//update a CRV record with dCRV
func (crv *CRVRecord) UpdateCRV(dCRV bitarray.BitArray){
	crv.CRV.Or(dCRV)
}

//this print out the entire CRV
func (crv *CRVRecord) GetCRV(){
	var x []byte
	x = make([]byte, crv.Length, crv.Length)
	for _, i := range crv.CRV.ToNums() {
		x[i] = 1
	}
	fmt.Println(x)
}

