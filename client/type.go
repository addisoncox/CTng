package client
import(
	"fmt"
	"CTng/gossip"
	"CTng/config"
	"CTng/crypto"
	"github.com/Workiva/go-datastructures/bitarray"
	//"github.com/gorilla/mux"
	"net/http"
	"encoding/json"
)

type Client_config struct {
	//This will be used if the Queried monitor is not responding or if the Queired monitor is convicted by the Threshold signed PoM 
	//Avoid adding 2 default monitor to this list
	Monitor_URLs            []string
	//This is the URL of the monitor where the client will get the information from
	Default_update_monitor  string
	//This is the URL of the monitor where the client will periodically send PoMs to (to make sure the queried monitor is not sending missing poms)
	Default_check_monitor  string
	MaxMonitor             int
	Client_URL             string
	Port                   string
	Crypto                 *crypto.CryptoConfig
	Crypto_config_path     string
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

type CRVRecord struct
{
	CAID string
	CRV bitarray.BitArray
	Length int
}
type SignedPoMs struct
{
	PoMs gossip.Gossip_Storage
	Period string
	Sig string
}

type SRH struct {
	RootHash string
	TreeSize int
	Period   string
}
type Revocation struct {
	//This is computed by bitarray.Bitarray.toNums
	Delta_CRV []int
	SRH       SRH
}

func GetRootHash (g gossip.Gossip_object)string{
	var REV1 Revocation 
	json.Unmarshal([]byte(g.Payload[2]), &REV1)
	return REV1.SRH.RootHash
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

