package client

import (
	"CTng/config"
	"CTng/crypto"
	"CTng/gossip"
	"fmt"

	"github.com/Workiva/go-datastructures/bitarray"

	//"github.com/gorilla/mux"
	"net/http"
)

type Client_config struct {
	//This will be used if the Queried monitor is not responding or if the Queired monitor is convicted by the Threshold signed PoM
	//Avoid adding 2 default monitor to this list
	Monitor_URLs []string
	//This is the URL of the monitor where the client will get the information from
	Default_update_monitor string
	//This is the URL of the monitor where the client will periodically send PoMs to (to make sure the queried monitor is not sending missing poms)
	Default_check_monitor string
	MaxMonitor            int
	Client_URL            string
	Port                  string
	Crypto                *crypto.CryptoConfig
	Crypto_config_path    string
	MMD                   int
}

type ClientContext struct {
	Storage_STH_FULL       *gossip.Gossip_Storage
	Storage_REV_FULL       *gossip.Gossip_Storage
	Storage_CONFLICT_POM   *gossip.Gossip_Storage
	Storage_ACCUSATION_POM *gossip.Gossip_Storage
	Storage_NUM            *gossip.NUM
	Storage_NUM_FULL       *gossip.NUM_FULL
	Storage_CRVRECORD      *CRV_Storage
	Client                 *http.Client
	Config                 *Client_config
	LastUpdatePeriod       string
}

type Clientquery struct {
	Client_URL       string
	LastUpdatePeriod string
}

type CRVRecord struct {
	CAID   string
	CRV    bitarray.BitArray
	Length int
}
type SignedPoMs struct {
	PoMs   gossip.Gossip_Storage
	Period string
	Sig    string
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

// the key would be the CA ID
type CRV_Storage map[string]CRVRecord

// update a CRV record with dCRV
func (crv *CRVRecord) UpdateCRV(dCRV bitarray.BitArray) {
	crv.CRV.Or(dCRV)
}

// this print out the entire CRV
func (crv *CRVRecord) GetCRV() {
	var x []byte
	x = make([]byte, crv.Length, crv.Length)
	for _, i := range crv.CRV.ToNums() {
		x[i] = 1
	}
	fmt.Println(x)
}

func InitializeClientContext(path string, cryptopath string) ClientContext {
	conf, err := LoadClientConfig(path, cryptopath)
	if err != nil {
		panic(err)
	}
	storage_conflict_pom := new(gossip.Gossip_Storage)
	*storage_conflict_pom = make(gossip.Gossip_Storage)
	storage_sth_full := new(gossip.Gossip_Storage)
	*storage_sth_full = make(gossip.Gossip_Storage)
	storage_rev_full := new(gossip.Gossip_Storage)
	*storage_rev_full = make(gossip.Gossip_Storage)
	storage_crv := new(CRV_Storage)
	*storage_crv = make(CRV_Storage)
	ctx := ClientContext{
		Storage_STH_FULL:     storage_sth_full,
		Storage_REV_FULL:     storage_rev_full,
		Storage_CONFLICT_POM: storage_conflict_pom,
		Storage_CRVRECORD:    storage_crv,
		Config:               &conf,
	}
	return ctx
}
