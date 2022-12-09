package testserver

import (
	"github.com/nipuntalukdar/bitset"
	"net/http"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"CTng/util"
	"CTng/crypto"
	"crypto/rand"
	"CTng/gossip"
	"CTng/config"
	"encoding/asn1"
	"crypto/x509/pkix"
	"math/big"
	//"encoding/json"
	"fmt"
)
type TestServerContext struct {
	Client            *http.Client
	CRVsize           int
	CRV               *bitset.Bitset
	SerialNumber      int
	Config            *TestServerConfig
}

type TestServerConfig struct{
	Signer string
	Port string
	MMD string 
	Private rsa.PrivateKey
	Public rsa.PublicKey
	MisbehaviorInterval int
	Revoke_Percentage int 
}

//this will be encoded and added to the pkix.Extension.Value
type CTngExtension struct{
	STH gossip.Gossip_object `json:"STH"`
	POI []string `json:"POI"`
	RID int  `json:"RID"`
}

func CTngExtension_init(rid int) CTngExtension{
	ext := CTngExtension{
		STH: gossip.Gossip_object{},
		POI: []string{},
		RID: rid,
	}
	return ext
}

func Generate_config_template() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("rsa private keygen failed")
	}
	pub, err := crypto.GetPublicKey(priv)
	if err!= nil{
		fmt.Println("rsa public keygen failed")
	}
	config := TestServerConfig{
		Signer: "",
		Port: "",
		MMD: "",
		Private: *priv,
		Public: *pub,
		MisbehaviorInterval: 2,
		Revoke_Percentage: 0,
	}
	err = util.WriteData("Configtemp.json", config)
	if err != nil {
		fmt.Println("Writing failed.")
	}
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
func TestServer_Context_init() *TestServerContext{
	conf := new(TestServerConfig)
	config.LoadConfiguration(&conf, "Configtemp.json")
	ctx := TestServerContext{
		CRV: bitset.NewBitset(2048),
		CRVsize: 0,
		SerialNumber: 1,
		Config: conf,
	}
	tr := &http.Transport{}
	ctx.Client = &http.Client{
		Transport: tr,
	}
	return &ctx
}

type pkcs1PublicKey struct {
	N *big.Int
	E int
}

func MarshalRSA(pub *rsa.PublicKey)(publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error){
	publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
		N: pub.N,
		E: pub.E,
	})
	oidPublicKeyRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
	// This is a NULL parameters value which is required by
	// RFC 3279, Section 2.3.1.
	publicKeyAlgorithm.Parameters = asn1.NullRawValue
	return publicKeyBytes, publicKeyAlgorithm, nil
}
