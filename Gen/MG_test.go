package Gen
/*
import (
	"CTng/crypto"
	"os"
	"encoding/json"
	"io/ioutil"
	"fmt"
	//"CTng/util"
	//"bytes"
	//"net/http"
	"testing"
	"crypto/rsa"
	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
	//bls "github.com/herumi/bls-go-binary/bls"
)


func TestGenerateGossiperCryptoConfig (t *testing.T){
	// Set threshold and total number of Gossipers
	Threshold := 2
	Total := 4
	// Generate a CryptoConfig for each Gossiper
	CryptoConfig_1 := crypto.StoredCryptoConfig{
		SelfID: "localhost:8080",
		Threshold: Threshold,
		N: Total,
		HashScheme: 4,
		SignScheme: "rsa",
		ThresholdScheme: "bls",
	}
	CryptoConfig_2 := crypto.StoredCryptoConfig{
		SelfID: "localhost:8081",
		Threshold: Threshold,
		N: Total,
		HashScheme: 4,
		SignScheme: "rsa",
		ThresholdScheme: "bls",
	}
	CryptoConfig_3 := crypto.StoredCryptoConfig{
		SelfID: "localhost:8082",
		Threshold: Threshold,
		N: Total,
		HashScheme: 4,
		SignScheme: "rsa",
		ThresholdScheme: "bls",
	}
	CryptoConfig_4 := crypto.StoredCryptoConfig{
		SelfID: "localhost:8083",
		Threshold: Threshold,
		N: Total,
		HashScheme: 4,
		SignScheme: "rsa",
		ThresholdScheme: "bls",
	}
	// CTngID for each Gossiper
	Gossiper_1 := crypto.CTngID("localhost:8080")
	Gossiper_2 := crypto.CTngID("localhost:8081")
	Gossiper_3 := crypto.CTngID("localhost:8082")
	Gossiper_4 := crypto.CTngID("localhost:8083")
	// create a list of CTngIDs
	CTngIDs := []crypto.CTngID{Gossiper_1, Gossiper_2, Gossiper_3, Gossiper_4}
	//Generate a threshold keypair for each CTngID
	_, pub, priv, err := crypto.GenerateThresholdKeypairs(CTngIDs, Threshold)
	if err != nil {
		t.Errorf("Error generating threshold keypair")
	}
	// generate RSA pubkey list
	pubList := []rsa.PublicKey{}
	// generate RSA privkey list
	privList := []rsa.PrivateKey{}
	// Generate RSA keypair for each CTngID
	for i := 0; i < len(CTngIDs); i++ {
		rsapriv, err := crypto.NewRSAPrivateKey()
		if err != nil {
			t.Errorf("Error generating RSA keypair")
		}
		rsapub := rsapriv.PublicKey
		pubList = append(pubList, rsapub)
		privList = append(privList, *rsapriv)
	}
	// Assign RSA Secret Key to CryptoConfig
	CryptoConfig_1.RSAPrivateKey = privList[0]
	CryptoConfig_2.RSAPrivateKey = privList[1]
	CryptoConfig_3.RSAPrivateKey = privList[2]
	CryptoConfig_4.RSAPrivateKey = privList[3]
	// Assign RSA Public Key map to CryptoConfig
	CryptoConfig_1.SignaturePublicMap = map[crypto.CTngID]rsa.PublicKey{Gossiper_1: pubList[0], Gossiper_2: pubList[1], Gossiper_3: pubList[2], Gossiper_4: pubList[3]}
	CryptoConfig_2.SignaturePublicMap = map[crypto.CTngID]rsa.PublicKey{Gossiper_1: pubList[0], Gossiper_2: pubList[1], Gossiper_3: pubList[2], Gossiper_4: pubList[3]}
	CryptoConfig_3.SignaturePublicMap = map[crypto.CTngID]rsa.PublicKey{Gossiper_1: pubList[0], Gossiper_2: pubList[1], Gossiper_3: pubList[2], Gossiper_4: pubList[3]}
	CryptoConfig_4.SignaturePublicMap = map[crypto.CTngID]rsa.PublicKey{Gossiper_1: pubList[0], Gossiper_2: pubList[1], Gossiper_3: pubList[2], Gossiper_4: pubList[3]}
	// Serialize Threshold Public Key 
	pub_byte_map :=pub.Serialize()
	// Assign Threshold Public Key to CryptoConfig
	CryptoConfig_1.ThresholdPublicMap = pub_byte_map
	CryptoConfig_2.ThresholdPublicMap = pub_byte_map
	CryptoConfig_3.ThresholdPublicMap = pub_byte_map
	CryptoConfig_4.ThresholdPublicMap = pub_byte_map
	// Assign Threshold Secret Key to CryptoConfig
	blssecretkey_1 := priv[CryptoConfig_1.SelfID]
	blssecretkey_2 := priv[CryptoConfig_2.SelfID]
	blssecretkey_3 := priv[CryptoConfig_3.SelfID]
	blssecretkey_4 := priv[CryptoConfig_4.SelfID]
	//Serialize Threshold Secret Key
	sk1_byte := blssecretkey_1.Serialize()
	sk2_byte := blssecretkey_2.Serialize()
	sk3_byte := blssecretkey_3.Serialize()
	sk4_byte := blssecretkey_4.Serialize()
	// Assign Threshold Secret Key to CryptoConfig
	CryptoConfig_1.ThresholdSecretKey = sk1_byte
	CryptoConfig_2.ThresholdSecretKey = sk2_byte
	CryptoConfig_3.ThresholdSecretKey = sk3_byte
	CryptoConfig_4.ThresholdSecretKey = sk4_byte
	// CryptoConfigList
	CryptoConfigList := []crypto.StoredCryptoConfig{CryptoConfig_1, CryptoConfig_2, CryptoConfig_3, CryptoConfig_4}
	// Create Directory for gossiper config
	os.Mkdir("gossiper_testconfig", 0777)
	// Create gossiper config file
	for i := 0; i < len(CTngIDs); i++ {
		// Marshal CryptoConfig
		cryptoConfigBytes, err := json.MarshalIndent(CryptoConfigList[i], "", " ")
		os.Mkdir("gossiper_testconfig/"+fmt.Sprint(i+1), 0777)
		err = ioutil.WriteFile("gossiper_testconfig/"+fmt.Sprint(i+1)+"/gossiper_config.json", cryptoConfigBytes, 0644)
		if err != nil {
			t.Errorf("Error writing gossiper config file")
		}

	}

}

func TestGenerateMonitorCryptoConfig (t *testing.T){
	
}
*/