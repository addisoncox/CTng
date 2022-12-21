package CA

import (
	//"github.com/nipuntalukdar/bitset"
	"net/http"
	"crypto/rsa"
	//"crypto/ecdsa"
	//"crypto/ed25519"
	"CTng/util"
	//"CTng/crypto"
	"crypto/rand"
	"CTng/gossip"
	"CTng/config"
	"crypto/x509"
	"fmt"
	"encoding/json"
	"io/ioutil"
	//"encoding/pem"
	//"CTng/config"
	//"encoding/asn1"
	//"crypto/x509/pkix"
	//"math/big"
	//"encoding/json"

)

type CAContext struct {
	Client            *http.Client
	SerialNumber      int
	Config            *CAConfig
	CurrentCertificatePool   *CTngCertificatePool
	CertPoolStorage   *CTngCertPoolStorage
	Rootcert *x509.Certificate
}

type CAConfig struct{
	Signer string
	Port string
	Private rsa.PrivateKey
	Public rsa.PublicKey
	Certnumber int
	Loggers map[string]string
	LoggersPublicKeys map[string] rsa.PublicKey
}

type CTngExtension struct{
	STH gossip.Gossip_object
	POI []string
	RID int
}

type CTngCertificatePool struct{
	Certificates map[string] x509.Certificate
}

type CTngCertPoolStorage struct{
	Certpools map[string] CTngCertificatePool
}

// add to certificate pool
func (c *CTngCertificatePool) AddCertificate(cert x509.Certificate) {
	c.Certificates[cert.SerialNumber.String()] = cert
}

// add all certificate from a certificate list to certificate pool
func (c *CTngCertificatePool) AddCertificateList(certList []x509.Certificate) {
	for _, cert := range certList {
		c.AddCertificate(cert)
	}
}

// add certpool to certpool storage by Period Number
func (c *CTngCertPoolStorage) AddCertPoolByPeriodNumber(periodNumber int, certPool CTngCertificatePool) {
	c.Certpools[fmt.Sprintf("%d", periodNumber)] = certPool
}

// Clear current certificate pool
func (c *CTngCertificatePool) Clear() {
	c.Certificates = make(map[string] x509.Certificate)
}

//get certificate from pool by subject common name, return empty certificate if not found

func (c *CTngCertificatePool) GetCertificateBySubjectCommonName(commonName string) x509.Certificate {
	for _, cert := range c.Certificates {
		if cert.Subject.CommonName == commonName {
			return cert
		}
	}
	return x509.Certificate{}
}

//get cert pool size
func (c *CTngCertificatePool) GetSize() int {
	return len(c.Certificates)
}

// Generate CAConfig template
func GenerateCAConfigTemplate() *CAConfig {
	return &CAConfig{
		Signer: "",
		Port: "",
		Private: rsa.PrivateKey{},
		Public: rsa.PublicKey{},
		Certnumber: 0,
		Loggers: map[string]string{},
		LoggersPublicKeys: map[string] rsa.PublicKey{},
	}
}


// Generate a public key from a private key
func publicKey(priv *rsa.PrivateKey) rsa.PublicKey {
	return priv.PublicKey
}
// Gererate RSA key pair
func GenerateRSAKeyPair() (rsa.PrivateKey, rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("rsa keygen failed")
	}
	pub := publicKey(priv)
	return *priv,pub
}

// Generate CAConfig with a random RSA key pair
func GenerateCAConfig() *CAConfig {
	config := GenerateCAConfigTemplate()
	config.Private, config.Public = GenerateRSAKeyPair()
	return config
}

// write CAConfig to file path
func WriteCAConfigToFile(config *CAConfig, filepath string) {
	util.CreateFile(filepath)
	filename := filepath + "CAConfig.json"
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		fmt.Println("json marshal failed")
	}
	err = ioutil.WriteFile(filename, jsonConfig, 0644)
	if err != nil {
		fmt.Println("write file failed")
	}
}


// Initialize CAContext
func InitializeCAContext(filepath string) *CAContext {
	conf := new(CAConfig)
	config.LoadConfiguration(&conf, filepath)
	caContext := &CAContext{
		SerialNumber: 0,
		Config: conf,
		CurrentCertificatePool: &CTngCertificatePool{Certificates: make(map[string] x509.Certificate)},
		CertPoolStorage: &CTngCertPoolStorage{Certpools: make(map[string] CTngCertificatePool)},
	}	
	tr := &http.Transport{}
	caContext.Client = &http.Client{
		Transport: tr,
	}
	caContext.Rootcert = Generate_Root_Certificate(caContext.Config)
	return caContext
}
