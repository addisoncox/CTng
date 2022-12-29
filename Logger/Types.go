package Logger

import (
	"crypto"
	"crypto/rsa"
	"net/http"
	"crypto/x509"
	"CTng/config"
	"CTng/CA"
)
type LoggerConfig struct {
	Signer              string
	Port                string
	MMD                 int
	Public			    rsa.PublicKey
	Private             rsa.PrivateKey
	CAs 				map[string]string
	CAsPublicKeys 		map[string]rsa.PublicKey
	MisbehaviorInterval int
}

type LoggerContext struct {
	Config *LoggerConfig
	Client *http.Client
	SerialNumber int
	CurrentPrecertPool *PrecertPool
	PrecertStorage *PrecertStorage
	OnlinePeriod int
}


type PrecertPool struct {
	Precerts map[string] x509.Certificate
}

type PrecertStorage struct {
	PrecertPools map[string] PrecertPool
}

func Verifyprecert (precert x509.Certificate, ctx LoggerContext) bool {
	issuer := precert.Issuer.CommonName
	//check if issuer is in CAs
	if _, ok := ctx.Config.CAs[issuer]; !ok {
		return false
	}
	//check if issuer is in CAsPublicKeys
	if _, ok := ctx.Config.CAsPublicKeys[issuer]; !ok {
		return false
	}
	//retrieve the public key of the issuer
	issuerPublicKey := ctx.Config.CAsPublicKeys[issuer]
	//retrieve the signature of the precert
	signature := precert.Signature
	//check if the signature is valid
	if err := rsa.VerifyPKCS1v15(&issuerPublicKey, crypto.SHA256, precert.RawTBSCertificate, signature); err != nil {
		return false
	}
	return true
}

func (pool *PrecertPool) AddPrecert(precert x509.Certificate) {
	pool.Precerts[precert.Subject.CommonName] = precert
}

// Get precert pool size
func (pool *PrecertPool) GetSize() int {
	return len(pool.Precerts)
}

// Get precert from pool by name
func (pool *PrecertPool) GetPrecert(name string) *x509.Certificate {
	if precert, ok := pool.Precerts[name]; ok {
		return &precert
	}
	return nil
}

// Generate Config template
func GenerateLoggerConfigTemplate() *LoggerConfig {
	return &LoggerConfig{
		Signer: "",
		Port: "",
		Public: rsa.PublicKey{},
		Private: rsa.PrivateKey{},
		CAs: map[string]string{},
		CAsPublicKeys: map[string] rsa.PublicKey{},
	}
}

// Generate LoggerConfig with a random RSA key pair
func GenerateLoggerConfig() *LoggerConfig {
	config := GenerateLoggerConfigTemplate()
	config.Private, config.Public = CA.GenerateRSAKeyPair()
	return config
}

// Initialize a LoggerContext
func InitializeLoggerContext(config *LoggerConfig) *LoggerContext {
	return &LoggerContext{
		Config: config,
		Client: &http.Client{},
		SerialNumber: 0,
		CurrentPrecertPool: &PrecertPool{Precerts: map[string] x509.Certificate{}},
		PrecertStorage: &PrecertStorage{PrecertPools: map[string] PrecertPool{}},
	}
}


func InitializeLoggerContextWithConfigFile(filepath string) *LoggerContext {
	conf := new(LoggerConfig)
	config.LoadConfiguration(&conf, filepath)
	return InitializeLoggerContext(conf)
}