package CA


import (
	"CTng/gossip"
	//"CTng/crypto"
	//"CTng/util"
	//"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	//"net/http"
	"testing"
	"time"
	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)
// test generate CA config
func testGenerateCAConfig(t *testing.T) {
	for i := 0;i < 2;i++{
		// generate CA config
		caConfig := GenerateCAConfig()
		// Intialize logger list
		caConfig.Loggers = make(map[string]string)
		// Logger 1: localhost:9100
		caConfig.Loggers["Logger 1"] = "localhost:9100"
		// Logger 2: localhost:9101
		caConfig.Loggers["Logger 2"] = "localhost:9101"
		// write CA config to file, use marshall indent to make it human readable
		caConfigBytes, err := json.MarshalIndent(caConfig, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile("ca_testconfig/" + fmt.Sprint(i+1)+ "/ca_config.json", caConfigBytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}

//test initialize CA context
func testContext(t *testing.T) {
	// initialize CA context
	ctx := InitializeCAContext("ca_testconfig/1/ca_config.json")
	fmt.Println("CA context initialized",(*ctx.Config).Loggers)
}

func Genrate_N_Ctng_Extensions(n int) []CTngExtension{
	// initialize CTng extension list
	extensions := make([]CTngExtension, n)
	// generate 2 ctng extensions
	for i := 0;i < n;i++{
		// generate STH
		sth := gossip.Gossip_object{}
		// generate POI
		poi := []string{"poi1", "poi2"}
		// generate RID
		rid := i
		// generate CTng extension
		extensions[i] = CTngExtension{sth, poi, rid}
	}
	return extensions
}

func CTngExtensions_to_Strings(extensions []CTngExtension) []string{
	// initialize CTng extension string list
	extensions_str := make([]string, len(extensions))
	// convert ctng extensions to strings
	for i := 0;i < len(extensions);i++{
		// Marshal CTng extension to json
		extension_bytes, err := json.Marshal(extensions[i])
		if err != nil {
			log.Fatal(err)
		}
		// convert json to string
		extensions_str[i] = string(extension_bytes)
	}
	return extensions_str
}

//test CertGen
func TestCertGen(t *testing.T) {
	// initialize CA context
	ctx := InitializeCAContext("ca_testconfig/1/ca_config.json")
	// generate issuer
	issuer := Generate_Issuer("CA 1")
	// generate host
	host := "CA 1"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate 64 certificates
	certs := Generate_N_Signed_PreCert(64, host, validFor, isCA, issuer, ctx.Rootcert, false, &ctx.Config.Public, &ctx.Config.Private)
	fmt.Println(len(certs))
	// print the common name of the first 10 certificate
	for i := 0;i < 10;i++{
		fmt.Println(certs[i].Subject.CommonName)
	}
	// generate 2 ctng extensions
	exts := Genrate_N_Ctng_Extensions(2)
	// convert ctng extensions to strings
	exts_str := CTngExtensions_to_Strings(exts)
	//fmt.Println(exts_str)
	// add first extension to 1 certificate
	certs[0].CRLDistributionPoints = []string{exts_str[0]}
	// add first cert to certpool
	ctx.CurrentCertificatePool.AddCertificate(*certs[0], ctx)
	// Print the first certificate in the certpool, cert pool is a map
	for _, cert := range ctx.CurrentCertificatePool.Certificates{
		fmt.Println(cert.Subject.CommonName)
		fmt.Println(cert.CRLDistributionPoints)
	}
	// add extensions to 1 certificate
	certs[0].CRLDistributionPoints = []string{exts_str[1]}
	// add first cert to certpool
	ctx.CurrentCertificatePool.AddCertificate(*certs[0], ctx)
	// Print the first certificate in the certpool, cert pool is a map
	for _, cert := range ctx.CurrentCertificatePool.Certificates{
		fmt.Println(cert.Subject.CommonName)
		fmt.Println(cert.CRLDistributionPoints)
	}
}

