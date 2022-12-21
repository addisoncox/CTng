package CA


import (
	//"CTng/gossip"
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
}

