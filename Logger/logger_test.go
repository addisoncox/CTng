package Logger

import (
	"CTng/CA"
	//"CTng/crypto"
	//"CTng/util"
	//"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	//"net/http"
	"os"
	"testing"

	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
	"github.com/google/certificate-transparency-go/x509"
)

// Test generate Logger config
func TestGenerateLoggerConfig(t *testing.T) {
	for i := 0; i < 2; i++ {
		// generate Logger config
		loggerConfig := GenerateLoggerConfig()
		// Intialize CA list
		loggerConfig.CAs = make(map[string]string)
		// CA 1: localhost:9000
		loggerConfig.CAs["CA 1"] = "localhost:9000"
		// CA 2: localhost:9001
		loggerConfig.CAs["CA 2"] = "localhost:9001"
		// set MMD to 60 seconds
		loggerConfig.MMD = 60
		// write Logger config to file, use marshall indent to make it human readable
		loggerConfigBytes, err := json.MarshalIndent(loggerConfig, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		os.Create("logger_testconfig/" + fmt.Sprint(i+1))
		err = ioutil.WriteFile("logger_testconfig/"+fmt.Sprint(i+1)+"/logger_config.json", loggerConfigBytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// test initialize Logger context
func TestContext(t *testing.T) {
	// initialize Logger context
	ctx := InitializeLoggerContextWithConfigFile("logger_testconfig/1/logger_config.json")
	fmt.Println("Logger context initialized", (*ctx.Config).CAs)
}

func CTngExtensions_to_Strings(extensions []CA.CTngExtension) []string {
	// initialize CTng extension string list
	extensions_str := make([]string, len(extensions))
	// convert ctng extensions to strings
	for i := 0; i < len(extensions); i++ {
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

func GenerateTestLoggerConfig() *LoggerConfig {

	loggerConfig := GenerateLoggerConfig()
	loggerConfig.CAs = make(map[string]string)
	loggerConfig.CAs["CA 1"] = "localhost:9000"
	loggerConfig.CAs["CA 2"] = "localhost:9001"
	return loggerConfig
}

func TestBuildMerkleTreeFromCerts(t *testing.T) {
	certs := make([]x509.Certificate, 0)
	for i := 0; i < 10; i++ {
		certs = append(certs, x509.Certificate{
			Version: i,
		})
	}
	periodNum := 0
	config := GenerateTestLoggerConfig()
	buildMerkleTreeFromCerts(certs, *config, periodNum)
}

func TestCertificateInMerkleTree(t *testing.T) {
	certs := make([]x509.Certificate, 0)
	for i := 0; i < 10; i++ {
		certs = append(certs, x509.Certificate{
			Version: i,
		})
	}
	periodNum := 0
	config := GenerateTestLoggerConfig()
	nodeMap, sth := buildMerkleTreeFromCerts(certs, *config, periodNum)

	if !poiAndSthContainsCert(sth, nodeMap[0].poi, certs[0]) {
		log.Fatal("Certificate verification failed")
	}

	doesNotExistCert := x509.Certificate{
		Version: 11,
	}

	if poiAndSthContainsCert(sth, nodeMap[0].poi, doesNotExistCert) {
		log.Fatal("Certificate verification failed")
	}
}
