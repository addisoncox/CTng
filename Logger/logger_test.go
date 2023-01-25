package Logger

import (

	//"CTng/crypto"
	//"CTng/util"
	//"bytes"

	"encoding/json"

	//"net/http"

	"log"
	"testing"
	"crypto/x509"

	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)

/*
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
*/

func TestMerkleTree(t *testing.T) {
	certs := make([]x509.Certificate, 0)
	for i := 0; i < 9; i++ {
		subjectKeyIdBytes, _ := json.Marshal(i)
		certs = append(certs, x509.Certificate{
			Version: i, SubjectKeyId: subjectKeyIdBytes,
		})
	}
	periodNum := 0
	ctx := InitializeLoggerContext("../Gen/logger_testconfig/1/Logger_public_config.json", "../Gen/logger_testconfig/1/Logger_private_config.json", "../Gen/logger_testconfig/1/Logger_crypto_config.json")
	_, sth, nodes := BuildMerkleTreeFromCerts(certs, *ctx, periodNum)
	testExistsSubjectKeyId, _ := json.Marshal(2)
	testCertExists := x509.Certificate{Version: 2, SubjectKeyId: testExistsSubjectKeyId}
	for _, node := range nodes {
		if node.SubjectKeyId == string(testExistsSubjectKeyId) {
			if !(VerifyPOI(sth, node.Poi, testCertExists)) {
				log.Fatal("Expected certificate does not exist")
			}
		}
	}
	testCertDoesNotExist := x509.Certificate{Version: 32, SubjectKeyId: testExistsSubjectKeyId}
	if VerifyPOI(sth, nodes[0].Poi, testCertDoesNotExist) {
		log.Fatal("Not existent certificate passed verification")
	}
}
