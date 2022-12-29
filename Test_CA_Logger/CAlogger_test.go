package Logger_CA
import (
	"CTng/CA"
	"CTng/Logger"
	"CTng/config"
	//"CTng/crypto"
	//"CTng/util"
	//"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	//"net/http"
	"testing"
	"os"
	"crypto/rsa"
	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)

type CTngID string



// Test generate Logger config
func TestGenerateLoggerConfig(t *testing.T) {
	for i := 0;i < 2;i++{
		// generate Logger config
		loggerConfig := Logger.GenerateLoggerConfig()
		// Intialize CA list
		loggerConfig.CAs = make(map[string]string)
		// CA 1: localhost:9000
		loggerConfig.CAs["CA 1"] = "localhost:9100"
		// CA 2: localhost:9001
		loggerConfig.CAs["CA 2"] = "localhost:9101"
		// Signer
		loggerConfig.Signer = "localhost:900"+fmt.Sprint(i+1)
		// Port
		loggerConfig.Port = "900"+fmt.Sprint(i+1)
		// write Logger config to file, use marshall indent to make it human readable
		loggerConfigBytes, err := json.MarshalIndent(loggerConfig, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		//create directory
		os.Mkdir("logger_testconfig", 0777)
		os.Mkdir("logger_testconfig/" + fmt.Sprint(i+1), 0777)
		err = ioutil.WriteFile("logger_testconfig/" + fmt.Sprint(i+1)+ "/logger_config.json", loggerConfigBytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

}

// test generate CA config
func TestGenerateCAConfig(t *testing.T) {
	for i := 0;i < 2;i++{
		// generate CA config
		caConfig := CA.GenerateCAConfig()
		// Intialize Logger list
		caConfig.Loggers = make(map[string]string)
		// Logger 1: localhost:9000
		caConfig.Loggers["Logger 1"] = "localhost:9000"
		// Logger 2: localhost:9001
		caConfig.Loggers["Logger 2"] = "localhost:9001"
		// Signer
		caConfig.Signer = "localhost:910"+fmt.Sprint(i+1)
		// Port
		caConfig.Port = "910"+fmt.Sprint(i+1)
		// write CA config to file, use marshall indent to make it human readable
		caConfigBytes, err := json.MarshalIndent(caConfig, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		//create directory
		os.Mkdir("ca_testconfig", 0777)
		os.Mkdir("ca_testconfig/" + fmt.Sprint(i+1), 0777)
		err = ioutil.WriteFile("ca_testconfig/" + fmt.Sprint(i+1)+ "/ca_config.json", caConfigBytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func TestKeyExchange (t *testing.T){
	var ca1_config CA.CAConfig
	var ca2_config CA.CAConfig
	var logger1_config Logger.LoggerConfig
	var logger2_config Logger.LoggerConfig
	// load ca1_config from file
	config.LoadConfiguration(&ca1_config, "ca_testconfig/1/ca_config.json")
	// load ca2_config from file
	config.LoadConfiguration(&ca2_config, "ca_testconfig/2/ca_config.json")
	// load logger1_config from file
	config.LoadConfiguration(&logger1_config, "logger_testconfig/1/logger_config.json")
	// load logger2_config from file
	config.LoadConfiguration(&logger2_config, "logger_testconfig/2/logger_config.json")
	
	// fill ca1_config with loggers public key
	ca1_config.LoggersPublicKeys = make(map[string]rsa.PublicKey)
	ca1_config.LoggersPublicKeys[logger1_config.Signer] = logger1_config.Public
	ca1_config.LoggersPublicKeys[logger2_config.Signer] = logger2_config.Public
	// fill ca2_config with loggers public key
	ca2_config.LoggersPublicKeys = make(map[string]rsa.PublicKey)
	ca2_config.LoggersPublicKeys[logger1_config.Signer] = logger1_config.Public
	ca2_config.LoggersPublicKeys[logger2_config.Signer] = logger2_config.Public
	// fill logger1_config with cas public key
	logger1_config.CAsPublicKeys = make(map[string]rsa.PublicKey)
	logger1_config.CAsPublicKeys[ca1_config.Signer] = ca1_config.Public
	logger1_config.CAsPublicKeys[ca2_config.Signer] = ca2_config.Public
	// fill logger2_config with cas public key
	logger2_config.CAsPublicKeys = make(map[string]rsa.PublicKey)
	logger2_config.CAsPublicKeys[ca1_config.Signer] = ca1_config.Public
	logger2_config.CAsPublicKeys[ca2_config.Signer] = ca2_config.Public
	ca1_configBytes, err := json.MarshalIndent(ca1_config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ca_testconfig/1/ca_config.json", ca1_configBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// write ca2_config to file
	ca2_configBytes, err := json.MarshalIndent(ca2_config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ca_testconfig/2/ca_config.json", ca2_configBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// write logger1_config to file
	logger1_configBytes, err := json.MarshalIndent(logger1_config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("logger_testconfig/1/logger_config.json", logger1_configBytes, 0644)
}