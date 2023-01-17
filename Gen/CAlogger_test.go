package Gen
import (
	"CTng/CA"
	"CTng/Logger"
	//"CTng/config"
	"CTng/crypto"
	//"CTng/util"
	//"bytes"
	//"encoding/json"
	"fmt"
	//"io/ioutil"
	"log"
	//"net/http"
	"testing"
	"os"
	//"crypto/rsa"
	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)


func Test_gen_CA_Logger(t *testing.T){
	num_gossiper := 4
	num_logger := 2
	num_ca := 2
	num_cert := 4
	Threshold := 2
	Total := num_gossiper
	G_list, M_list, C_list, L_list := Generate_all_list(num_gossiper, num_ca, num_logger)
	// Generate CA public config map
	ca_public_config := GenerateCA_public_config(C_list, L_list, 60, 60, []string{"1.1"})
	// Generate CA private config map
	ca_private_config_map := make(map[string]CA.CA_private_config)
	ca_private_config_map = GenerateCA_private_config_map(G_list, M_list, L_list, num_cert,num_ca)
	// Generate CA crypto config map
	ca_crypto_config_map := make(map[string]crypto.StoredCryptoConfig)
	ca_crypto_config_map = GenerateCryptoconfig_map(Total,Threshold,"CA")
	// Create CA directory
	os.Mkdir("ca_testconfig", 0777)
	// Generate Logger public config map
	logger_public_config := GenerateLogger_public_config(C_list, L_list, 60, 60, []string{"1.1"})
	// Generate Logger private config map
	logger_private_config_map := make(map[string]Logger.Logger_private_config)
	logger_private_config_map = GenerateLogger_private_config_map(G_list,M_list,C_list, num_logger)
	// Generate Logger crypto config map
	logger_crypto_config_map := make(map[string]crypto.StoredCryptoConfig)
	logger_crypto_config_map = GenerateCryptoconfig_map(Total,Threshold,"Logger")
	// Create Logger directory
	os.Mkdir("logger_testconfig", 0777)
	// write all CA public config, private config, crypto config to file
	for i := 0;i < num_ca;i++{
		// create a new folder for each CA
		err := os.Mkdir("ca_testconfig/" + fmt.Sprint(i+1), 0777)
		if err != nil {
			log.Fatal(err)
		}
		filepath := "ca_testconfig/" + fmt.Sprint(i+1) + "/"
		write_all_configs_to_file(ca_public_config, ca_private_config_map[C_list[i]], ca_crypto_config_map[C_list[i]], filepath, "CA")
	}
	// write all Logger public config, private config, crypto config to file
	for i := 0;i < num_logger;i++{
		// create a new folder for each Logger
		err := os.Mkdir("logger_testconfig/" + fmt.Sprint(i+1), 0777)
		if err != nil {
			log.Fatal(err)
		}
		filepath := "logger_testconfig/" + fmt.Sprint(i+1) + "/"
		write_all_configs_to_file(logger_public_config, logger_private_config_map[L_list[i]], logger_crypto_config_map[L_list[i]], filepath, "Logger")
	}
}


/*
func TestGenerateCAConfig(t *testing.T) {
	for i := 0;i < 2;i++{
		// Generate CA public config template
		caPublicConfig := CA.GenerateCA_public_config_template()
		// Generate CA private config template
		caPrivateConfig := CA.GenerateCA_private_config_template()
		// Generate CA crypto config template
		caCryptoConfig := CA.GenerateCA_Crypto_config_template()

		// Start setting CA public config
		// set all CA URLs
		caPublicConfig.All_CA_URLs = []string{"localhost:9100", "localhost:9101"}
		// set all logger URLs
		caPublicConfig.All_Logger_URLs = []string{"localhost:9000", "localhost:9001"}
		// set MMD
		caPublicConfig.MMD = 60
		// set MRD
		caPublicConfig.MRD = 60
		// set http version
		caPublicConfig.Http_vers = []string{"1.1"}

		// Start setting CA private config
		caPrivateConfig.Signer = "localhost:910" + fmt.Sprint(i)
		caPrivateConfig.Port = "910" + fmt.Sprint(i)
		caPrivateConfig.Loggerlist = []string{"localhost:9000", "localhost:9001"}
		caPrivateConfig.Monitorlist = []string{"localhost:8180", "localhost:8181", "localhost:8182", "localhost:8183"}
		caPrivateConfig.Gossiperlist = []string{"localhost:8080", "localhost:8081", "localhost:8082", "localhost:8083"}
		caPrivateConfig.Cert_per_period = 10

		// Start setting CA crypto config
		caCryptoConfig.SelfID = crypto.CTngID("localhost:910" + fmt.Sprint(i))
		caCryptoConfig.SignScheme = "rsa"
		caCryptoConfig.HashScheme = 4



		// Start Marshal indent all 3
		caPublicConfigBytes, err := json.MarshalIndent(caPublicConfig, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile("ca_testconfig/" + fmt.Sprint(i+1)+ "/ca_public_config.json", caPublicConfigBytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
		caPrivateConfigBytes, err := json.MarshalIndent(caPrivateConfig, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile("ca_testconfig/" + fmt.Sprint(i+1)+ "/ca_private_config.json", caPrivateConfigBytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
		caCryptoConfigBytes, err := json.MarshalIndent(caCryptoConfig, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile("ca_testconfig/" + fmt.Sprint(i+1)+ "/ca_crypto_config.json", caCryptoConfigBytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}



// Test generate Logger config
func TestGenerateLoggerConfig(t *testing.T) {
	for i := 0;i < 3;i++{
		// generate Logger config
		loggerConfig := Logger.GenerateLoggerConfig()
		// Intialize CA list
		loggerConfig.CAs = make(map[string]string)
		// CA 1: localhost:9100
		loggerConfig.CAs["CA 1"] = "localhost:9100"
		// CA 2: localhost:9101
		loggerConfig.CAs["CA 2"] = "localhost:9101"
		// CA 3: localhost:9102
		loggerConfig.CAs["CA 3"] = "localhost:9102"
		// set MMD to 60 seconds
		loggerConfig.MMD = 60
		// Signer
		loggerConfig.Signer = crypto.CTngID("localhost:900"+fmt.Sprint(i))
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
	for i := 0;i < 3;i++{
		// generate CA config
		caConfig := CA.GenerateCAConfig()
		// Intialize Logger list
		caConfig.Loggers = make(map[string]string)
		// Logger 1: localhost:9000
		caConfig.Loggers["Logger 1"] = "localhost:9000"
		// Logger 2: localhost:9001
		caConfig.Loggers["Logger 2"] = "localhost:9001"
		// Logger 3: localhost:9002
		caConfig.Loggers["Logger 3"] = "localhost:9002"
		// set MMD to 60 seconds
		caConfig.MMD = 60
		// Signer
		caConfig.Signer = "localhost:910"+fmt.Sprint(i)
		// Port
		caConfig.Port = "910"+fmt.Sprint(i)
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
	var ca3_config CA.CAConfig
	var logger1_config Logger.LoggerConfig
	var logger2_config Logger.LoggerConfig
	var logger3_config Logger.LoggerConfig
	// load ca1_config from file
	config.LoadConfiguration(&ca1_config, "ca_testconfig/1/ca_config.json")
	// load ca2_config from file
	config.LoadConfiguration(&ca2_config, "ca_testconfig/2/ca_config.json")
	// Load ca3_config from file
	config.LoadConfiguration(&ca3_config, "ca_testconfig/3/ca_config.json")
	// load logger1_config from file
	config.LoadConfiguration(&logger1_config, "logger_testconfig/1/logger_config.json")
	// load logger2_config from file
	config.LoadConfiguration(&logger2_config, "logger_testconfig/2/logger_config.json")
	// Load logger3_config from file
	config.LoadConfiguration(&logger3_config, "logger_testconfig/3/logger_config.json")
	
	// fill ca1_config with loggers public key
	ca1_config.LoggersPublicKeys = make(map[string]rsa.PublicKey)
	ca1_config.LoggersPublicKeys[logger1_config.Signer.String()] = logger1_config.Public
	ca1_config.LoggersPublicKeys[logger2_config.Signer.String()] = logger2_config.Public
	ca1_config.LoggersPublicKeys[logger3_config.Signer.String()] = logger3_config.Public
	// fill ca2_config with loggers public key
	ca2_config.LoggersPublicKeys = make(map[string]rsa.PublicKey)
	ca2_config.LoggersPublicKeys[logger1_config.Signer.String()] = logger1_config.Public
	ca2_config.LoggersPublicKeys[logger2_config.Signer.String()] = logger2_config.Public
	ca2_config.LoggersPublicKeys[logger3_config.Signer.String()] = logger3_config.Public
	// fill ca3_config with loggers public key
	ca3_config.LoggersPublicKeys = make(map[string]rsa.PublicKey)
	ca3_config.LoggersPublicKeys[logger1_config.Signer.String()] = logger1_config.Public
	ca3_config.LoggersPublicKeys[logger2_config.Signer.String()] = logger2_config.Public
	ca3_config.LoggersPublicKeys[logger3_config.Signer.String()] = logger3_config.Public
	// fill logger1_config with cas public key
	logger1_config.CAsPublicKeys = make(map[string]rsa.PublicKey)
	logger1_config.CAsPublicKeys[ca1_config.Signer] = ca1_config.Public
	logger1_config.CAsPublicKeys[ca2_config.Signer] = ca2_config.Public
	logger1_config.CAsPublicKeys[ca3_config.Signer] = ca3_config.Public
	// fill logger2_config with cas public key
	logger2_config.CAsPublicKeys = make(map[string]rsa.PublicKey)
	logger2_config.CAsPublicKeys[ca1_config.Signer] = ca1_config.Public
	logger2_config.CAsPublicKeys[ca2_config.Signer] = ca2_config.Public
	logger2_config.CAsPublicKeys[ca3_config.Signer] = ca3_config.Public
	// fill logger3_config with cas public key
	logger3_config.CAsPublicKeys = make(map[string]rsa.PublicKey)
	logger3_config.CAsPublicKeys[ca1_config.Signer] = ca1_config.Public
	logger3_config.CAsPublicKeys[ca2_config.Signer] = ca2_config.Public
	logger3_config.CAsPublicKeys[ca3_config.Signer] = ca3_config.Public
	// write ca1_config to file
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
	// write ca3_config to file
	ca3_configBytes, err := json.MarshalIndent(ca3_config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ca_testconfig/3/ca_config.json", ca3_configBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// write logger1_config to file
	logger1_configBytes, err := json.MarshalIndent(logger1_config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("logger_testconfig/1/logger_config.json", logger1_configBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// write logger2_config to file
	logger2_configBytes, err := json.MarshalIndent(logger2_config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("logger_testconfig/2/logger_config.json", logger2_configBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// write logger3_config to file
	logger3_configBytes, err := json.MarshalIndent(logger3_config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("logger_testconfig/3/logger_config.json", logger3_configBytes, 0644)
}

func TestCAServer(t *testing.T){
	// initialize cacontext for ca1
	ca1_context := CA.InitializeCAContext("ca_testconfig/1/ca_config.json")
	fmt.Println((*ca1_context).Config.Signer,"Context initialized")
	// initialize cacontext for ca2
	ca2_context := CA.InitializeCAContext("ca_testconfig/2/ca_config.json")
	fmt.Println((*ca2_context).Config.Signer,"Context initialized")
	// initialize cacontext for ca3
	ca3_context := CA.InitializeCAContext("ca_testconfig/3/ca_config.json")
	fmt.Println((*ca3_context).Config.Signer,"Context initialized")
}

func TestLoggerServer(t *testing.T){
	// initialize loggercontext for logger1
	logger1_context := Logger.InitializeLoggerContextWithConfigFile("logger_testconfig/1/logger_config.json")
	fmt.Println((*logger1_context).Config.Signer,"Context initialized")
	// initialize loggercontext for logger2
	logger2_context := Logger.InitializeLoggerContextWithConfigFile("logger_testconfig/2/logger_config.json")
	fmt.Println((*logger2_context).Config.Signer,"Context initialized")
	// initialize loggercontext for logger3
	logger3_context := Logger.InitializeLoggerContextWithConfigFile("logger_testconfig/3/logger_config.json")
	fmt.Println((*logger3_context).Config.Signer,"Context initialized")
}*/