package Gen
import (
	"CTng/CA"
	"CTng/Logger"
	"CTng/config"
	"CTng/crypto"
	//"CTng/util"
	//"bytes"
	//"encoding/json"
	"fmt"
	"encoding/json"
	"io/ioutil"
	//"log"
	//"net/http"
	//"testing"
	//"os"
	//"crypto/rsa"
	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)
func GenerateCryptoconfig_map(Total int, Threshold int, entitytype string) map[string]crypto.StoredCryptoConfig {
	prefix := "localhost:000"
	switch entitytype {
	case "CA":
		prefix = "localhost:910"
	case "Logger":
		prefix = "localhost:900"
	case "Monitor":
		prefix = "localhost:818"
	case "Gossiper":
		prefix = "localhost:808"
	}	
	var cryptoConfigs map [string]crypto.StoredCryptoConfig
	cryptoConfigs = make(map[string]crypto.StoredCryptoConfig)
	for i := 0; i < Total; i++ {
		newcryptoConfig := crypto.StoredCryptoConfig{
			SelfID: crypto.CTngID(prefix + fmt.Sprint(i)),
			Threshold: Threshold,
			N: Total,
			HashScheme: 4,
			SignScheme: "rsa",
			ThresholdScheme: "bls",
		}
		cryptoConfigs[prefix + fmt.Sprint(i)] = newcryptoConfig
	}
	return cryptoConfigs
}

func Generate_all_list(num_MG int, num_CA int, num_logger int) ([]string, []string, []string, []string) {
	G_list := make([]string, num_MG)
	M_list := make([]string, num_MG)
	C_list := make([]string, num_CA)
	L_list := make([]string, num_logger)
	for i := 0; i < num_MG; i++ {
		G_list[i] = "localhost:808" + fmt.Sprint(i)
		M_list[i] = "localhost:818" + fmt.Sprint(i)
	}
	for i := 0; i < num_CA; i++ {
		C_list[i] = "localhost:910" + fmt.Sprint(i)
	}
	for i := 0; i < num_logger; i++ {
		L_list[i] = "localhost:900" + fmt.Sprint(i)
	}
	return G_list, M_list, C_list, L_list
}

func GenerateCA_private_config_map(G_list []string, M_list []string, L_list []string, num_CA int, num_cert int) map[string]CA.CA_private_config {
	ca_private_map := make(map[string]CA.CA_private_config)
	for i := 0; i < num_CA; i++ {
		// generate CA config
		ca_private_config := CA.GenerateCA_private_config_template()
		// Signer
		ca_private_config.Signer = "localhost:910" + fmt.Sprint(i)
		// Port
		ca_private_config.Port = "910" + fmt.Sprint(i)
		// Cert_per_period
		ca_private_config.Cert_per_period = num_cert
		// Gossiperlist
		ca_private_config.Gossiperlist = G_list
		// Monitorlist
		ca_private_config.Monitorlist = M_list
		// Loggerlist
		ca_private_config.Loggerlist = L_list
		// append to caConfigs
		ca_private_map[ca_private_config.Signer] = *ca_private_config
	}
	return ca_private_map
}

func GenerateLogger_private_config_map(G_list []string, M_list []string, C_list []string, num_logger int) map[string]Logger.Logger_private_config {
	logger_private_map := make(map[string]Logger.Logger_private_config)
	for i := 0; i < num_logger; i++ {
		// generate logger config
		logger_private_config := Logger.GenerateLogger_private_config_template()
		// Signer
		logger_private_config.Signer = "localhost:900" + fmt.Sprint(i)
		// Port
		logger_private_config.Port = "900" + fmt.Sprint(i)
		// Gossiperlist
		logger_private_config.Gossiperlist = G_list
		// Monitorlist
		logger_private_config.Monitorlist = M_list
		// Loggerlist
		logger_private_config.CAlist = C_list
		// append to loggerConfigs
		logger_private_map[logger_private_config.Signer] = *logger_private_config
	}
	return logger_private_map
}


func GenerateCA_public_config(L_list []string, C_list []string, MMD int, MRD int, Http_vers []string) *CA.CA_public_config{
	// generate CA config
	ca_public_config := CA.GenerateCA_public_config_template()
	// All_CA_URLs
	ca_public_config.All_CA_URLs = C_list
	// All_Logger_URLs
	ca_public_config.All_Logger_URLs = L_list
	// MMD
	ca_public_config.MMD = MMD
	// MRD
	ca_public_config.MRD = MRD
	// Http_vers
	ca_public_config.Http_vers = Http_vers
	return ca_public_config
}

func GenerateLogger_public_config(L_list []string, C_list []string, MMD int, MRD int, Http_vers []string) *Logger.Logger_public_config{
	// generate logger config
	logger_public_config := Logger.GenerateLogger_public_config_template()
	// All_CA_URLs
	logger_public_config.All_CA_URLs = C_list
	// All_Logger_URLs
	logger_public_config.All_Logger_URLs = L_list
	// MMD
	logger_public_config.MMD = MMD
	// MRD
	logger_public_config.MRD = MRD
	// Http_vers
	logger_public_config.Http_vers = Http_vers
	return logger_public_config
}


func GenerateMonitor_public_config(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int,Http_vers []string) *config.Monitor_public_config{
	return &config.Monitor_public_config{
		All_CA_URLs:      C_list,
		All_Logger_URLs:  L_list,
		Gossip_wait_time: Gossip_wait_time,
		MMD:              MMD,
		MRD:              MRD,
		Length:           100,
		Http_vers:        Http_vers,
	}
}


func GenerateMonitor_private_config(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int,Http_vers []string, filepath string) map[string]config.Monitor_config{
	Monitor_private_map := make(map[string]config.Monitor_config)
	for i := 0; i < len(M_list); i++ {
		// generate monitor config
		monitor_private_config := &config.Monitor_config{
			Crypto_config_location: filepath,
			CA_URLs:                C_list,
			Logger_URLs:            L_list,
			Signer:                 M_list[i],
			Gossiper_URL:           G_list[i],
			Inbound_gossiper_port:  "808" + fmt.Sprint(i),
			Port:                   "818" + fmt.Sprint(i),
		}
		// append to monitorConfigs
		Monitor_private_map[monitor_private_config.Signer] = *monitor_private_config
	}
	return Monitor_private_map
}


func GenerateGossiper_public_config(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int,Communiation_delay int,Http_vers []string) *config.Gossiper_public_config{
	return &config.Gossiper_public_config{
		Communiation_delay: Communiation_delay,
		Gossip_wait_time:   Gossip_wait_time,
		Max_push_size:      100,
		Period_interval:    1000,
		Expiration_time:    0,
		MMD:                MMD,
		MRD:                MRD,
		Gossiper_URLs:      G_list,
		Signer_URLs:        M_list,
	}
}

func GenerateGossiper_private_config(G_list []string, M_list []string, C_list []string, L_list []string, MMD int, MRD int, Gossip_wait_time int,Communiation_delay int,Http_vers []string, filepath string) map[string]config.Gossiper_config{
	Gossiper_private_map := make(map[string]config.Gossiper_config)
	for i := 0; i < len(G_list); i++ {
		// generate gossiper config
		gossiper_private_config := &config.Gossiper_config{
			// Crypto_config_location: filepath,
			Connected_Gossipers: G_list,
			Owner_URL:           M_list[i],
			Port:                "808" + fmt.Sprint(i),
		}
		// append to gossiperConfigs
		Gossiper_private_map[gossiper_private_config.Owner_URL] = *gossiper_private_config
	}
	return Gossiper_private_map
}

func write_all_configs_to_file(public_config interface{}, private_config interface{}, crypto_config interface{}, filepath string, entitytype string) {
	// write to file
	public_config_path := filepath + entitytype + "_public_config.json"
	private_config_path := filepath + entitytype + "_private_config.json"
	crypto_config_path := filepath + entitytype + "_crypto_config.json"
	public_config_json, _ := json.MarshalIndent(public_config," "," ")
	private_config_json, _ := json.MarshalIndent(private_config," "," ")
	crypto_config_json, _ := json.MarshalIndent(crypto_config, " ", " ")
	ioutil.WriteFile(public_config_path, public_config_json, 0644)
	ioutil.WriteFile(private_config_path, private_config_json, 0644)
	ioutil.WriteFile(crypto_config_path, crypto_config_json, 0644)
}
