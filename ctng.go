package main

/*
Code Ownership:
Finn - Made main function
*/
import (
	// "CTng/CA"
	"CTng/client"
	"CTng/config"
	"CTng/gossip"
	// "CTng/logger"
	"CTng/minimon"
	"CTng/miniclient"
	"CTng/monitor"
	"CTng/testData/fakeCA"
	"CTng/testData/fakeLogger"
	"CTng/webserver"
	"CTng/logger_ca"
	"CTng/network"
	"fmt"
	"os"
)

// main is run when the user types "go run ."
// it allows a user to run a gossiper, monitor, fakeLogger, or fakeCA.
// Currently unimplemented: Different object_storage locations than ./gossiper_data.json and ./monitor_data.json
// This field could be defined within the configuration files to make this more modular.
func main() {
	helpText := "Usage:\n ./CTng [gossiper|monitor] <public_config_file_path> <private_config_file_path> <crypto_config_path>\n ./Ctng [logger|ca] <fakeentity_config_path>\n ./CTng web"

	if len(os.Args) < 2 {
		fmt.Println(helpText)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "minilogger":
		logger_ca.StartLogger(os.Args[2])
	case "minica":
		logger_ca.StartCA()
	case "lcmonitor":
		logger_ca.StartMonitor()
	case "web":
		webserver.Start()
	case "minimon":
		minimon.Start()
	case "miniclient":
		miniclient.Start()
	case "network_monitor":
		network.StartMonitor(os.Args[2])
	case "network_gossiper":
		network.StartGossiper(os.Args[2])
	case "network_logger":
		network.StartLogger(os.Args[2])
	case "network_ca":
		network.StartCA(os.Args[2])
	case "gossiper":
		// make the config object.
		conf, err := config.LoadGossiperConfig(os.Args[2], os.Args[3], os.Args[4])
		if err != nil {
			fmt.Println(helpText)
			panic(err)
		}
		ctx := gossip.Gossip_Context_Init(&conf, os.Args[5])
		gossip.StartGossiperServer(ctx)
	case "monitor":
		ctx := monitor.InitializeMonitorContext(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
		monitor.StartMonitorServer(ctx)
	case "logger":
		fakeLogger.RunFakeLogger(os.Args[2])
	case "ca":
		fakeCA.RunFakeCA(os.Args[2])
	case "client":
		conf, err := client.LoadClientConfig(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(helpText)
			panic(err)
		}
		storage_conflict_pom := new(gossip.Gossip_Storage)
		*storage_conflict_pom = make(gossip.Gossip_Storage)
		storage_sth_full := new(gossip.Gossip_Storage)
		*storage_sth_full = make(gossip.Gossip_Storage)
		storage_rev_full := new(gossip.Gossip_Storage)
		*storage_rev_full = make(gossip.Gossip_Storage)
		storage_crv := new(client.CRV_Storage)
		*storage_crv = make(client.CRV_Storage)
		ctx := client.ClientContext{
			Storage_STH_FULL:     storage_sth_full,
			Storage_REV_FULL:     storage_rev_full,
			Storage_CONFLICT_POM: storage_conflict_pom,
			Storage_CRVRECORD:    storage_crv,
			Config:               &conf,
		}
		client.StartClientServer(&ctx)
	default:
		fmt.Println(helpText)
	}
}
