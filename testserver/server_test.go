package testserver


import(
	"CTng/CA"
	"CTng/Logger"
	"CTng/monitor"
	"CTng/gossip"
	"CTng/config"
	//"CTng/crypto"
	"testing"
	"fmt"
)
func InitializeMonitorContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) monitor.MonitorContext {
	conf, err := config.LoadMonitorConfig(public_config_path, private_config_path, crypto_config_path)
	if err != nil {
		//panic(err)
	}
	// Space is allocated for all storage fields, and then make is run to initialize these spaces.
	storage_temp := new(gossip.Gossip_Storage)
	*storage_temp = make(gossip.Gossip_Storage)
	storage_conflict_pom := new(gossip.Gossip_Storage)
	*storage_conflict_pom = make(gossip.Gossip_Storage)
	storage_accusation_pom := new(gossip.Gossip_Storage)
	*storage_accusation_pom = make(gossip.Gossip_Storage)
	storage_sth_full := new(gossip.Gossip_Storage)
	*storage_sth_full = make(gossip.Gossip_Storage)
	storage_rev_full := new(gossip.Gossip_Storage)
	*storage_rev_full = make(gossip.Gossip_Storage)
	ctx := monitor.MonitorContext{
		Config:                 &conf,
		Storage_TEMP:           storage_temp,
		Storage_CONFLICT_POM:   storage_conflict_pom,
		Storage_ACCUSATION_POM: storage_accusation_pom,
		Storage_STH_FULL:       storage_sth_full,
		Storage_REV_FULL:       storage_rev_full,
		StorageID:              storageID,
	}
	ctx.Config = &conf
	return ctx
}

func InitializeGossiperContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) gossip.GossiperContext {
	conf, err := config.LoadGossiperConfig(public_config_path, private_config_path, crypto_config_path)
	if err != nil {
		panic(err)
	}
	storage_raw := new(gossip.Gossip_Storage_Counter)
	*storage_raw = make(gossip.Gossip_Storage_Counter)
	storage_frag := new(gossip.Gossip_Storage_Counter)
	*storage_frag = make(gossip.Gossip_Storage_Counter)
	storage_full := new(gossip.Gossip_Storage)
	*storage_full = make(gossip.Gossip_Storage)
	storage_pom := new(gossip.Gossip_Storage)
	*storage_pom = make(gossip.Gossip_Storage)
	storage_pom_temp := new(gossip.Gossip_Storage)
	*storage_pom_temp = make(gossip.Gossip_Storage)
	gossip_object_TSS_DB := new(gossip.Gossip_Object_TSS_DB)
	*gossip_object_TSS_DB = make(gossip.Gossip_Object_TSS_DB)
	accusation_db := new(gossip.Accusation_DB)
	*accusation_db = make(gossip.Accusation_DB)
	conflict_db := new(gossip.Conflict_DB)
	*conflict_db = make(gossip.Conflict_DB)
	g_log := new(gossip.Gossiper_log)
	*g_log = make(gossip.Gossiper_log) 
	ctx := gossip.GossiperContext{
		Config:      &conf,
		//STH + REV + ACC + CON
		Storage_RAW:  storage_raw,
		//STH_FRAG + REV_FRAG + ACC_FRAG + CON_FRAG
		Storage_FRAG: storage_frag,
		//STH_FULL + REV_FULL + ACC_FULL + CON_FULL
		Storage_FULL: storage_full,
		//CON_FRAG + ACC_FULL + CON_FULL 
		Storage_POM: storage_pom,
		Storage_POM_TEMP: storage_pom_temp,
		//ACC_FRAG counter + CON_FRAG counter 
		Obj_TSS_DB: gossip_object_TSS_DB,
		//ACC Counter
		ACC_DB: accusation_db,
		CON_DB: conflict_db,
		G_log: g_log,
		StorageFile: "gossiper_data.json", // could be a parameter in the future.
		StorageID:   storageID,
	}
	return ctx
}


func TestEntityContext (t *testing.T){
	// initialize CA context
	ctx_ca_1 := CA.InitializeCAContext("../Gen/ca_testconfig/1/CA_public_config.json","../Gen/ca_testconfig/1/CA_private_config.json","../Gen/ca_testconfig/1/CA_crypto_config.json")
	ctx_ca_2 := CA.InitializeCAContext("../Gen/ca_testconfig/2/CA_public_config.json","../Gen/ca_testconfig/2/CA_private_config.json","../Gen/ca_testconfig/2/CA_crypto_config.json")
	fmt.Println(ctx_ca_1.CA_private_config.Signer, ctx_ca_2.CA_private_config.Signer)
	// initialze Logger context
	ctx_logger_1 := Logger.InitializeLoggerContext("../Gen/logger_testconfig/1/Logger_public_config.json","../Gen/logger_testconfig/1/Logger_private_config.json","../Gen/logger_testconfig/1/Logger_crypto_config.json")
	ctx_logger_2 := Logger.InitializeLoggerContext("../Gen/logger_testconfig/2/Logger_public_config.json","../Gen/logger_testconfig/2/Logger_private_config.json","../Gen/logger_testconfig/2/Logger_crypto_config.json")
	fmt.Println(ctx_logger_1.Logger_private_config.Signer, ctx_logger_2.Logger_private_config.Signer)
	// initialize Monitor context
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json","../Gen/monitor_testconfig/1/Monitor_private_config.json","../Gen/monitor_testconfig/1/Monitor_crypto_config.json","1")
	ctx_monitor_2 := InitializeMonitorContext("../Gen/monitor_testconfig/2/Monitor_public_config.json","../Gen/monitor_testconfig/2/Monitor_private_config.json","../Gen/monitor_testconfig/2/Monitor_crypto_config.json","2")
	ctx_monitor_3 := InitializeMonitorContext("../Gen/monitor_testconfig/3/Monitor_public_config.json","../Gen/monitor_testconfig/3/Monitor_private_config.json","../Gen/monitor_testconfig/3/Monitor_crypto_config.json","3")
	ctx_monitor_4 := InitializeMonitorContext("../Gen/monitor_testconfig/4/Monitor_public_config.json","../Gen/monitor_testconfig/4/Monitor_private_config.json","../Gen/monitor_testconfig/4/Monitor_crypto_config.json","4")
	fmt.Println(ctx_monitor_1.Config.Signer, ctx_monitor_2.Config.Signer, ctx_monitor_3.Config.Signer, ctx_monitor_4.Config.Signer)
	// initialize Gossiper context
	ctx_gossiper_1 := InitializeGossiperContext("../Gen/gossiper_testconfig/1/Gossiper_public_config.json","../Gen/gossiper_testconfig/1/Gossiper_private_config.json","../Gen/gossiper_testconfig/1/Gossiper_crypto_config.json","1")
	ctx_gossiper_2 := InitializeGossiperContext("../Gen/gossiper_testconfig/2/Gossiper_public_config.json","../Gen/gossiper_testconfig/2/Gossiper_private_config.json","../Gen/gossiper_testconfig/2/Gossiper_crypto_config.json","2")
	ctx_gossiper_3 := InitializeGossiperContext("../Gen/gossiper_testconfig/3/Gossiper_public_config.json","../Gen/gossiper_testconfig/3/Gossiper_private_config.json","../Gen/gossiper_testconfig/3/Gossiper_crypto_config.json","3")
	ctx_gossiper_4 := InitializeGossiperContext("../Gen/gossiper_testconfig/4/Gossiper_public_config.json","../Gen/gossiper_testconfig/4/Gossiper_private_config.json","../Gen/gossiper_testconfig/4/Gossiper_crypto_config.json","4")
	fmt.Println((*ctx_gossiper_1.Config).Crypto.SelfID.String(), (*ctx_gossiper_2.Config).Crypto.SelfID.String(), (*ctx_gossiper_3.Config).Crypto.SelfID.String(), (*ctx_gossiper_4.Config).Crypto.SelfID.String())

}