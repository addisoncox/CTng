package client_test

import(
	"testing"
	"CTng/Gen"
	"CTng/CA"
	"CTng/Logger"
	"CTng/monitor"
	"CTng/gossip"
	"fmt"
)
var num_ca int = 3
var num_logger int = 3
var num_gossiper int = 4
var num_monitor int = 4
var Threshold int = 2
var num_cert int = 7
var MMD int = 60
var MRD int = 60
var config_path string = ""

var ctx_ca []*CA.CAContext
var ctx_logger []*Logger.LoggerContext
var ctx_gossiper []*gossip.GossiperContext
var ctx_monitor []*monitor.MonitorContext

func Test_gen(t *testing.T){
	Gen.Generateall(num_gossiper,Threshold,num_logger,num_ca,num_cert,MMD,MRD,config_path)
}

func Test_Context_Init(t *testing.T){
	for i:=0;i<num_ca;i++{
		ctx_ca = append(ctx_ca,Gen.InitializeOneEntity("CA",fmt.Sprint(i+1)).(*CA.CAContext))
	}
	for i:=0;i<num_logger;i++{
		ctx_logger = append(ctx_logger,Gen.InitializeOneEntity("Logger",fmt.Sprint(i+1)).(*Logger.LoggerContext))
	}
	for i:=0;i<num_monitor;i++{
		ctx_monitor = append(ctx_monitor,Gen.InitializeOneEntity("Monitor",fmt.Sprint(i+1)).(*monitor.MonitorContext))
	}
	for i:=0;i<num_gossiper;i++{
		ctx_gossiper = append(ctx_gossiper,Gen.InitializeOneEntity("Gossiper",fmt.Sprint(i+1)).(*gossip.GossiperContext))
	}
	fmt.Println(ctx_ca[0].CA_crypto_config.SelfID,ctx_ca[1].CA_crypto_config.SelfID,ctx_ca[2].CA_crypto_config.SelfID)
	fmt.Println(ctx_logger[0].Logger_crypto_config.SelfID,ctx_logger[1].Logger_crypto_config.SelfID,ctx_logger[2].Logger_crypto_config.SelfID)
	fmt.Println(ctx_monitor[0].Config.Crypto.SelfID,ctx_monitor[1].Config.Crypto.SelfID,ctx_monitor[2].Config.Crypto.SelfID,ctx_monitor[3].Config.Crypto.SelfID)
	fmt.Println(ctx_gossiper[0].Config.Crypto.SelfID,ctx_gossiper[1].Config.Crypto.SelfID,ctx_gossiper[2].Config.Crypto.SelfID,ctx_gossiper[3].Config.Crypto.SelfID)
}