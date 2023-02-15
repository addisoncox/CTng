package testserver


import(
	"CTng/Gen"
	"CTng/CA"
	"CTng/Logger"
	"CTng/monitor"
	"CTng/gossip"
	//"CTng/config"
//	"CTng/crypto"
	"testing"
	//"sync"
	"fmt"
	"time"
	"crypto/x509"
	"crypto/x509/pkix"
//	"encoding/json"
//	"io/ioutil"
//	"os"
	//"encoding/pem"
	//"log"
//	"crypto/rand"
//	"github.com/bits-and-blooms/bitset"
)


// For the client test
//we will have 3 CAs, one normal CA, One Split World CA, and one Sometimes Unreponsive CA
//we will have 3 Loggers, one normal logger, one split world logger, and one sometimes unreponsive logger

//let CA 1 be the normal CA, CA 2 be the sometimes unreponsive CA, and CA 3 be the split world CA
//let Logger 1 be the normal logger, Logger 2 be the sometimes unreponsive logger, and Logger 3 be the split world logger

//We are simulating the interaction for 4 periods
//Period 1: All CAs and Loggers are normal
//Period 2: CA 2 is sometimes unreponsive, and Logger 3 is split world
//Period 3: CA 3 is split world, and Logger 2 is sometimes unreponsive
//Period 4: All CAs and Loggers are normal (we won't get any new information from CA 3 and Logger 3 because they have been blacklisted)

//For the CAs
//Period 1: CA 1,2 and 3 are all normal
//Period 2: CA 1 is normal, CA 2 is unreponsive, and CA 3 is normal
//Period 3: CA 1 is normal, CA 2 is normal, and CA 3 is split world
//Period 4: CA 1,2 and 3 are all normal (but we still won't have any new information from CA 3 because it has been blacklisted)

//For the Loggers
//Period 1: Logger 1,2 and 3 are all normal
//Period 2: Logger 1 is normal, Logger 2 is normal, and Logger 3 is split world
//Period 3: Logger 1 is normal, Logger 2 is unreponsive, and Logger 3 normal (but we still won't have any new information from Logger 2 because it has been blacklisted)
//Period 4: Logger 1,2 and 3 are all normal (but we still won't have any new information from Logger 3 because it has been blacklisted)

// Variables for CAs
var ctx_ca_1 *CA.CAContext // Normal CA
var ctx_ca_2 *CA.CAContext // Sometimes Unreponsive CA
var ctx_ca_3 *CA.CAContext // Split World CA
var CA1_cert_pool CA.CertPool
var CA2_cert_pool CA.CertPool
var CA3_cert_pool CA.CertPool
var REV_CA1 []gossip.Gossip_object 
var REV_CA2 []gossip.Gossip_object
var REV_CA3 []gossip.Gossip_object
var REV_CA3_alt []gossip.Gossip_object // Conflicting REV for CA 3

// Variables for Loggers
var ctx_logger_1 *Logger.LoggerContext
var ctx_logger_2 *Logger.LoggerContext
var ctx_logger_3 *Logger.LoggerContext
var Logger1_cert_pool []*x509.Certificate
var Logger2_cert_pool []*x509.Certificate
var Logger3_cert_pool []*x509.Certificate
var logger3_cert_pool_alt []*x509.Certificate // Conflicting cert pool for logger 3
var STH_Logger1 []gossip.Gossip_object
var STH_Logger2 []gossip.Gossip_object
var STH_Logger3 []gossip.Gossip_object
var STH_Logger3_alt []gossip.Gossip_object // Conflicting STH for logger 3
var POI_Logger1_map map[string][]CA.POI
var POI_Logger2_map map[string][]CA.POI
var POI_Logger3_map map[string][]CA.POI

// Variables for Gossipers
var ctx_gossiper_1 *gossip.GossiperContext
var ctx_gossiper_2 *gossip.GossiperContext
var ctx_gossiper_3 *gossip.GossiperContext
var ctx_gossiper_4 *gossip.GossiperContext

// Variables for Monitors
var ctx_monitor_1 *monitor.MonitorContext
var ctx_monitor_2 *monitor.MonitorContext
var ctx_monitor_3 *monitor.MonitorContext
var ctx_monitor_4 *monitor.MonitorContext

// Variable for a single monitor, should be the same accross all monitors
var STH_FULL []gossip.Gossip_object
var REV_FULL []gossip.Gossip_object 
var ACC_FULL []gossip.Gossip_object
var CON_FULL []gossip.Gossip_object

// All the certs from all the CAs for client test
var cert_pool []*x509.Certificate
// 7 certs per CA
// 1 cert only logged by logger 1
// 1 cert only logged by logger 2
// 1 cert only logged by logger 3
// 1 cert logged by logger 1 and 2
// 1 cert logged by logger 1 and 3
// 1 cert logged by logger 2 and 3
// 1 cert logged by all 3 loggers
var CertsPerCA int

// Some Variables for the client test not important for the client test
var host string
var isCA bool
var validFor time.Duration
var Issuer_1 pkix.Name
var Issuer_2 pkix.Name
var Issuer_3 pkix.Name



func test_gen(t *testing.T){
	// Arguements are: num_gossiper int, Threshold int, num_logger int, num_ca int, num_cert int, MMD int, MRD int, config_path string
	Gen.Generateall(4,2,3,3,7,60,60,"")
}

func Test_Context_Init(t *testing.T){
	ctx_ca_1 = Gen.InitializeOneEntity("CA","1").(*CA.CAContext)
	ctx_ca_2 = Gen.InitializeOneEntity("CA","2").(*CA.CAContext)
	ctx_ca_3 = Gen.InitializeOneEntity("CA","3").(*CA.CAContext)
	ctx_logger_1 = Gen.InitializeOneEntity("Logger","1").(*Logger.LoggerContext)
	ctx_logger_2 = Gen.InitializeOneEntity("Logger","2").(*Logger.LoggerContext)
	ctx_logger_3 = Gen.InitializeOneEntity("Logger","3").(*Logger.LoggerContext)
	ctx_monitor_1 = Gen.InitializeOneEntity("Monitor","1").(*monitor.MonitorContext)
	ctx_monitor_2 = Gen.InitializeOneEntity("Monitor","2").(*monitor.MonitorContext)
	ctx_monitor_3 = Gen.InitializeOneEntity("Monitor","3").(*monitor.MonitorContext)
	ctx_monitor_4 = Gen.InitializeOneEntity("Monitor","4").(*monitor.MonitorContext)
	ctx_gossiper_1 = Gen.InitializeOneEntity("Gossiper","1").(*gossip.GossiperContext)
	ctx_gossiper_2 = Gen.InitializeOneEntity("Gossiper","2").(*gossip.GossiperContext)
	ctx_gossiper_3 = Gen.InitializeOneEntity("Gossiper","3").(*gossip.GossiperContext)
	ctx_gossiper_4 = Gen.InitializeOneEntity("Gossiper","4").(*gossip.GossiperContext)
	fmt.Println(ctx_ca_1.CA_private_config.Signer, ctx_ca_2.CA_private_config.Signer, ctx_ca_3.CA_private_config.Signer)
	fmt.Println(ctx_logger_1.Logger_private_config.Signer, ctx_logger_2.Logger_private_config.Signer, ctx_logger_3.Logger_private_config.Signer)
	fmt.Println(ctx_monitor_1.Config.Signer, ctx_monitor_2.Config.Signer, ctx_monitor_3.Config.Signer, ctx_monitor_4.Config.Signer)
	fmt.Println((*ctx_gossiper_1.Config).Crypto.SelfID.String(), (*ctx_gossiper_2.Config).Crypto.SelfID.String(), (*ctx_gossiper_3.Config).Crypto.SelfID.String(), (*ctx_gossiper_4.Config).Crypto.SelfID.String())
	fmt.Println("Contexts Initialized")
	// initialize some CA variables
	host = "Host Whatever"
	isCA = false
	validFor = 365 * 24 * time.Hour
	CertsPerCA = 7
	Issuer_1 = CA.Generate_Issuer("CA 1")
	Issuer_2 = CA.Generate_Issuer("CA 2")
	Issuer_3 = CA.Generate_Issuer("CA 3")
}

func Test_CA_Cert_Gen(t *testing.T){
	// Initialize CA_cert_pool
	CA1_cert_pool = *CA.NewCertPool()
	CA2_cert_pool = *CA.NewCertPool()
	CA3_cert_pool = *CA.NewCertPool()
	// generate certificates
	certs1 := CA.Generate_N_Signed_PreCert(ctx_ca_1, CertsPerCA, host, validFor, isCA, Issuer_1, ctx_ca_1.Rootcert, false, &ctx_ca_1.CA_crypto_config.RSAPrivateKey, 0)
	certs2 := CA.Generate_N_Signed_PreCert(ctx_ca_2, CertsPerCA, host, validFor, isCA, Issuer_2, ctx_ca_2.Rootcert, false, &ctx_ca_2.CA_crypto_config.RSAPrivateKey, 7)
	certs3 := CA.Generate_N_Signed_PreCert(ctx_ca_3, CertsPerCA, host, validFor, isCA, Issuer_3, ctx_ca_3.Rootcert, false, &ctx_ca_3.CA_crypto_config.RSAPrivateKey, 14)
	for i := 0; i < CertsPerCA; i++{
		CA1_cert_pool.AddCert(certs1[i])
		CA2_cert_pool.AddCert(certs2[i])
		CA3_cert_pool.AddCert(certs3[i])
		fmt.Println(certs1[i].Subject.CommonName, certs2[i].Subject.CommonName, certs3[i].Subject.CommonName)
	}
	cert_pool = append(cert_pool, certs1...)
	cert_pool = append(cert_pool, certs2...)
	cert_pool = append(cert_pool, certs3...)
	fmt.Println("Number of Certs in the pool: ", len(cert_pool))

	// try to parse CTng extension from the first cert
	fmt.Println(cert_pool[0].Issuer)
	CTng_ext_list := CA.GetCTngExtensions(cert_pool[0])
	fmt.Println("CTng extension list: ", CTng_ext_list)
	// try to print all the revocation ID from cert_pool
	for i := 0; i < len(cert_pool); i++{
		fmt.Print(cert_pool[i].Issuer, " : ",CA.GetCTngExtensions(cert_pool[i])[0].RID,"  ")
	}
}

