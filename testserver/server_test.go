package testserver


import(
	"CTng/CA"
	"CTng/Logger"
	"CTng/monitor"
	"CTng/gossip"
	"CTng/config"
	"CTng/crypto"
	"testing"
	"sync"
	"fmt"
	"time"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"encoding/pem"
	"log"
	"crypto/rand"
	"github.com/bits-and-blooms/bitset"
)

var ctx_ca_1 *CA.CAContext
var ctx_ca_2 *CA.CAContext
var CertsPerCA int
var ctx_logger_1 *Logger.LoggerContext
var ctx_logger_2 *Logger.LoggerContext
var ctx_monitor_1 *monitor.MonitorContext
var ctx_monitor_2 *monitor.MonitorContext
var ctx_monitor_3 *monitor.MonitorContext
var ctx_monitor_4 *monitor.MonitorContext
var ctx_gossiper_1 *gossip.GossiperContext
var ctx_gossiper_2 *gossip.GossiperContext
var ctx_gossiper_3 *gossip.GossiperContext
var ctx_gossiper_4 *gossip.GossiperContext
var cert_pool []*x509.Certificate
var Logger1_cert_pool []*x509.Certificate
var logger1_cert_pool_alt []*x509.Certificate // cert pool for logger 1 with a different number of certs
var Logger2_cert_pool []*x509.Certificate
var logger2_cert_pool_alt []*x509.Certificate // cert pool for logger 2 with a different number of certs
var CA1_cert_pool CA.CertPool
var CA2_cert_pool CA.CertPool
var POI_Logger1_map map[string][]CA.POI
var POI_Logger2_map map[string][]CA.POI
var STH_Logger1 gossip.Gossip_object
var STH_Logger1_alt gossip.Gossip_object // Conflicting STH for logger 1
var STH_Logger2 gossip.Gossip_object
var STH_Logger2_alt gossip.Gossip_object // Conflicting STH for logger 2
var STH_FULL_Logger1 gossip.Gossip_object
var STH_FULL_Logger2 gossip.Gossip_object
var REV_CA1 gossip.Gossip_object
var REV_CA1_alt gossip.Gossip_object
var REV_CA2 gossip.Gossip_object
var REV_CA2_alt gossip.Gossip_object
var REV_FULL_CA1 gossip.Gossip_object
var REV_FULL_CA2 gossip.Gossip_object

func SaveCertificateToDisk(certBytes []byte, filePath string) {
	certOut, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", filePath, err)
	}
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s: %v", filePath, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", filePath, err)
	}
}

func InitializeMonitorContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) *monitor.MonitorContext {
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
	return &ctx
}

func InitializeGossiperContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) *gossip.GossiperContext {
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
		RWlock: &sync.RWMutex{},
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
	return &ctx
}


func TestEntityContext (t *testing.T){
	// initialize CA context
	ctx_ca_1 = CA.InitializeCAContext("../Gen/ca_testconfig/1/CA_public_config.json","../Gen/ca_testconfig/1/CA_private_config.json","../Gen/ca_testconfig/1/CA_crypto_config.json")
	ctx_ca_2 = CA.InitializeCAContext("../Gen/ca_testconfig/2/CA_public_config.json","../Gen/ca_testconfig/2/CA_private_config.json","../Gen/ca_testconfig/2/CA_crypto_config.json")
	fmt.Println(ctx_ca_1.CA_private_config.Signer, ctx_ca_2.CA_private_config.Signer)
	// initialze Logger context
	ctx_logger_1 = Logger.InitializeLoggerContext("../Gen/logger_testconfig/1/Logger_public_config.json","../Gen/logger_testconfig/1/Logger_private_config.json","../Gen/logger_testconfig/1/Logger_crypto_config.json")
	ctx_logger_2 = Logger.InitializeLoggerContext("../Gen/logger_testconfig/2/Logger_public_config.json","../Gen/logger_testconfig/2/Logger_private_config.json","../Gen/logger_testconfig/2/Logger_crypto_config.json")
	fmt.Println(ctx_logger_1.Logger_private_config.Signer, ctx_logger_2.Logger_private_config.Signer)
	// initialize Monitor context
	ctx_monitor_1 = InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json","../Gen/monitor_testconfig/1/Monitor_private_config.json","../Gen/monitor_testconfig/1/Monitor_crypto_config.json","1")
	ctx_monitor_2 = InitializeMonitorContext("../Gen/monitor_testconfig/2/Monitor_public_config.json","../Gen/monitor_testconfig/2/Monitor_private_config.json","../Gen/monitor_testconfig/2/Monitor_crypto_config.json","2")
	ctx_monitor_3 = InitializeMonitorContext("../Gen/monitor_testconfig/3/Monitor_public_config.json","../Gen/monitor_testconfig/3/Monitor_private_config.json","../Gen/monitor_testconfig/3/Monitor_crypto_config.json","3")
	ctx_monitor_4 = InitializeMonitorContext("../Gen/monitor_testconfig/4/Monitor_public_config.json","../Gen/monitor_testconfig/4/Monitor_private_config.json","../Gen/monitor_testconfig/4/Monitor_crypto_config.json","4")
	fmt.Println(ctx_monitor_1.Config.Signer, ctx_monitor_2.Config.Signer, ctx_monitor_3.Config.Signer, ctx_monitor_4.Config.Signer)
	// initialize Gossiper context
	ctx_gossiper_1 = InitializeGossiperContext("../Gen/gossiper_testconfig/1/Gossiper_public_config.json","../Gen/gossiper_testconfig/1/Gossiper_private_config.json","../Gen/gossiper_testconfig/1/Gossiper_crypto_config.json","1")
	ctx_gossiper_2 = InitializeGossiperContext("../Gen/gossiper_testconfig/2/Gossiper_public_config.json","../Gen/gossiper_testconfig/2/Gossiper_private_config.json","../Gen/gossiper_testconfig/2/Gossiper_crypto_config.json","2")
	ctx_gossiper_3 = InitializeGossiperContext("../Gen/gossiper_testconfig/3/Gossiper_public_config.json","../Gen/gossiper_testconfig/3/Gossiper_private_config.json","../Gen/gossiper_testconfig/3/Gossiper_crypto_config.json","3")
	ctx_gossiper_4 = InitializeGossiperContext("../Gen/gossiper_testconfig/4/Gossiper_public_config.json","../Gen/gossiper_testconfig/4/Gossiper_private_config.json","../Gen/gossiper_testconfig/4/Gossiper_crypto_config.json","4")
	fmt.Println((*ctx_gossiper_1.Config).Crypto.SelfID.String(), (*ctx_gossiper_2.Config).Crypto.SelfID.String(), (*ctx_gossiper_3.Config).Crypto.SelfID.String(), (*ctx_gossiper_4.Config).Crypto.SelfID.String())
	fmt.Println("-------------------------------Context Initialization Test Passed-------------------------------")
}

func TestCACertGen(t *testing.T){
	// Initialize CA_cert_pool
	CA1_cert_pool = *CA.NewCertPool()
	CA2_cert_pool = *CA.NewCertPool()
	// Certs Per CA per period
	CertsPerCA = 5
	// generate issuer
	issuer := CA.Generate_Issuer("CA 1")
	// generate host
	host := "Host Whatever"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate certificates
	certs := CA.Generate_N_Signed_PreCert(ctx_ca_1, CertsPerCA, host, validFor, isCA, issuer, ctx_ca_1.Rootcert, false, &ctx_ca_1.CA_crypto_config.RSAPrivateKey, 0)
	fmt.Println("Number of Certs per period from CA 1: ", len(certs), " ", CA1_cert_pool.GetLength())
	// print the common name of the first 10 certificate
	for i := 0;i < CertsPerCA;i++{
		fmt.Println(certs[i].Subject.CommonName)
		CA1_cert_pool.AddCert(certs[i])
	}
	issuer2 := CA.Generate_Issuer("CA 2")
	certs2 := CA.Generate_N_Signed_PreCert(ctx_ca_2, CertsPerCA, host, validFor, isCA, issuer2, ctx_ca_2.Rootcert, false, &ctx_ca_2.CA_crypto_config.RSAPrivateKey, CertsPerCA)
	fmt.Println("Number of Certs per period from CA 2: ", len(certs2), " ", CA2_cert_pool.GetLength())
	// print the common name of the first 10 certificate
	for i := 0;i < CertsPerCA;i++{
		fmt.Println(certs2[i].Subject.CommonName)
		CA2_cert_pool.AddCert(certs2[i])
	}
	// add certs and certs2 to cert_pool variable
	cert_pool = append(cert_pool, certs...)
	cert_pool = append(cert_pool, certs2...)
	fmt.Println("Number of Certs in the pool: ", len(cert_pool))
	fmt.Println(cert_pool[0].Issuer)
	// try to parse CTng extension from the first cert
	CTng_ext_list := CA.GetCTngExtensions(cert_pool[0])
	fmt.Println("CTng extension list: ", CTng_ext_list)
	fmt.Println("-------------------------------CA Cert Generation Test Passed-------------------------------")
}


func TestCertLogging (t *testing.T){
	// Prepare cert pool for logger 1
	Logger1_cert_pool := make([]*x509.Certificate, 0)
	// append 4 certs from CA 1 and 3 certs from CA 2
	for i := 0;i < 4;i++{
		// Logger 1 logs first 4 certs from CA 1 and first 4 certs from CA 2
		Logger1_cert_pool = append(Logger1_cert_pool, cert_pool[i])
		Logger1_cert_pool = append(Logger1_cert_pool, cert_pool[i+5])
	}
	// Prepare cert pool alt for logger 1
	Logger1_cert_pool_alt := make([]*x509.Certificate, 0)
	// append 3 certs from CA 1 and 3 certs from CA 2 (one less than Logger1_cert_pool)
	for i := 0;i < 3;i++{
		// Logger 1 logs first 4 certs from CA 1 and first 4 certs from CA 2
		Logger1_cert_pool_alt = append(Logger1_cert_pool_alt, cert_pool[i])
		Logger1_cert_pool_alt = append(Logger1_cert_pool_alt, cert_pool[i+5])
	}
	// Prepare cert pool for logger 2
	Logger2_cert_pool := make([]*x509.Certificate, 0)
	// append 4 certs from CA 1 and 3 certs from CA 2
	for i := 0;i < 4;i++{
		// Logger 2 logs last 4 certs from CA 1 and last 4 certs from CA 2
		Logger2_cert_pool = append(Logger2_cert_pool, cert_pool[i+1])
		Logger2_cert_pool = append(Logger2_cert_pool, cert_pool[i+6])
	}
	// Prepare cert pool alt for logger 2
	Logger2_cert_pool_alt := make([]*x509.Certificate, 0)
	// append 3 certs from CA 1 and 3 certs from CA 2 (one less than Logger2_cert_pool)
	for i := 0;i < 3;i++{
		// Logger 2 logs last 4 certs from CA 1 and last 4 certs from CA 2
		Logger2_cert_pool_alt = append(Logger2_cert_pool_alt, cert_pool[i+1])
		Logger2_cert_pool_alt = append(Logger2_cert_pool_alt, cert_pool[i+6])
	}
	// convert []*x509.Certificate to []x509.Certificate
	Logger1_cert_pool_2 := make([]x509.Certificate, 0)
	for i := 0;i < len(Logger1_cert_pool);i++{
		Logger1_cert_pool_2 = append(Logger1_cert_pool_2, *Logger1_cert_pool[i])
	}
	Logger1_cert_pool_alt_2 := make([]x509.Certificate, 0)
	for i := 0;i < len(Logger1_cert_pool_alt);i++{
		Logger1_cert_pool_alt_2 = append(Logger1_cert_pool_alt_2, *Logger1_cert_pool_alt[i])
	}
	Logger2_cert_pool_2 := make([]x509.Certificate, 0)
	for i := 0;i < len(Logger2_cert_pool);i++{
		Logger2_cert_pool_2 = append(Logger2_cert_pool_2, *Logger2_cert_pool[i])
	}
	Logger2_cert_pool_alt_2 := make([]x509.Certificate, 0)
	for i := 0;i < len(Logger2_cert_pool_alt);i++{
		Logger2_cert_pool_alt_2 = append(Logger2_cert_pool_alt_2, *Logger2_cert_pool_alt[i])
	}
	// Start building Merkle Tree and get STH and POI
	gossip_sth_1, _, nodes_logger_1 := Logger.BuildMerkleTreeFromCerts(Logger1_cert_pool_2, *ctx_logger_1, 0)
	gossip_sth_1_alt, _, _ := Logger.BuildMerkleTreeFromCerts(Logger1_cert_pool_alt_2, *ctx_logger_1, 0)
	gossip_sth_2, _, nodes_logger_2 := Logger.BuildMerkleTreeFromCerts(Logger2_cert_pool_2, *ctx_logger_2, 0)
	gossip_sth_2_alt, _, _ := Logger.BuildMerkleTreeFromCerts(Logger2_cert_pool_alt_2, *ctx_logger_2, 0)
	STH_Logger1 = gossip_sth_1
	STH_Logger1_alt = gossip_sth_1_alt
	STH_Logger2 = gossip_sth_2
	STH_Logger2_alt = gossip_sth_2_alt
	fmt.Println("Signer of the STH from logger 1 is: ", STH_Logger1.Signer)
	fmt.Println("Signer of the STH_alt from logger 1 is: ", STH_Logger1_alt.Signer)
	fmt.Println("Signer of the STH from logger 2 is: ", STH_Logger2.Signer)
	fmt.Println("Signer of the STH_alt from logger 2 is: ", STH_Logger2_alt.Signer)
	// initialize POI map
	ca1_from_logger1 := []CA.POI{}
	ca1_from_logger2 := []CA.POI{}
	ca2_from_logger1 := []CA.POI{}
	ca2_from_logger2 := []CA.POI{}
	// iterate over nodes_logger_1
	for i := 0;i < len(nodes_logger_1);i++{
		if nodes_logger_1[i].Issuer == ctx_ca_1.CA_crypto_config.SelfID.String(){
			ca1_from_logger1 = append(ca1_from_logger1, CA.POI{ProofOfInclusion: nodes_logger_1[i].Poi, SubjectKeyId: nodes_logger_1[i].SubjectKeyId})
			new_ctng_ext := CA.CTngExtension{STH: gossip_sth_1, POI:  nodes_logger_1[i].Poi}
			target_cert := CA1_cert_pool.GetCertBySubjectKeyID(nodes_logger_1[i].SubjectKeyId)
			target_cert = CA.AddCTngExtension(target_cert, new_ctng_ext)
			CA1_cert_pool.UpdateCertBySubjectKeyID(nodes_logger_1[i].SubjectKeyId, target_cert)
		}else{
			ca2_from_logger1 = append(ca2_from_logger1, CA.POI{ProofOfInclusion: nodes_logger_1[i].Poi, SubjectKeyId: nodes_logger_1[i].SubjectKeyId})
			new_ctng_ext := CA.CTngExtension{STH: gossip_sth_1, POI:  nodes_logger_1[i].Poi}
			target_cert := CA2_cert_pool.GetCertBySubjectKeyID(nodes_logger_1[i].SubjectKeyId)
			target_cert = CA.AddCTngExtension(target_cert, new_ctng_ext)
			CA2_cert_pool.UpdateCertBySubjectKeyID(nodes_logger_1[i].SubjectKeyId, target_cert)
		}
	}
	// iterate over nodes_logger_2
	for i := 0;i < len(nodes_logger_2);i++{
		if nodes_logger_2[i].Issuer == ctx_ca_1.CA_crypto_config.SelfID.String(){
			ca1_from_logger2 = append(ca1_from_logger2, CA.POI{ProofOfInclusion: nodes_logger_2[i].Poi, SubjectKeyId: nodes_logger_2[i].SubjectKeyId})
			new_ctng_ext := CA.CTngExtension{STH: gossip_sth_2, POI:  nodes_logger_2[i].Poi}
			target_cert := CA1_cert_pool.GetCertBySubjectKeyID(nodes_logger_2[i].SubjectKeyId)
			target_cert = CA.AddCTngExtension(target_cert, new_ctng_ext)
			CA1_cert_pool.UpdateCertBySubjectKeyID(nodes_logger_2[i].SubjectKeyId, target_cert)
		}else{
			ca2_from_logger2 = append(ca2_from_logger2, CA.POI{ProofOfInclusion: nodes_logger_2[i].Poi, SubjectKeyId: nodes_logger_2[i].SubjectKeyId})
			new_ctng_ext := CA.CTngExtension{STH: gossip_sth_2, POI:  nodes_logger_2[i].Poi}
			target_cert := CA2_cert_pool.GetCertBySubjectKeyID(nodes_logger_2[i].SubjectKeyId)
			target_cert = CA.AddCTngExtension(target_cert, new_ctng_ext)
			CA2_cert_pool.UpdateCertBySubjectKeyID(nodes_logger_2[i].SubjectKeyId, target_cert)
		}
	}
	//fmt.Println("POI list for CA 1 from logger 1 is: ", ca1_from_logger1[0].SubjectKeyId)
	//fmt.Println("POI list for CA 1 from logger 2 is: ", ca1_from_logger2)
	//fmt.Println("POI list for CA 2 from logger 1 is: ", ca2_from_logger1)
	//fmt.Println("POI list for CA 2 from logger 2 is: ", ca2_from_logger2)
	
	// For all the certs in CA 1 Cert Pool, Sign them and write them to disk
	ca_1_cert_list := CA1_cert_pool.GetCertList()
	for i := 0;i < CA1_cert_pool.GetLength();i++{
		target_cert := ca_1_cert_list[i]
		derbytes, err := x509.CreateCertificate(rand.Reader, target_cert, ctx_ca_1.Rootcert, target_cert.PublicKey,&ctx_ca_1.CA_crypto_config.RSAPrivateKey)
		if err != nil{
			fmt.Println("Error in creating certificate: ", err)
		}
		//fmt.Println("root cert: ", ctx_ca_1.Rootcert)
		//fmt.Println("derbytes: ", derbytes)

		SaveCertificateToDisk(derbytes, target_cert.Subject.CommonName+ " from CA 1.crt")
	}
	// For all the certs in CA 2 Cert Pool, Sign them and write them to disk
	ca_2_cert_list := CA2_cert_pool.GetCertList()
	for i := 0;i < CA2_cert_pool.GetLength();i++{
		target_cert := ca_2_cert_list[i]
		derbytes, err := x509.CreateCertificate(rand.Reader, target_cert, ctx_ca_2.Rootcert, target_cert.PublicKey,&ctx_ca_2.CA_crypto_config.RSAPrivateKey)
		if err != nil{
			fmt.Println("Error in creating certificate: ", err)
		}
		//fmt.Println("root cert: ", ctx_ca_2.Rootcert)
		//fmt.Println("derbytes: ", derbytes)
		SaveCertificateToDisk(derbytes, target_cert.Subject.CommonName+ " from CA 2.crt")
	}


	// Get STH from cert 1 CA 1
	cert1_ca1 := CA1_cert_pool.GetCertBySubjectKeyID(ca1_from_logger1[0].SubjectKeyId)
	sth1_cert1_ca1 := CA.GetCTngExtensions(cert1_ca1)[1].STH.Signer
	//fmt.Println("cert 1 CA 1 is: ", cert1_ca1.CRLDistributionPoints[1])
	fmt.Println("STH of cert 1 CA 1 is: ", sth1_cert1_ca1)
	//fmt.Println("all ctng ext of cert 1 CA 1 is: ", CA.GetCTngExtensions(cert1_ca1))
	fmt.Println("-------------------------------Cert Logging Test Passed-------------------------------")
}


func TestSTHFULL(t *testing.T){
	//Gossiper 1 Threshold sign STH_logger1
	partial_sig_1, err := ctx_gossiper_1.Config.Crypto.ThresholdSign(STH_Logger1.Signer)
	if err != nil{
		fmt.Println("Error in threshold sign STH_Logger1")
	}
	//Gossiper 2 Threshold sign STH_logger2
	partial_sig_2, err := ctx_gossiper_2.Config.Crypto.ThresholdSign(STH_Logger2.Signer)
	if err != nil{
		fmt.Println("Error in threshold sign STH_Logger2")
	}
	// Create a list of partial signature
	partial_sig_list := []crypto.SigFragment{partial_sig_1, partial_sig_2}
	// Aggregate partial signature
	sig, err := ctx_gossiper_1.Config.Crypto.ThresholdAggregate(partial_sig_list)
	if err != nil{
		fmt.Println("Error in threshold aggregate STH_Logger1 and STH_Logger2")
	}
	sigstring, err:= sig.String()
	if err != nil{
		fmt.Println("Error in converting signature to string")
	}
	// Create Signer map
	signermap := make(map[int]string)
	signermap[0] = ctx_gossiper_1.Config.Crypto.SelfID.String()
	signermap[1] = ctx_gossiper_2.Config.Crypto.SelfID.String()
	STH_FULL_Logger1 = gossip.Gossip_object{
		Application: "CTng",
		Type:        "STH_FULL",
		Period:      "0",
		Signer:      "",
		Signers:     signermap,
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{sigstring},
		Crypto_Scheme: "BLS",
		Payload:     STH_Logger1.Payload,
	}

	//Gossiper 2 Threshold sign STH_logger2
	partial_sig_1, err = ctx_gossiper_1.Config.Crypto.ThresholdSign(STH_Logger1.Signer)
	if err != nil{
		fmt.Println("Error in threshold sign STH_Logger1")
	}
	//Gossiper 3 Threshold sign STH_logger2
	partial_sig_2, err = ctx_gossiper_3.Config.Crypto.ThresholdSign(STH_Logger2.Signer)
	if err != nil{
		fmt.Println("Error in threshold sign STH_Logger2")
	}
	// Create a list of partial signature
	partial_sig_list = []crypto.SigFragment{partial_sig_1, partial_sig_2}
	// Aggregate partial signature
	sig, err = ctx_gossiper_1.Config.Crypto.ThresholdAggregate(partial_sig_list)
	if err != nil{
		fmt.Println("Error in threshold aggregate STH_Logger1 and STH_Logger2")
	}
	sigstring, err= sig.String()
	if err != nil{
		fmt.Println("Error in converting signature to string")
	}
	// Create Signer map
	signermap = make(map[int]string)
	signermap[0] = ctx_gossiper_1.Config.Crypto.SelfID.String()
	signermap[1] = ctx_gossiper_3.Config.Crypto.SelfID.String()
	STH_FULL_Logger2 = gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.STH_FULL,
		Period:      "0",
		Signer:      "",
		Signers:     signermap,
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{sigstring},
		Crypto_Scheme: "BLS",
		Payload:     STH_Logger2.Payload,
	}

	// Create a jsonfile for STHs
	STHs := []gossip.Gossip_object{STH_FULL_Logger1}
	STHs_json, err := json.MarshalIndent(STHs, "", "  ")
	if err != nil{
		fmt.Println("Error in marshaling STHs")
	}
	err = ioutil.WriteFile("STH_TSS.json", STHs_json, 0644)
	if err != nil{
		fmt.Println("Error in writing STHs to json file")
	}
	fmt.Println("-------------------------------STH FULL Test Passed-------------------------------")
}
func TestREVFULL(t *testing.T){
	// Revoke cert 3 from CA 1
	ctx_ca_1.CRV.Revoke(3)
	// Revoke cert 3 from CA 2
	ctx_ca_2.CRV.Revoke(3)
	//Generate REV from CA 1
	rev_ca1 := CA.Generate_Revocation(ctx_ca_1, "0")
	bitset_DCRV_CA1 := new(bitset.BitSet)
	bitset_DCRV_CA1.UnmarshalJSON([]byte(ctx_ca_1.CRV.GetDeltaCRV()))
	fmt.Println("CRV for CA 1", bitset_DCRV_CA1)
	REV_CA1 = rev_ca1
	// Generate REV from CA 2
	rev_ca2 := CA.Generate_Revocation(ctx_ca_2, "0")
	bitset_DCRV_CA2 := new(bitset.BitSet)
	bitset_DCRV_CA2.UnmarshalJSON([]byte(ctx_ca_2.CRV.GetDeltaCRV()))
	fmt.Println("CRV for CA 2", bitset_DCRV_CA2)
	REV_CA2 = rev_ca2
	// revoke cert 4 from CA 2
	ctx_ca_2.CRV.Revoke(4)
	bitset_DCRV_CA2_alt := new(bitset.BitSet)
	bitset_DCRV_CA2_alt.UnmarshalJSON([]byte(ctx_ca_2.CRV.GetDeltaCRV()))
	fmt.Println("CRV_alt for CA 2", bitset_DCRV_CA2_alt)
	// Generate REV from CA 2
	REV_CA2_alt = CA.Generate_Revocation(ctx_ca_2, "0")
	// Get the Gossiper 1's signature on the payload of ca1's revocation
	partial_sig_1, err := ctx_gossiper_1.Config.Crypto.ThresholdSign(rev_ca1.Payload[0]+rev_ca1.Payload[1]+rev_ca1.Payload[2])
	if err != nil{
		fmt.Println("Error in threshold sign REV_Logger1")
	}
	// Get the Gossiper 2's signature on the payload of ca1's revocation
	partial_sig_2, err := ctx_gossiper_2.Config.Crypto.ThresholdSign(rev_ca1.Payload[0]+rev_ca1.Payload[1]+rev_ca1.Payload[2])
	if err != nil{
		fmt.Println("Error in threshold sign REV_Logger2")
	}
	// Get the Gossiper 1's signature on the payload of ca2's revocation
	partial_sig_3, err := ctx_gossiper_1.Config.Crypto.ThresholdSign(rev_ca2.Payload[0]+rev_ca2.Payload[1]+rev_ca2.Payload[2])
	if err != nil{
		fmt.Println("Error in threshold sign REV_Logger1")
	}
	// Get the Gossiper 2's signature on the payload of ca2's revocation
	partial_sig_4, err := ctx_gossiper_2.Config.Crypto.ThresholdSign(rev_ca2.Payload[0]+rev_ca2.Payload[1]+rev_ca2.Payload[2])
	if err != nil{
		fmt.Println("Error in threshold sign REV_Logger2")
	}
	// Create a list of partial signature for ca1's revocation
	partial_sig_list := []crypto.SigFragment{partial_sig_1, partial_sig_2}
	// Create a list of partial signature for ca2's revocation
	partial_sig_list2 := []crypto.SigFragment{partial_sig_3, partial_sig_4}
	// Aggregate partial signature for ca1's revocation
	sig, err := ctx_gossiper_1.Config.Crypto.ThresholdAggregate(partial_sig_list)
	if err != nil{
		fmt.Println("Error in threshold aggregate REV_Logger1 and REV_Logger2")
	}
	// Aggregate partial signature for ca2's revocation
	sig2, err := ctx_gossiper_1.Config.Crypto.ThresholdAggregate(partial_sig_list2)
	if err != nil{
		fmt.Println("Error in threshold aggregate REV_Logger1 and REV_Logger2")
	}
	sigstring, err:= sig.String()
	if err != nil{
		fmt.Println("Error in converting signature to string")
	}
	sigstring2, err:= sig2.String()
	if err != nil{
		fmt.Println("Error in converting signature to string")
	}
	// Create Signer map for ca1's revocation
	signermap := make(map[int]string)
	signermap[0] = ctx_gossiper_1.Config.Crypto.SelfID.String()
	signermap[1] = ctx_gossiper_2.Config.Crypto.SelfID.String()
	// Create Signer map for ca2's revocation
	signermap2 := make(map[int]string)
	signermap2[0] = ctx_gossiper_1.Config.Crypto.SelfID.String()
	signermap2[1] = ctx_gossiper_2.Config.Crypto.SelfID.String()
	// Create REV_FULL object for ca1's revocation
	REV_FULL_CA1= gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.REV_FULL,
		Period:      "0",
		Signer:      "",
		Signers:     signermap,
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{sigstring},
		Crypto_Scheme: "BLS",
		Payload:     [3]string{rev_ca1.Payload[0], rev_ca1.Payload[1], rev_ca1.Payload[2]},
	}
	// Create REV_FULL object for ca2's revocation
	REV_FULL_CA2 = gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.REV_FULL,
		Period:      "0",
		Signer:      "",
		Signers:     signermap2,
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{sigstring2},
		Crypto_Scheme: "BLS",
		Payload:     [3]string{rev_ca2.Payload[0], rev_ca2.Payload[1], rev_ca2.Payload[2]},
	}
	REV_FULL_list := []gossip.Gossip_object{REV_FULL_CA1}
	REV_FULL_json, err := json.MarshalIndent(REV_FULL_list, "", "  ")
	if err != nil{
		fmt.Println("Error in marshaling REV_FULLs")
	}
	err = ioutil.WriteFile("REV_TSS.json", REV_FULL_json, 0644)
	if err != nil{
		fmt.Println("Error in writing REV_FULLs to file")
	}
}
	 
func TestCONFULL(t *testing.T){
	// Create the payload for CON, should be the signer of the STH || STH || STH_alt
	payload := [3]string{STH_Logger2.Signer, STH_Logger2.Payload[0]+STH_Logger2.Payload[1]+ STH_Logger2.Payload[2], STH_Logger2_alt.Payload[0]+STH_Logger2_alt.Payload[1]+ STH_Logger2_alt.Payload[2]}
	//Gossiper 1 Threshold sign the payload
	partial_sig_1, err := ctx_gossiper_1.Config.Crypto.ThresholdSign(payload[0]+payload[1]+payload[2])
	if err != nil{
		fmt.Println("Error in threshold sign CONF_Logger1")
	}
	//Gossiper 2 Threshold sign CON_logger2
	partial_sig_2, err := ctx_gossiper_2.Config.Crypto.ThresholdSign(payload[0]+payload[1]+payload[2])
	if err != nil{
		fmt.Println("Error in threshold sign CONF_Logger2")
	}
	// Create a list of partial signature
	partial_sig_list := []crypto.SigFragment{partial_sig_1, partial_sig_2}
	// Aggregate partial signature
	sig, err := ctx_gossiper_1.Config.Crypto.ThresholdAggregate(partial_sig_list)
	if err != nil{
		fmt.Println("Error in threshold aggregate CONF_Logger1 and CONF_Logger2")
	}
	sigstring, err:= sig.String()
	if err != nil{
		fmt.Println("Error in converting signature to string")
	}
	// Create Signer map
	signermap := make(map[int]string)
	signermap[0] = ctx_gossiper_1.Config.Crypto.SelfID.String()
	signermap[1] = ctx_gossiper_2.Config.Crypto.SelfID.String()
	CON_FULL_Logger2 := gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.CON_FULL,
		Period:      "0",
		Signer:      "",
		Signers:     signermap,
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{sigstring},
		Crypto_Scheme: "BLS",
		Payload:     payload,
	}
	// Create the payload for CON, should be the signer of the REV || REV || REV_alt, from CA 2
	payload2 := [3]string{REV_CA2.Signer, REV_CA2.Payload[0]+REV_CA2.Payload[1]+ REV_CA2.Payload[2], REV_CA2_alt.Payload[0]+REV_CA2_alt.Payload[1]+ REV_CA2_alt.Payload[2]}
	//Gossiper 1 Threshold sign the payload
	partial_sig_1, err = ctx_gossiper_1.Config.Crypto.ThresholdSign(payload2[0]+payload2[1]+payload2[2])
	if err != nil{
		fmt.Println("Error in threshold sign CONF_Logger1")
	}
	//Gossiper 2 Threshold sign CON_logger2
	partial_sig_2, err = ctx_gossiper_2.Config.Crypto.ThresholdSign(payload2[0]+payload2[1]+payload2[2])
	if err != nil{
		fmt.Println("Error in threshold sign CONF_Logger2")
	}
	// Create a list of partial signature
	partial_sig_list = []crypto.SigFragment{partial_sig_1, partial_sig_2}
	// Aggregate partial signature
	sig, err = ctx_gossiper_1.Config.Crypto.ThresholdAggregate(partial_sig_list)
	if err != nil{
		fmt.Println("Error in threshold aggregate CONF_Logger1 and CONF_Logger2")
	}
	sigstring2, err:= sig.String()
	if err != nil{
		fmt.Println("Error in converting signature to string")
	}
	// Create Signer map
	signermap = make(map[int]string)
	signermap[0] = ctx_gossiper_1.Config.Crypto.SelfID.String()
	signermap[1] = ctx_gossiper_2.Config.Crypto.SelfID.String()
	CON_FULL_CA2 := gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.CON_FULL,
		Period:      "0",
		Signer:      "",
		Signers:     signermap,
		Timestamp:   gossip.GetCurrentTimestamp(),
		Signature:   [2]string{sigstring2},
		Crypto_Scheme: "BLS",
		Payload:     payload2,
	}
	POMs := []gossip.Gossip_object{CON_FULL_Logger2, CON_FULL_CA2}
	POMs_json, err := json.MarshalIndent(POMs, "", "  ")
	if err != nil{
		fmt.Println("Error in marshaling POMs")
	}
	err = ioutil.WriteFile("POM_TSS.json", POMs_json, 0644)
	if err != nil{
		fmt.Println("Error in writing POMs to json file")
	}
	fmt.Println("-------------------------------CONF FULL Test Passed-------------------------------")
}

