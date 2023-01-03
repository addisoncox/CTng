package CA



import (
	//"CTng/gossip"
	//"CTng/crypto"
	//"CTng/util"
	//"bytes"
	"encoding/json"
	"fmt"
	//"io/ioutil"
	"crypto/x509"
	"log"
	"net/http"
	"time"
	//"strings"
	"strconv"
	"bytes"
	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"

//bind CA context to the function
func bindCAContext(context *CAContext, fn func(context *CAContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleCARequests(c *CAContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions

	// receive certificate from logger
	gorillaRouter.HandleFunc("/CA/receive-certificate", bindCAContext(c, receive_certificate)).Methods("POST")
	// receive a list of certificates from logger
	gorillaRouter.HandleFunc("/CA/receive-certificate-list", bindCAContext(c, receive_certificate_list)).Methods("POST")
	
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.Config.Port, nil))
}


// receive certificate from logger
func receive_certificate(c *CAContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into a certificate
	var cert x509.Certificate
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&cert)
	if err != nil {
		panic(err)
	}
	// use sign certificate to sign the certificate
	signedcert := Sign_certificate(&cert, c.Rootcert, false, &c.Config.Public, &c.Config.Private)
	// add to certificate pool
	c.CurrentCertificatePool.AddCertificate(*signedcert, c)
}

// receive a list of certificates from logger
func receive_certificate_list(c *CAContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into a list of certificates
	var certList []x509.Certificate
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&certList)
	if err != nil {
		panic(err)
	}
	// use sign certificate to sign the certificates
	for _, cert := range certList {
		signedcert := Sign_certificate(&cert, c.Rootcert, false, &c.Config.Public, &c.Config.Private)
		// add to certificate pool
		c.CurrentCertificatePool.AddCertificate(*signedcert,c)
	}
}
//send a signed precert to a logger
func Send_Signed_PreCert_To_Logger(c *CAContext,precert *x509.Certificate, logger string){
	precert_json := Marshall_Signed_PreCert_To_Json(precert)
	//fmt.Println(precert_json)
	//fmt.Println(logger)
	//fmt.Println(precert_json)
	resp, err := c.Client.Post(PROTOCOL+ logger+"/logger/receive-precert", "application/json", bytes.NewBuffer(precert_json))
	if err != nil {
		log.Fatalf("Failed to send precert to loggers: %v", err)
	}
	defer resp.Body.Close()
}


//Send a list of signed precerts to all loggers in the map
func Send_Signed_PreCerts_To_Loggers_Map(c *CAContext, precerts []*x509.Certificate, loggers_map map[string]string){
	for i:=0;i<len(loggers_map);i++{
		precerts_json, err := json.Marshal(precerts)
		if err != nil {
			log.Fatalf("Failed to marshall certificate: %v", err)
		}
		//fmt.Println(precerts_json)
		fmt.Println(fmt.Sprint(i))
		fmt.Println(loggers_map["Logger "+ fmt.Sprint(i+1)])
		resp, err := c.Client.Post(PROTOCOL+ loggers_map["Logger "+ fmt.Sprint(i+1)]+"/logger/receive-precerts", "application/json", bytes.NewBuffer(precerts_json))
		if err != nil {
			//just panic dont stop the program
			log.Println("Failed to send precerts to loggers: ", err)
			continue
		}
		defer resp.Body.Close()
	}
}


func GetCurrentPeriod() string{
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Miniutes, err := strconv.Atoi(timerfc[14:16])
	Periodnum := strconv.Itoa(Miniutes)
	if err != nil {
	}
	return Periodnum
}

func GerCurrentSecond() string{
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Second, err := strconv.Atoi(timerfc[17:19])
	Secondnum := strconv.Itoa(Second)
	if err != nil {
	}
	return Secondnum
}

func PeriodicTask(ctx *CAContext) {
	f := func() {
		PeriodicTask(ctx)
	}
	time.AfterFunc(time.Duration(ctx.Config.MMD)*time.Second, f)
	fmt.Println("CA Running Tasks at Period", GetCurrentPeriod())
	//Generate N signed pre-certificates
	issuer := Generate_Issuer(ctx.Config.Signer)
	// generate host
	host := "www.example.com"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate pre-certificates
	certs := Generate_N_Signed_PreCert(64, host, validFor, isCA, issuer, ctx.Rootcert, false, &ctx.Config.Public, &ctx.Config.Private)
	//Send the pre-certificates to the log
	Send_Signed_PreCerts_To_Loggers_Map(ctx, certs, ctx.Config.Loggers)
	fmt.Println("CA Finished Tasks at Period", GetCurrentPeriod())
}


// Our CA does not create certificate by requests
// The purpose of the CA is for testing purposes only
func StartCA(c *CAContext) {
	currentsecond := GerCurrentSecond()
	// convert string to int
	second, err := strconv.Atoi(currentsecond)
	if err != nil {
	}
	// if current second is not 0, wait till the next minute
	if second != 0 {
		fmt.Println("CA will start", 60-second, " seconds later.")
		//time.Sleep(time.Duration(60-second) * time.Second)
	}
	// Initialize CA context
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// print loggers map
	fmt.Println(c.Config.Loggers)
	// Start HTTP server loop on the main thread
	go PeriodicTask(c)
	handleCARequests(c)
}
