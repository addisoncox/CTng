package CA



import (
	"CTng/gossip"
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

	// Comments: RID should be received right after the precert is sent to the logger
	// STH and POI should be received at the end of each period
	// receive STH from logger
	gorillaRouter.HandleFunc("/CA/receive-sth", bindCAContext(c, receive_sth)).Methods("POST")
	// receive POI from logger
	gorillaRouter.HandleFunc("/CA/receive-poi", bindCAContext(c, receive_poi)).Methods("POST")
	
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.CA_private_config.Port, nil))
}

// receive STH from logger
func receive_sth(c *CAContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into a STH
	// STH should be in the form of gossip.STH
	var sth gossip.Gossip_object
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&sth)
	if err != nil {
		panic(err)
	}
	// Verify the STH
	err = sth.Verify(c.CA_crypto_config)
	if err != nil {
		panic(err)
	}
	// Update all STHs in the certificate pool by logger ID
	// search by STH.LoggerID
	(*c.CurrentCertificatePool).UpdateCertsByLID(sth.Signer, sth)
}

// receive POI from logger
func receive_poi(c *CAContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into [][]byte
	var poi [][]byte
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&poi)
	if err != nil {
		panic(err)
	}
	// Verify the POI
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

// send a signed precert to all loggers
func Send_Signed_PreCert_To_Loggers(c *CAContext, precert *x509.Certificate, loggers []string){
	for i:=0;i<len(loggers);i++{
		precert_json := Marshall_Signed_PreCert_To_Json(precert)
		//fmt.Println(precert_json)
		//fmt.Println(loggers[i])
		resp, err := c.Client.Post(PROTOCOL+ loggers[i]+"/logger/receive-precert", "application/json", bytes.NewBuffer(precert_json))
		if err != nil {
			log.Fatalf("Failed to send precert to loggers: %v", err)
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
	time.AfterFunc(time.Duration(ctx.CA_public_config.MMD)*time.Second, f)
	fmt.Println("CA Running Tasks at Period", GetCurrentPeriod())
	//Generate N signed pre-certificates
	issuer := Generate_Issuer(ctx.CA_private_config.Signer)
	// generate host
	host := "www.example.com"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate pre-certificates
	certs := Generate_N_Signed_PreCert(ctx,64, host, validFor, isCA, issuer, ctx.Rootcert, false,&ctx.PrivateKey, 0)
	//Send the pre-certificates to the log
	// iterate over certs
	for i:=0;i<len(certs);i++{
		Send_Signed_PreCert_To_Loggers(ctx, certs[i], ctx.CA_private_config.Loggerlist)
	}
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
	// Start HTTP server loop on the main thread
	go PeriodicTask(c)
	handleCARequests(c)
}
