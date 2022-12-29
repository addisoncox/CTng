package CA



import (
	//"CTng/gossip"
	//"CTng/crypto"
	//"CTng/util"
	//"bytes"
	"encoding/json"
	//"fmt"
	//"io/ioutil"
	"crypto/x509"
	"log"
	"net/http"
	"time"
	//"strings"
	"strconv"
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
	//Generate N signed pre-certificates
	// generate issuer
	issuer := Generate_Issuer("CA 1")
	// generate host
	host := "CA 1"
	// generate valid duration
	validFor := 365 * 24 * time.Hour
	isCA := false
	// generate pre-certificates
	certs := Generate_N_Signed_PreCert(64, host, validFor, isCA, issuer, ctx.Rootcert, false, &ctx.Config.Public, &ctx.Config.Private)
	//Add the pre-certificates to the pool
	for _, cert := range certs {
		ctx.CurrentCertificatePool.AddCertificate(*cert, ctx)
	}
	//Send the pre-certificates to the log
	Send_Signed_PreCerts_To_Loggers_Map(ctx, certs, ctx.Config.Loggers)
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
		time.Sleep(time.Duration(60-second) * time.Second)
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
