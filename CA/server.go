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
	//"time"
	//"strings"
	//"strconv"
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

func StartCA(c *CAContext) {
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// Start HTTP server loop on the main thread
	handleCARequests(c)
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
	c.CurrentCertificatePool.AddCertificate(*signedcert)
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
		c.CurrentCertificatePool.AddCertificate(*signedcert)
	}
}