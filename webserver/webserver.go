package webserver

import (
	"crypto/tls"
	"log"
	"net/http"
)

// Run a HTTPS web server that returns a different type of CTng certificate depending on the port:
// 1. A normal, valid certificate on port 8000
// 2. A revoked certificate on port 8001
// 3. A certificate from an entity that has a proof of misbehavior (POM) against them on port 8002
func Start() {
	normalCert, revokedCert, pomCert := getCertificates()

	normalMux := http.NewServeMux()
	normalMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This website has a normal certificate."))
	})
	revokedMux := http.NewServeMux()
	revokedMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This website has a certificate that has been revoked."))
	})
	pomMux := http.NewServeMux()
	pomMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This website has a certificate from an entity that has a POM against them."))
	})

	normalServer := http.Server{
		Addr: "localhost:8000",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{normalCert},
		},
		Handler: normalMux,
	}
	revokedServer := http.Server{
		Addr: "localhost:8001",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{revokedCert},
		},
		Handler: revokedMux,
	}
	pomServer := http.Server{
		Addr: "localhost:8002",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pomCert},
		},
		Handler: pomMux,
	}

	log.Println("Listening on port 8000, 8001, and 8002")

	go func() {
		if err := normalServer.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := revokedServer.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()

	if err := pomServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

// Get the certificates to be used by the server
func getCertificates() (tls.Certificate, tls.Certificate, tls.Certificate) {
	normalCert, err := tls.LoadX509KeyPair("webserver/test/normal.crt", "webserver/test/normal.key")
	if err != nil {
		panic(err)
	}
	revokedCert, err := tls.LoadX509KeyPair("webserver/test/revoked.crt", "webserver/test/revoked.key")
	if err != nil {
		panic(err)
	}
	pomCert, err := tls.LoadX509KeyPair("webserver/test/pom.crt", "webserver/test/pom.key")
	if err != nil {
		panic(err)
	}
	return normalCert, revokedCert, pomCert
}
