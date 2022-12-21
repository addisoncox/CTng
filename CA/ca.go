package CA

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
	"encoding/json"
	"fmt"
	"bytes"
)
// Unsigned Pre-certificate
func Genrate_Unsigned_PreCert(host string, validFor time.Duration, isCA bool, issuer pkix.Name, subject pkix.Name) *x509.Certificate{
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	keyUsage |= x509.KeyUsageKeyEncipherment
	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.Add(validFor)
	//serialNumber need to be random per X.509 requirement
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: subject,
		Issuer: issuer,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	return &template
}


// Signed certificate with Root certificate
func Sign_certificate(cert *x509.Certificate, root_cert *x509.Certificate,root bool, pub *rsa.PublicKey, priv *rsa.PrivateKey) *x509.Certificate{
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, root_cert, pub, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	//fmt.Println(derBytes)
	cert, err = x509.ParseCertificate(derBytes)
	return cert
}

//Generate Root certificate self signed
func Generate_Root_Certificate(caConfig *CAConfig) *x509.Certificate{
	host := caConfig.Signer
	validFor := 365 * 24 * time.Hour
	isCA := true
	issuer := Generate_Issuer(caConfig.Signer)
	subject := Generate_Issuer(caConfig.Signer)
	root_cert_unsigned := Genrate_Unsigned_PreCert(host, validFor, isCA, issuer, subject)
	root_cert_signed := Generate_Signed_PreCert(host, validFor, isCA, issuer, subject, root_cert_unsigned, true, &caConfig.Public, &caConfig.Private)
	return root_cert_signed
}

// Parse CTng extension from certificate
func Parse_CTng_extension(cert *x509.Certificate) *CTngExtension{
	ctng_ext_M := []byte(cert.CRLDistributionPoints[0])
	ctng_UM := new(CTngExtension)
	json.Unmarshal(ctng_ext_M, &ctng_UM)
	return ctng_UM
}

// generate signed precert
func Generate_Signed_PreCert(host string, validFor time.Duration, isCA bool, issuer pkix.Name, subject pkix.Name, root_cert *x509.Certificate, root bool, pub *rsa.PublicKey, priv *rsa.PrivateKey) *x509.Certificate{
	precert := Genrate_Unsigned_PreCert(host, validFor, isCA, issuer, subject)
	signed_precert := Sign_certificate(precert, root_cert, root, pub, priv)
	return signed_precert
}

//generate N subject, with different common name
func Generate_N_Subjects(N int) []pkix.Name{
	subjects := make([]pkix.Name,N)
	for i:=0;i<N;i++{
		subjects[i].CommonName = "Testing Dummy "+fmt.Sprint(i)
	}
	return subjects
}

//generate 1 issuer given N
func Generate_Issuer(name string) pkix.Name{
	issuer := pkix.Name{}
	issuer.CommonName = name
	return issuer
}

//generate N signed precert, with different subject
func Generate_N_Signed_PreCert(N int, host string, validFor time.Duration, isCA bool, issuer pkix.Name, root_cert *x509.Certificate, root bool, pub *rsa.PublicKey, priv *rsa.PrivateKey) []*x509.Certificate{
	precerts := make([]*x509.Certificate,N)
	subjects := Generate_N_Subjects(N)
	for i:=0;i<N;i++{
		precerts[i] = Generate_Signed_PreCert(host, validFor, isCA, issuer, subjects[i], root_cert, root, pub, priv)
	}
	return precerts
}

// Marshall signed precert to json
func Marshall_Signed_PreCert_To_Json(precert *x509.Certificate) []byte{
	precert_json, err := json.Marshal(precert)
	if err != nil {
		log.Fatalf("Failed to marshall certificate: %v", err)
	}
	return precert_json
}

// Unmarshall signed precert from json
func Unmarshall_Signed_PreCert_From_Json(precert []byte) *x509.Certificate{
	cert, err := x509.ParseCertificate(precert)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	return cert
}

//Send a signed precert to all loggers in the list
func Send_Signed_PreCert_To_Loggers(c *CAContext,precert *x509.Certificate, loggers []string){
	for i:=0;i<len(loggers);i++{
		precert_json := Marshall_Signed_PreCert_To_Json(precert)
		//fmt.Println(precert_json)
		//fmt.Println(loggers[i])
		//fmt.Println(precert_json)
		resp, err := c.Client.Post(PROTOCOL+ loggers[i]+"/logger/receive-precert", "application/json", bytes.NewBuffer(precert_json))
		if err != nil {
			log.Fatalf("Failed to send precert to loggers: %v", err)
		}
		defer resp.Body.Close()
		//fmt.Println(resp.Status)
	}
}

//Send a x509.Certificate map to all loggers in the map
func Send_Certificate_Map_To_Loggers_Map(c *CAContext, cert_map map[string]*x509.Certificate, loggers_map map[string]string){
	for i:=0;i<len(loggers_map);i++{
		cert_map_json, err := json.Marshal(cert_map)
		if err != nil {
			log.Fatalf("Failed to marshall certificate: %v", err)
		}
		//fmt.Println(cert_map_json)
		resp, err := c.Client.Post(PROTOCOL+ loggers_map[fmt.Sprint(i)]+"/logger/receive-cert-map", "application/json", bytes.NewBuffer(cert_map_json))
		if err != nil {
			log.Fatalf("Failed to send cert map to loggers: %v", err)
		}
		defer resp.Body.Close()
		//fmt.Println(resp.Status)
	}
}