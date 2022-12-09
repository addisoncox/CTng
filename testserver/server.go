package testserver

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
	//"fmt"
)



// Unsigned Pre-certificate with Revocation ID, empty STH and POI
func Genrate_Unsigned_PreCert_CTng(host string, validFor time.Duration, isCA bool, issuer pkix.Name, subject pkix.Name, c *TestServerContext) *x509.Certificate{
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
	//adding extension now
	extension_rid := CTngExtension_init(c.CRVsize)
	newdata,_ := json.Marshal(extension_rid)
	datastring := string(newdata)
	dataslice := make([]string,1)
	dataslice = []string{datastring}
	template.CRLDistributionPoints = dataslice
	c.CRVsize++
	return &template
}

func Sign_certificate(cert *x509.Certificate, root_cert *x509.Certificate,root bool, pub any, priv *rsa.PrivateKey) *x509.Certificate{
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, root_cert, pub, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	//fmt.Println(derBytes)
	cert, err = x509.ParseCertificate(derBytes)
	return cert
}

func Parse_CTng_extension(cert *x509.Certificate) *CTngExtension{
	ctng_ext_M := []byte(cert.CRLDistributionPoints[0])
	ctng_UM := new(CTngExtension)
	json.Unmarshal(ctng_ext_M, &ctng_UM)
	return ctng_UM
}
