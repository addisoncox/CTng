
package testserver

import (
	//"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
)




func Genrate_PreCert(host string, validFor time.Duration, isCA bool, issuer pkix.Name, subject pkix.Name, c *TestServerContext) *x509.Certificate{
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
//host: DNS+IP
//validfor: duration of the certificate
//isCA: whether the this certificate is for a CA
//priv: private key of the signer
//pub: public key of the signer
//Issuer: detailed info about the issuing CA
//subject: detailed info about the subject 
//root: whether you are trying to generate a root certificate
//root_cert: if you are not trying to generate a root certificate, you need to provide a root certificate
func Generate_Cert(host string, validFor time.Duration, isCA bool,priv *rsa.PrivateKey, pub any,issuer pkix.Name, subject pkix.Name, root bool,root_cert *x509.Certificate) *x509.Certificate{
	// KeyUsage bits set in the x509.Certificate template
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
	if root{
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
		if err != nil {
			log.Fatalf("Failed to create certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(derBytes)
		cert.Issuer = issuer
		return cert
	}else{
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, root_cert, pub, priv)
		if err != nil {
			log.Fatalf("Failed to create certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(derBytes)
		return cert
	}

}