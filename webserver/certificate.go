package webserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

type CertificateAuthority struct {
	RootCertificate       x509.Certificate
	RootCertificateSigned []byte
	PrivateKey            *rsa.PrivateKey
}

func CreateCA(companyName string) CertificateAuthority {
	// Create root certificate
	rootCert := x509.Certificate{
		SerialNumber: createSerialNumber(),
		Subject: pkix.Name{
			Organization: []string{companyName},
			CommonName:   companyName,
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Default validity of CA root cert is 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate private, public key using RSA 4096
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate CA private key: %v", err)
	}

	// Sign root cert using CA's private key
	rootCertBytes, err := x509.CreateCertificate(rand.Reader, &rootCert, &rootCert, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatalf("Failed to sign CA root certificate: %v", err)
	}

	return CertificateAuthority{
		RootCertificate:       rootCert,
		RootCertificateSigned: rootCertBytes,
		PrivateKey:            privKey,
	}
}

// Create a new cerificate and sign it with a subject's private key and the CA's root certificate
func (ca CertificateAuthority) CreateCertificate(subjectName string, pubKey *rsa.PublicKey) (x509.Certificate, []byte) {
	cert := x509.Certificate{
		SerialNumber: createSerialNumber(), // Some arbitrary serial number
		Subject: pkix.Name{
			Organization: []string{subjectName},
			CommonName:   subjectName,
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 1, 0), // Make a subject certificate valid for a month
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// TODO: Add CTng Extensions to the certificate

	// Sign certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &cert, &ca.RootCertificate, pubKey, ca.PrivateKey)
	if err != nil {
		log.Printf("Failed to sign certificate: %v\n", err)
		panic(err)
	}

	return cert, certBytes
}

func ReadCAFromDisk(rootCertPath string, privKeyPath string) CertificateAuthority {
	// Read the certificate file from disk
	certBytes, err := os.ReadFile(rootCertPath)
	if err != nil {
		panic(err)
	}

	// Parse the certificate data into a x509 certificate object
	block, _ := pem.Decode(certBytes)
	if block == nil {
		panic("failed to parse PEM block containing the certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	// Read the private key from disk
	keyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		panic(err)
	}

	// Parse the private key data into a RSA Private Key object
	block, _ = pem.Decode(keyData)
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return CertificateAuthority{
		RootCertificate:       *cert,
		RootCertificateSigned: certBytes,
		PrivateKey:            privKey.(*rsa.PrivateKey),
	}
}

// Generate a serial number for a certificate
func createSerialNumber() *big.Int {
	// Not really sure what Lsh() does... ¯\_(ツ)_/¯
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	return serialNumber
}
