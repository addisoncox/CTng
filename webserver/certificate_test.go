package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"testing"
)

func saveCertificateToDisk(certBytes []byte, filePath string) {
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

func saveKeyToDisk(privKey *rsa.PrivateKey, filePath string) {
	keyOut, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", filePath, err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s: %v", filePath, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", filePath, err)
	}
}

func TestCreateCA(t *testing.T) {
	// Create a new certificate authority
	ca := CreateCA("CTng Certificate Authority")

	// Save CA root certificate to disk
	saveCertificateToDisk(ca.RootCertificateSigned, "test/ca.crt")
	log.Println("Wrote cert to disk")

	// Save CA private key to disk
	saveKeyToDisk(ca.PrivateKey, "test/ca.key")
	log.Println("Wrote priv key to disk")
}

func TestCreateCertificate(t *testing.T) {
	// Read CA root certificate from disk
	ca := ReadCAFromDisk("test/ca.crt", "test/ca.key")
	// ca := CreateCA("CTng Certificate Authority")

	// Create a private key for our certificate
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate cert private key: %v", err)
	}

	// Create a new certificate
	_, certBytes := ca.CreateCertificate("CTng Normal Certificate", &certPrivKey.PublicKey)

	// Save the certificate to disk
	saveCertificateToDisk(certBytes, "test/normal.crt")
	log.Println("Wrote cert to disk")

	// Save certificate's private key to disk
	saveKeyToDisk(certPrivKey, "test/normal.key")
	log.Println("Wrote priv key to disk")
}

func TestCreatePOMCertificate(t *testing.T) {
	// Create a new "malicious" CA
	ca := CreateCA("Evil Certificate Authority")

	// Create a private key for the certificate
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate cert private key: %v", err)
	}

	// Create a new certificate
	_, certBytes := ca.CreateCertificate("CTng POM Certificate", &certPrivKey.PublicKey)

	// Save the certificate to disk
	saveCertificateToDisk(certBytes, "test/pom.crt")
	log.Println("Wrote cert to disk")

	// Save certificate's private key to disk
	saveKeyToDisk(certPrivKey, "test/pom.key")
	log.Println("Wrote priv key to disk")
}

func TestCreateRevokedCertificate(t *testing.T) {
	// Read CA root certificate from disk
	ca := ReadCAFromDisk("test/ca.crt", "test/ca.key")

	// Create a private key for our certificate
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate cert private key: %v", err)
	}

	// Create a new certificate
	_, certBytes := ca.CreateCertificate("CTng Revoked Certificate", &certPrivKey.PublicKey)

	// Save the certificate to disk
	saveCertificateToDisk(certBytes, "test/revoked.crt")
	log.Println("Wrote cert to disk")

	// Save certificate's private key to disk
	saveKeyToDisk(certPrivKey, "test/revoked.key")
	log.Println("Wrote priv key to disk")
}
