package testserver

import (
	"testing"
	"time"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
	"crypto/x509/pkix"
	"crypto/x509"
	//"crypto"

)

/*
var (

	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	ed25519Key = flag.Bool("ed25519", false, "Generate an Ed25519 key")

)
*/


func Test_generate_cert(t *testing.T){
	serialNumber := 0;
	//Certifcate lasting time
	validFor := 365 * 24 * time.Hour
	//Used to generate root certificate
	//use the Serial number of the subject as the Revocation ID
	testserver := pkix.Name{
		Country:[]string{"US"},
		Organization:[]string{"CTng Deleveoper's Team"}, 
		OrganizationalUnit: []string{"001"},
		CommonName: "CA_Logger 1",
		SerialNumber: fmt.Sprint(serialNumber),
	}
	serialNumber++

	//Test subject (certificate subject)
	subject := pkix.Name{
		Country:[]string{"US"},
		Organization:[]string{"CTng Department of testing dunmmies"}, 
		OrganizationalUnit: []string{"001"},
		CommonName: "testdummy001",
		SerialNumber: fmt.Sprint(serialNumber),
	}
	serialNumber++
	//Privatekey and Public key for the CA
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("rsa keygen failed")
	}
	pub := publicKey(priv)

	//fmt.Println(pub)
	//Generate_cert uses the private key of the CA
	//The Public key of the subject
	emptycert := new(x509.Certificate)
	cert := Generate_Cert("testserver", validFor, true, priv, pub,testserver, testserver, true, emptycert)
	fmt.Println("RootCert Generated")
	fmt.Println("Subject Name: ", (*cert).Subject.CommonName)
	fmt.Println("Revocation ID: ", (*cert).Subject.SerialNumber)
	fmt.Println("Issuer Name: ", (*cert).Issuer.CommonName)
	fmt.Println("Subject DNS: ", (*cert).DNSNames)
	//PK1 := ((*cert).PublicKey).(*rsa.PublicKey)
	//fmt.Println(PK1.Equal(pub))
	fmt.Println("Extra Extension (should be empty for pre-cert): ", (*cert).ExtraExtensions)
	fmt.Println("----------------------------------------------------------------")
	


	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("rsa keygen failed")
	}
	pub1 := publicKey(priv1)
	//fmt.Println(pub1)
	cert1 := Generate_Cert("testsubject001", validFor, false, priv, pub1,testserver, subject, false, cert)
	fmt.Println("SubjectCert Generated")
	fmt.Println("Subject Name: ", (*cert1).Subject.CommonName)
	fmt.Println("Revocation ID: ", (*cert1).Subject.SerialNumber)
	fmt.Println("Issuer Name: ", (*cert1).Issuer.CommonName)
	fmt.Println("Subject DNS: ", (*cert1).DNSNames)
	//PK2 := ((*cert1).PublicKey).(*rsa.PublicKey)
	//fmt.Println(PK2.Equal(pub1))
	//fmt.Println(PK2.Equal(pub))
	fmt.Println("Extra Extension (should be empty for pre-cert): ", (*cert1).ExtraExtensions)
}