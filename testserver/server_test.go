package testserver

import (
	"testing"
	"time"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
	"crypto/x509/pkix"
	//"crypto/x509"
	//"encoding/asn1"
	//"encoding/json"
	//"reflect"
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

func Test_precert_and_selfsign(t *testing.T){
	//Certifcate lasting time
	validFor := 365 * 24 * time.Hour
	//Used to generate root certificate
	testserver := pkix.Name{
		Country:[]string{"US"},
		Organization:[]string{"CTng Deleveoper's Team"}, 
		OrganizationalUnit: []string{"001"},
		CommonName: "CA_Logger 1",
	}
	ctx := TestServer_Context_init()
	cert := Genrate_Unsigned_PreCert_CTng("testserver", validFor, true,testserver, testserver,ctx)
	//We need to sign the precert and send to logger 
	cert_signed := Sign_certificate(cert,cert, true,&ctx.Config.Public, &ctx.Config.Private)
	//After we get the CTng extension from the logger, we need to sign it again
	cert_signagain := Sign_certificate(cert_signed,cert_signed, true,&ctx.Config.Public, &ctx.Config.Private)
	ctng_ext := Parse_CTng_extension(cert_signagain)
	fmt.Println("CTng extension: ", ctng_ext)
}

func Test_signing(t *testing.T){
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
	
	//generate the key pair for the test subject
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("rsa keygen failed")
	}
	pub := publicKey(priv)
	//read the key pair for CA from config
	ctx := TestServer_Context_init()
	root_cert := Genrate_Unsigned_PreCert_CTng("testserver", validFor, true,testserver, testserver,ctx)
	root_cert_signed := Sign_certificate(root_cert,root_cert, true,&ctx.Config.Public, &ctx.Config.Private)
	subject_cert := Genrate_Unsigned_PreCert_CTng("testsubject001", validFor, false, testserver, subject, ctx)
	sub_cert_signed := Sign_certificate(subject_cert,root_cert_signed, false,pub, &ctx.Config.Private)
	fmt.Println(root_cert_signed.Issuer.CommonName, root_cert_signed.Subject.CommonName, sub_cert_signed.Signature != nil)
	fmt.Println(sub_cert_signed.Issuer.CommonName, sub_cert_signed.Subject.CommonName, sub_cert_signed.Signature != nil)
}

/*
func Test_generate_temp(t *testing.T){
	Generate_config_template()
}*/