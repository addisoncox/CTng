package CA

import (
	//crypto "CTng/crypto"
	"fmt"
	//"reflect"
	"CTng/gossip"
    "CTng/util"
	"CTng/config"
	"CTng/crypto"
	"encoding/json"
	"net/http"
	"testing"
	"github.com/Workiva/go-datastructures/bitarray"
	"github.com/google/certificate-transparency-go/tls"
)

func TestAddCertificateTest(t *testing.T){
	conf, err := config.LoadCAConfig("ca_testconfigs/ca_pub_config.json","ca_testconfigs/ca_priv_config.json","ca_testconfigs/caCrypto.json")
	if err != nil {
		panic(err)
	}
	SRHs := make([]gossip.Gossip_object, 0, 20)
	var revoc Revocator = &CRV{
		Vector:   bitarray.NewBitArray(1),
		DeltaVec: bitarray.NewBitArray(1),
		CASign: tls.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.RSA,
			},
			Signature: []byte("0"),
		},
		LoggerSign: tls.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.RSA,
			},
			Signature: []byte("0"),
		},
		Length: conf.Public.Length,
	}
	revocators := []*Revocator{&revoc}
	certs := NewCertPool()

	ctx := CAContext{
		Config:         &conf,
		SRHs:           SRHs,
		Revocators:     revocators,
		Request_Count:  0,
		Current_Period: 0,
		Certificates:   certs,
	}
	issuerCert, err := GenerateSelfSigned(&ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	ctx.IssuerCertificate = *issuerCert

	//fmt.Println("started ca server")
	//StartCAServer(&ctx)
	tr := &http.Transport{}
	ctx.Client = &http.Client{
		Transport: tr,
	}
	fmt.Println(gossip.EntityString(ctx.Config.Signer))
	//fmt.Println(Certificates.GetSizeOfCertPool())
	cert, _, err := GeneratePrecert("google.com", false, &ctx)
	if err != nil {
		fmt.Println((err))
	}
	fmt.Println(cert.UnhandledCriticalExtensions)
	fmt.Println(cert.Subject.CommonName)
	//fmt.Println(cert.NotBefore)
	//fmt.Println(cert.NotAfter)
	var p *util.Place = util.FindRevokePlace(cert)
	println("vector: ", p.Vector, "Index: ",p.Index)
	msg, err := json.Marshal(cert)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(msg))
	hashmsg := string(msg)
	hash, _ := crypto.GenerateSHA256([]byte(hashmsg))
	fmt.Println("Hash is ",string(hash))
	// Send the gossip object to the gossiper.
	//resp, postErr := c.Client.Post(PROTOCOL+c.Config.Gossiper_URL+"/gossip/gossip-data", "application/json", bytes.NewBuffer(msg))
	fmt.Println("current size of the certpool is: ", ctx.Certificates.GetSizeOfCertPool())
	for _,logger :=  range(ctx.Config.Logger_URLs){
		println(logger)
	}
	SendCert(&ctx,cert)
	cert, _, err = GeneratePrecert("ynet.co.il", false, &ctx)
	if err != nil {
		fmt.Println((err))
	}
	fmt.Println(cert.Subject.CommonName)
	p = util.FindRevokePlace(cert)
	println("vector: ", p.Vector, "Index: ",p.Index)
	fmt.Println("current size of the certpool is: ", ctx.Certificates.GetSizeOfCertPool())
}