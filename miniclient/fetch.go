package miniclient

import (
	"CTng/gossip"
	"CTng/monitor"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type MonitorData = []gossip.Gossip_object

func Fetch(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return resBody, err
	}

	if res.StatusCode != http.StatusOK {
		return resBody, fmt.Errorf("server returned status code %v: %v", res.StatusCode, string(resBody))
	}

	return resBody, nil
}

func FetchClientUpdate(url string) (monitor.ClientUpdate, error) {
	res, err := Fetch(url)
	if err != nil {
		return monitor.ClientUpdate{}, err
	}

	var data monitor.ClientUpdate
	err = json.Unmarshal(res, &data)
	return data, err
}

func FetchCertificate(url string) (x509.Certificate, error) {
	// Disable TLS certificate verificiation
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Get(url)
	if err != nil {
		return x509.Certificate{}, err
	}

	// if res.TLS != nil {
	// 	certificates := res.TLS.PeerCertificates
	// 	if len(certificates) > 0 && certificates[0] != nil {
	// 		return *certificates[0], nil
	// 	}
	// }

	// return x509.Certificate{}, nil

	if res.TLS == nil {
		return x509.Certificate{}, nil
	}

	certificates := res.TLS.PeerCertificates
	if len(certificates) == 0 && certificates[0] != nil {
		return x509.Certificate{}, fmt.Errorf("no certificate")
	}

	return *certificates[0], nil
}

func FetchGossipObject(url string) (MonitorData, error) {
	res, err := Fetch(url)
	if err != nil {
		return MonitorData{}, err
	}

	var data MonitorData
	err = json.Unmarshal(res, &data)
	return data, err
}
