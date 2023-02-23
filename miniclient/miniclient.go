package miniclient

import (
	"CTng/gossip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// TODO: Clean up code
type MonitorData = []gossip.Gossip_object

func Start() {
	// monitorURL := "http://localhost:3000"
	// backupMonitorURL := "http://localhost:3001"

	QueryMonitor()
	QueryServer()
}

func QueryMonitor() {
	res, err := FetchGossipObject("http://localhost:3000/sth")
	sthNumPeriods := len(res)
	if err != nil {
		fmt.Printf("sth err: %v\n", err)
	} else {
		fmt.Printf("sth: %v\n", res)
		fmt.Printf("sth field: %v\n", GetRootHash(res))
		fmt.Printf("sth num periods: %d\n", sthNumPeriods)
	}

	res, err = FetchGossipObject("http://localhost:3000/rev")
	revNumPeriods := len(res)
	if err != nil {
		fmt.Printf("rev err: %v\n", err)
	} else {
		fmt.Printf("rev: %v\n", res)
		fmt.Printf("rev delta crv: %s\n", GetDeltaCRV(res))
		fmt.Printf("rev num periods: %d\n", revNumPeriods)
	}

	res, err = FetchGossipObject("http://localhost:3000/pom")
	pomNumPeriods := len(res)
	if err != nil {
		fmt.Printf("pom err: %v\n", err)
	} else {
		fmt.Printf("pom: %v\n", res)
		fmt.Printf("pom num periods: %v\n", pomNumPeriods)
	}

	if (sthNumPeriods == revNumPeriods) && (sthNumPeriods == pomNumPeriods) {
		// TODO: Query another monitor
	}
}

func QueryServer() {
	cert, err := FetchCertificate("https://localhost:8000")
	if err != nil {
		fmt.Printf("normal cert err: %v\n", err)
	} else {
		fmt.Printf("normal cert: %v\n", cert.Subject)
	}

	cert, err = FetchCertificate("https://localhost:8001")
	if err != nil {
		fmt.Printf("revoked cert err: %v\n", err)
	} else {
		fmt.Printf("revoked cert: %v\n", cert.Subject)
	}

	cert, err = FetchCertificate("https://localhost:8002")
	if err != nil {
		fmt.Printf("pom cert err: %v\n", err)
	} else {
		fmt.Printf("pom cert: %v\n", cert.Subject)
	}
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

func GetDeltaCRV(data MonitorData) []string {
	// Parse payload[2] as Revocation
	var out []string
	for _, rev := range data {
		var payload map[string]any
		err := json.Unmarshal([]byte(rev.Payload[2]), &payload)
		if err != nil {
			fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		// TODO: Parse as REV instead of string
		out = append(out, payload["Delta_CRV"].(string))
	}
	return out
}

func GetRootHash(data MonitorData) []string {
	var out []string
	for _, sth := range data {
		var payload map[string]any
		err := json.Unmarshal([]byte(sth.Payload[1]), &payload)
		if err != nil {
			fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		out = append(out, payload["RootHash"].(string))
	}
	return out
}

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
		return resBody, fmt.Errorf("server returned status code %v", res.StatusCode)
	}

	return resBody, nil
}
