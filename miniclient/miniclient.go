package miniclient

import (
	"fmt"
)

func Start() {
	QueryMonitor()
	fmt.Println()
	QueryServer()
}

func QueryMonitor() {
	res, err := FetchClientUpdate("http://localhost:3000/?period=0")
	if err != nil {
		fmt.Printf("client update err: %v\n", err)
		return
	}

	fmt.Printf("monitor id: %v\n", res.MonitorID)
	fmt.Printf("period: %v\n", res.Period)
	fmt.Printf("\nsth: %v\n", res.STHs)
	fmt.Printf("\nrev: %v\n", res.REVs)
	fmt.Printf("\npom: %v\n", res.PoMs)

	fmt.Printf("\nsth delta crv: %v\n", GetDeltaCRV(res.STHs))
	fmt.Printf("\nsth srh value: %v\n", GetSRH(res.STHs))
	fmt.Printf("\nrev root hash: %v\n", GetRootHash(res.REVs))
}

// Deprecated: These endpoints have been removed from the monitor
func QueryMonitorOldEndpoints() {
	// monitorURL := "http://localhost:3000"
	// backupMonitorURL := "http://localhost:3001"

	res, err := FetchGossip("http://localhost:3000/sth")
	sthNumPeriods := len(res)
	if err != nil {
		fmt.Printf("sth err: %v\n", err)
	} else {
		fmt.Printf("sth: %v\n", res)
	}

	res, err = FetchGossip("http://localhost:3000/rev")
	revNumPeriods := len(res)
	if err != nil {
		fmt.Printf("rev err: %v\n", err)
	} else {
		fmt.Printf("rev: %v\n", res)
		fmt.Printf("rev delta crv: %s\n", GetDeltaCRV(res))
		fmt.Printf("rev num periods: %d\n", revNumPeriods)
	}

	res, err = FetchGossip("http://localhost:3000/pom")
	pomNumPeriods := len(res)
	if err != nil {
		fmt.Printf("pom err: %v\n", err)
	} else {
		fmt.Printf("pom: %v\n", res)
		fmt.Printf("pom num periods: %v\n", pomNumPeriods)
	}

	// TODO: Query another monitor?
	if (sthNumPeriods == revNumPeriods) && (sthNumPeriods == pomNumPeriods) {
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
