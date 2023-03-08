package monitor

import (
	"CTng/gossip"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
)

type ClientMock struct{}

func dummyGossipObject() gossip.Gossip_object {
	return gossip.Gossip_object{
		Application: "test", Period: "0", Type: "", Signer: "",
		Signers:       make(map[int]string),
		Signature:     [2]string{"", ""},
		Timestamp:     "",
		Crypto_Scheme: "",
		Payload:       [3]string{"", "", ""},
	}
}

func (c *ClientMock) GoodRequest(req *http.Request) (*http.Request, error) {
	mockedRes := dummyGossipObject()
	b, err := json.Marshal(mockedRes)
	if err != nil {
		log.Panic("Error reading a mockedRes from mocked client", err)
	}

	return &http.Request{Body: ioutil.NopCloser(bytes.NewBuffer(b))}, nil
}

func (c *ClientMock) BadRequest(req *http.Request) (*http.Request, error) {
	mockedResBad := "bad"
	b, err := json.Marshal(mockedResBad)
	if err != nil {
		log.Panic("Error reading a mockedRes from mocked client", err)
	}

	return &http.Request{Body: ioutil.NopCloser(bytes.NewBuffer(b))}, nil
}

func testReceiveGossip(t *testing.T) {
	monitorContext := MonitorContext{}
	req, _ := (&ClientMock{}).GoodRequest(&http.Request{})
	receiveGossip(&monitorContext, nil, req)
}

func testPanicOnBadReceiveGossip(t *testing.T) {
	monitorContext := MonitorContext{}
	// Catch Panic
	defer func() { _ = recover() }()

	req, _ := (&ClientMock{}).BadRequest(&http.Request{})
	receiveGossip(&monitorContext, nil, req)

	t.Errorf("Expected panic")
}

func TestPrepareClientupdate(t *testing.T) {
	// TODO
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	update, err := PrepareClientUpdate(ctx_monitor_1, "../client_test/ClientData/Period 0/FromMonitor/ClientUpdate_at_Period 0.json")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(update)
}

func testLoadStorage(t *testing.T) {
	// TODO
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	ctx_monitor_1.LoadOneStorage(gossip.CON_FULL, "../testserver/POM_TSS.json")
	ctx_monitor_1.LoadOneStorage(gossip.STH_FULL, "../testserver/REV_TSS.json")
	ctx_monitor_1.LoadOneStorage(gossip.REV_FULL, "../testserver/STH_TSS.json")
	fmt.Println(ctx_monitor_1.GetObjectNumber(gossip.CON_FULL))
	fmt.Println(ctx_monitor_1.GetObjectNumber(gossip.STH_FULL))
	fmt.Println(ctx_monitor_1.GetObjectNumber(gossip.REV_FULL))
}

func testSaveStorage(t *testing.T) {
	// TODO
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	ctx_monitor_1.LoadOneStorage(gossip.CON_FULL, "../testserver/POM_TSS.json")
	ctx_monitor_1.LoadOneStorage(gossip.STH_FULL, "../testserver/REV_TSS.json")
	ctx_monitor_1.LoadOneStorage(gossip.REV_FULL, "../testserver/STH_TSS.json")
	ctx_monitor_1.InitializeMonitorStorage("../testserver")
	fmt.Println(ctx_monitor_1.StorageDirectory)
	//ctx_monitor_1.SaveStorage("0")
}

func testMonitorServer(t *testing.T) {
	ctx_monitor_1 := InitializeMonitorContext("../Gen/monitor_testconfig/1/Monitor_public_config.json", "../Gen/monitor_testconfig/1/Monitor_private_config.json", "../Gen/monitor_testconfig/1/Monitor_crypto_config.json", "1")
	//over write ctx_monitor_1.Mode to 1 if you want to test the monitor server without waiting
	ctx_monitor_1.Mode = 1
	StartMonitorServer(ctx_monitor_1)
}
