package client

import (
	"CTng/monitor"
	"CTng/util"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/bits-and-blooms/bitset"
)

func TestGet_SRH_and_DCRV(t *testing.T) {
	//read from client_test/ClientData/Period 0/FromMonitor/ClientUpdate_at_Period 0.json"3"
	client_json, err := util.ReadByte("../client_test/ClientData/Period 0/FromMonitor/ClientUpdate_at_Period 0.json")
	if err != nil {
		t.Error(err)
	}
	var clientUpdate monitor.ClientUpdate
	err = json.Unmarshal(client_json, &clientUpdate)
	if err != nil {
		t.Error(err)
	}
	var SRHs []string
	var DCRVs []bitset.BitSet
	for _, rev := range clientUpdate.REVs {
		newSRH, newDCRV := Get_SRH_and_DCRV(rev)
		SRHs = append(SRHs, newSRH)
		DCRVs = append(DCRVs, newDCRV)
	}
	fmt.Println(SRHs)
	fmt.Println(DCRVs)

}

/*
package main

import (
	"encoding/json"
	"fmt"
)

type CRV struct {
	CAID    string
	Payload [2]string
}
type SRH struct {
	RootHash string
	TreeSize int
	Period   string
}
type Revocation struct {
	Day       int
	Delta_CRV string
	SRH       SRH
}

func main() {
	REV := Revocation{
		Day:       1,
		Delta_CRV: "test_delta_CRV",
		SRH: SRH{
			RootHash: "randomhash",
			TreeSize: 5,
			Period:   "0",
		},
	}
	payload1, _ := json.Marshal(REV)
	payload := string(payload1)
	testCRV := CRV{
		CAID:    "1",
		Payload: [2]string{"", payload},
	}
	fmt.Println(testCRV)
	var REV1 Revocation
	json.Unmarshal([]byte(testCRV.Payload[1]), &REV1)
	fmt.Println(REV1.SRH.RootHash)
	var a bitarray.BitArray
	var b bitarray.BitArray
	a = bitarray.NewBitArray(60)
	b = bitarray.NewBitArray(30)
	a.SetBit(1)
	a.SetBit(10)
	a.SetBit(30)
	b.SetBit(20)
	a = a.Or(b)
	fmt.Println(a.Blocks)
	var x []byte
	x = make([]byte, 60, 60)
	for _, i := range a.ToNums() {
		x[i] = 1
	}
	fmt.Println(x)
}
*/
/*
func QueryMonitors(c *ClientContext){
	// Convert gossip object to JSON
	msg, _ := json.Marshal(c.LastUpdatePeriod)
	// Send the gossip object to all connected gossipers.
	for _, url := range  c.Config.Monitor_URLs {
		//fmt.Println("Attempting to sending data to", url)
		// HTTP POST the data to the url or IP address.
		resp, err := c.Client.Post("http://"+url+"/monitor/get-updates/", "application/json", bytes.NewBuffer(msg))
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") ||
				strings.Contains(err.Error(), "connection refused") {
				fmt.Println(util.RED+"Connection failed to "+url+".", util.RESET)
			} else {
				fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
			}
			continue
		}
		defer resp.Body.Close()
	}
}
*/

/*
func QueryMonitors(c *ClientContext){
	for _, m := range c.Config.Monitor_URLs{
		fmt.Println(util.GREEN + "Querying Monitors Initiated" + util.RESET)
		sthResp, err := http.GET(PROTOCOL + m + "/monitor/get-updates/")
		if err != nil {
			log.Println(util.RED+"Query Monitor Failed, connection refused.",util.RESET)
			continue
		}
		UpBody, err := ioutil.ReadAll(sthResp.Body)
		var update monitor.Clientupdate
		err = json.Unmarshal(UpBody, &UpBody)
		if err != nil {
			log.Println(util.RED+err.Error(), util.RESET)
		}else{
			Process_valid_update(c,update)
		}

	}
}*/
