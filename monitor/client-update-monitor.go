package monitor

import (
	"CTng/gossip"
	//"CTng/crypto"
	"CTng/util"
	"bytes"
	"encoding/json"
	"fmt"
	//"io/ioutil"
	//"log"
	"net/http"
	//"time"
	//"strings"
	//"strconv"
	//"github.com/gorilla/mux"
)

type Clientupdate struct{
	STHs gossip.Gossip_Storage
	REVs gossip.Gossip_Storage
	PoMs gossip.Gossip_Storage
	MonitorID string
	//Period here means the update period, the client udpate object can contain more information than just the period 
	Period string
	PoMsig string
}

type Clientquery struct{
	Client_URL string
	LastUpdatePeriod string
}

//we use this function to prepare the client update object, the client update object contains all the information that the client needs to update its local storage
// filepath is where STHs, REVs and PoMs are stored, local file system stores these information by period
func PrepareClientupdate(c *MonitorContext, filepath string) Clientupdate{
	//intialize some storages
	storage_conflict_pom := new(gossip.Gossip_Storage)
	*storage_conflict_pom = make(gossip.Gossip_Storage)
	storage_sth_full := new(gossip.Gossip_Storage)
	*storage_sth_full = make(gossip.Gossip_Storage)
	storage_rev_full := new(gossip.Gossip_Storage)
	*storage_rev_full = make(gossip.Gossip_Storage)
	//load all sths and store them in storage_sth_full
	bytes, err := util.ReadByte(filepath + "/STH_TSS.json")
	if err != nil {
		panic(err)
	}
	// Create an array of Gossip_object
	var sths []gossip.Gossip_object
	err = json.Unmarshal(bytes, &sths)
	if err != nil {
		panic(err)
	}
	for _, sth := range sths {
		// compute gossip ID
		gossipID := sth.GetID()
		// store gossip object
		(*storage_sth_full)[gossipID] = sth
	}
	//load all revs and store them in storage_rev_full
	bytes, err = util.ReadByte(filepath + "/REV_TSS.json")
	if err != nil {
		panic(err)
	}
	var revs []gossip.Gossip_object
	err = json.Unmarshal(bytes, &revs)
	if err != nil {
		panic(err)
	}
	for _, rev := range revs {
		// compute gossip ID
		gossipID := rev.GetID();
		// store gossip object
		(*storage_rev_full)[gossipID] = rev
	}
	//load all poms and sign on it
	bytes, err = util.ReadByte(filepath + "/POM_TSS.json")
	if err != nil {
		panic(err)
	}
	var poms []gossip.Gossip_object
	err = json.Unmarshal(bytes, &poms)
	if err != nil {
		panic(err)
	}
	for _, pom := range poms {
		// compute gossip ID
		gossipID := pom.GetID()
		// store gossip object
		(*storage_conflict_pom)[gossipID] = pom
	}
	//prepare the client update object
	CTupdate := Clientupdate{
		STHs: *storage_sth_full,
		REVs: *storage_rev_full,
		PoMs: *storage_conflict_pom,
		MonitorID: c.Config.Signer,
		Period: gossip.GetCurrentPeriod(),
	}
	return CTupdate
}


func requestupdate(c *MonitorContext, w http.ResponseWriter, r *http.Request){
	var ticket Clientquery
	fmt.Println(util.GREEN+"Client ticket received"+util.RESET)
	err := json.NewDecoder(r.Body).Decode(&ticket)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	var ctupdate = PrepareClientupdate(c,ticket.LastUpdatePeriod)
	fmt.Println(ctupdate.Period)
	msg, _ := json.Marshal(ctupdate)
	resp, postErr := c.Client.Post("http://"+ticket.Client_URL+"/receive-updates", "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println("Error sending update to client: " + postErr.Error())
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		if c.Verbose {
			fmt.Println("Client responded with " + resp.Status)
		}
		fmt.Println(util.GREEN+"Client update Sent"+util.RESET)
	}
}
