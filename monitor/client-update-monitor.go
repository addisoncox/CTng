package monitor

import (
	"CTng/gossip"
	//"CTng/crypto"
	"CTng/util"
	//"bytes"
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

//we use this function to prepare the client update object, the client update object contains all the information that the client needs to update its local storage
// filepath is where STHs, REVs and PoMs are stored, local file system stores these information by period
func PrepareClientupdate(c *MonitorContext, filepath_sth string, filepath_rev string, filepath_pom string) Clientupdate{
	//intialize some storages
	storage_conflict_pom := new(gossip.Gossip_Storage)
	*storage_conflict_pom = make(gossip.Gossip_Storage)
	storage_sth_full := new(gossip.Gossip_Storage)
	*storage_sth_full = make(gossip.Gossip_Storage)
	storage_rev_full := new(gossip.Gossip_Storage)
	*storage_rev_full = make(gossip.Gossip_Storage)
	//load all sths and store them in storage_sth_full
	bytes, err := util.ReadByte(filepath_sth)
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
	bytes, err = util.ReadByte(filepath_rev)
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
	bytes, err = util.ReadByte(filepath_pom)
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

func Getfilepath_sth(maindir string, period string) string{
	//get the file path
	filepath := maindir + period + "/STH_TSS.json"
	return filepath
}

func Getfilepath_rev(maindir string, period string) string{
	//get the file path
	filepath := maindir + period + "/REV_TSS.json"
	return filepath
}

func Getfilepath_pom(maindir string, period string) string{
	//get the file path
	filepath := maindir + period + "/PoM_TSS.json"
	return filepath
}

func Getallpath(c *MonitorContext, period string) (string, string, string){
	//get the file path
	filepath_sth := c.StorageFile_STH_FULL+ period + "/STH_TSS.json"
	filepath_rev := c.StorageFile_REV_FULL+ period + "/REV_TSS.json"
	filepath_pom := c.StorageFile_CONFLICT_POM+ period + "/PoM_TSS.json"
	return filepath_sth, filepath_rev, filepath_pom
}

func requestupdate(c *MonitorContext, w http.ResponseWriter, r *http.Request){
	var periodnum string
	err := json.NewDecoder(r.Body).Decode(&periodnum) 
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	//get the file path
	filepath_sth, filepath_rev, filepath_pom := Getallpath(c, periodnum)
	var ctupdate = PrepareClientupdate(c, filepath_sth, filepath_rev, filepath_pom)
	fmt.Println(ctupdate.Period)
	msg, _ := json.Marshal(ctupdate)
	json.NewEncoder(w).Encode(msg)
	fmt.Println("Update request Processed")
}
