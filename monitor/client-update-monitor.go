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

type ClientUpdate struct{
	STHs []gossip.Gossip_object
	REVs []gossip.Gossip_object
	ACCs []gossip.Gossip_object
	PoMs []gossip.Gossip_object
	MonitorID string
	//Period here means the update period, the client udpate object can contain more information than just the period 
	Period string
	// PoMsig string
}

//we use this function to prepare the client update object, the client update object contains all the information that the client needs to update its local storage
// filepath is where STHs, REVs and PoMs are stored, local file system stores these information by period
func PrepareClientUpdate(c *MonitorContext, filepath_sth string, filepath_rev string, filepath_pom string) (ClientUpdate, error) {
	//load all sths and store them in storage_sth_full
	bytes, err := util.ReadByte(filepath_sth)
	if err != nil {
		return ClientUpdate{}, err
	}
	// Create an array of Gossip_object
	var sths []gossip.Gossip_object
	err = json.Unmarshal(bytes, &sths)
	if err != nil {
		return ClientUpdate{}, err
	}

	//load all revs and store them in storage_rev_full
	bytes, err = util.ReadByte(filepath_rev)
	if err != nil {
		return ClientUpdate{}, err
	}
	var revs []gossip.Gossip_object
	err = json.Unmarshal(bytes, &revs)
	if err != nil {
		return ClientUpdate{}, err
	}

	//load all poms and sign on it
	bytes, err = util.ReadByte(filepath_pom)
	if err != nil {
		return ClientUpdate{}, err
	}
	var poms []gossip.Gossip_object
	err = json.Unmarshal(bytes, &poms)
	if err != nil {
		return ClientUpdate{}, err
	}

	//prepare the client update object
	CTupdate := ClientUpdate{
		STHs: sths,
		REVs: revs,
		PoMs: poms,
		MonitorID: c.Config.Signer,
		Period: gossip.GetCurrentPeriod(),
	}
	return CTupdate, nil
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
	ctupdate, _ := PrepareClientUpdate(c, filepath_sth, filepath_rev, filepath_pom)
	fmt.Println(ctupdate.Period)
	msg, _ := json.Marshal(ctupdate)
	json.NewEncoder(w).Encode(msg)
	fmt.Println("Update request Processed")
}
