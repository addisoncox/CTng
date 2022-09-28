package monitor

import (
	"CTngv1/gossip"
	"CTngv1/util"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"github.com/gorilla/mux"
)

// Binds the context to the functions we pass to the router.
func bindMonitorContext(context *MonitorContext, fn func(context *MonitorContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleMonitorRequests(c *MonitorContext) {

	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)

	// POST functions
	gorillaRouter.HandleFunc("/monitor/recieve-gossip", bindMonitorContext(c, handle_gossip)).Methods("POST")
	gorillaRouter.HandleFunc("/monitor/recieve-gossip-from-gossiper", bindMonitorContext(c, handle_gossip_from_gossiper)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.Config.Port, nil))
}

func receiveGossip(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	// Post request, parse sent object.
	body, err := ioutil.ReadAll(r.Body)

	// If there is an error, post the error and terminate.
	if err != nil {
		panic(err)
	}

	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj gossip.Gossip_object
	err = json.NewDecoder(r.Body).Decode(&gossip_obj)
	// Prints the body of the post request to the server console
	log.Println(string(body))

	// Use a mapped empty interface to store the JSON object.
	var postData map[string]interface{}
	// Decode the JSON object stored in the body
	err = json.Unmarshal(body, &postData)

	// If there is an error, post the error and terminate.
	if err != nil {
		panic(err)
	}

	// TODO - Validate, parse, and store postData
}

func handle_gossip_from_gossiper(c *MonitorContext, w http.ResponseWriter, r *http.Request){
	var gossip_obj gossip.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	fmt.Println("Recieved new, valid", gossip_obj.Type, "from "+util.GetSenderURL(r)+".")
	Process_valid_object(c, gossip_obj)
}
func handle_gossip(c *MonitorContext, w http.ResponseWriter, r *http.Request) {
	// Parse sent object.
	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj gossip.Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	// Verify the object is valid.
	err = gossip_obj.Verify(c.Config.Crypto)
	if err != nil {
		fmt.Println("Recieved invalid object from " + util.GetSenderURL(r) + ".")
		AccuseEntity(c, gossip_obj.Signer)
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	// Check for duplicate object.
	if c.IsDuplicate(gossip_obj){
		// If the object is already stored, still return OK.{
		fmt.Println("Duplicate:", gossip_obj.Type, util.GetSenderURL(r)+".")
		http.Error(w, "Gossip object already stored.", http.StatusOK)
		// processDuplicateObject(c, gossip_obj, stored_obj)
		return
	} else {
		fmt.Println("Recieved new, valid", gossip_obj.Type, "from "+util.GetSenderURL(r)+".")
		Process_valid_object(c, gossip_obj)
		c.SaveStorage()
	}
	http.Error(w, "Gossip object Processed.", http.StatusOK)
}

func InitializeMonitorStorage(c *MonitorContext){
	c.StorageDirectory = "testData/monitordata/"+c.StorageID+"/"
	c.StorageFile_CONFLICT_POM  = "CONFLICT_POM.json"
	c.StorageFile_ACCUSATION_POM = "ACCUSATION_POM.json"
	c.StorageFile_STH_FULL = "STH_FULL.json"
	c.StorageFile_REV_FULL = "REV_FULL.json" 
	util.CreateFile(c.StorageDirectory+c.StorageFile_CONFLICT_POM)
	util.CreateFile(c.StorageDirectory+c.StorageFile_ACCUSATION_POM)
	util.CreateFile(c.StorageDirectory+c.StorageFile_STH_FULL)
	util.CreateFile(c.StorageDirectory+c.StorageFile_REV_FULL)
}

func StartMonitorServer(c *MonitorContext) {
	// Check if the storage file exists in this directory
	InitializeMonitorStorage(c)
	err := c.LoadStorage()
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			// Storage File doesn't exit. Create new, empty json file.
			err = c.SaveStorage()
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// Run a go routine to handle tasks that must occur every MMD
	go PeriodicTasks(c)
	// Start HTTP server loop on the main thread
	handleMonitorRequests(c)
}
