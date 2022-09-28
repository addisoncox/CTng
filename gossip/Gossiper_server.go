package gossip

import (
	"CTngv1/util"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"github.com/gorilla/mux"
	"time"
)

var GossiperServerType int
type Gossiper interface {

	// Response to entering the 'base page' of a gossiper.
	// TODO: Create informational landing page
	homePage()

	// HTTP POST request, receive a JSON object from another gossiper or connected monitor.
	// /gossip/push-data
	handleGossip(w http.ResponseWriter, r *http.Request)

	// Respond to HTTP GET request.
	// /gossip/get-data
	handleGossipObjectRequest(w http.ResponseWriter, r *http.Request)

	// Push JSON object to connected network from this gossiper via HTTP POST.
	// /gossip/gossip-data
	gossipData()

	// TODO: Push JSON object to connected 'owner' (monitor) from this gossiper via HTTP POST.
	// Sends to an owner's /monitor/recieve-gossip endpoint.
	sendToOwner()

	// Process JSON object received from HTTP POST requests.
	processData()

	// TODO: Erase stored data after one MMD.
	eraseData()

	// HTTP server function which handles GET and POST requests.
	handleRequests()
}

// Binds the context to the functions we pass to the router.
func bindContext(context *GossiperContext, fn func(context *GossiperContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleRequests(c *GossiperContext) {

	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)

	// homePage() is ran when base directory is accessed.
	gorillaRouter.HandleFunc("/gossip/", homePage)

	// Inter-gossiper endpoints
	gorillaRouter.HandleFunc("/gossip/push-data", bindContext(c, handleGossip)).Methods("POST")

	//gorillaRouter.HandleFunc("/gossip/get-data", bindContext(c, handleGossipObjectRequest)).Methods("GET")

	// Monitor interaction endpoint
	if GossiperServerType == 2{
		gorillaRouter.HandleFunc("/gossip/gossip-data", bindContext(c, handleOwnerGossip)).Methods("POST")}else{
		gorillaRouter.HandleFunc("/gossip/gossip-data", bindContext(c, handleGossip)).Methods("POST")
	}
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	fmt.Println(util.BLUE+"Listening on port:", c.Config.Port, util.RESET)
	err := http.ListenAndServe(":"+c.Config.Port, nil)
	// We wont get here unless there's an error.
	log.Fatal("ListenAndServe: ", err)
	os.Exit(1)
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the base page for the CTng gossiper.")
}
// handleGossip() is ran when POST is recieved at /gossip/push-data.
// It should verify the Gossip object and then send it to the network.
func handleGossip(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	// Parse sent object.
	// Converts JSON passed in the body of a POST to a Gossip_object.
	var gossip_obj Gossip_object
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Verify the object is valid, if invalid we just ignore it
	err = gossip_obj.Verify(c.Config.Crypto)
	if err != nil {
		//fmt.Println("Received invalid object "+TypeString(gossip_obj.Type)+" from " + util.GetSenderURL(r) + ".")
		fmt.Println(util.RED,"Received invalid object "+TypeString(gossip_obj.Type)+ " signed by " + gossip_obj.Signer + ".",util.RESET)
		http.Error(w, err.Error(), http.StatusOK)
		return
	}
	// Check for duplicate object.
	stored_obj, found := c.GetObject(gossip_obj.GetID())
	if found && stored_obj.Signature == gossip_obj.Signature{
		// If the object is already stored, still return OK.
		//fmt.Println("Duplicate:", gossip_obj.Type, util.GetSenderURL(r)+".")
		//fmt.Println("Duplicate: ", TypeString(gossip_obj.Type), " signed by ",gossip_obj.Signer+".")
		err := ProcessDuplicateObject(c, gossip_obj, stored_obj)
		if err != nil {
			http.Error(w, err.Error(), http.StatusOK)
			return
		}
		http.Error(w, "Received Duplicate Object."+ TypeString(gossip_obj.Type)+ " signed by " + gossip_obj.Signer+".", http.StatusOK)
		return
	} else {
		//fmt.Println(util.GREEN+"Received new, valid", TypeString(gossip_obj.Type), "from "+util.GetSenderURL(r)+".", util.RESET)
		fmt.Println(util.GREEN,"Received new, valid ",TypeString(gossip_obj.Type), "signed by ",gossip_obj.Signer, " at Period ",gossip_obj.Period,"from "+util.GetSenderURL(r), " .", util.RESET)
		ProcessValidObject(c, gossip_obj)
		c.SaveStorage()
	}
	http.Error(w, "Gossip object Processed.", http.StatusOK)
}

// Runs when /gossip/gossip-data is sent a POST request.
// Should verify gossip object and then send it to the network
// With the exception of not handling invalidObjects, this feels identical to gossipObject..
func handleOwnerGossip(c *GossiperContext, w http.ResponseWriter, r *http.Request) {
	var gossip_obj Gossip_object
	// Verify sender is an owner.
	if !util.IsOwner(c.Config.Owner_URL, util.GetSenderURL(r)) {
		http.Error(w, "Not an owner.", http.StatusForbidden)
		return
	}
	// Parses JSON from body of the request into gossip_obj
	err := json.NewDecoder(r.Body).Decode(&gossip_obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = gossip_obj.Verify(c.Config.Crypto)
	if err != nil {
		// Might not want to handle invalid object for our owner: Just warn them.
		// gossip.ProcessInvalidObject(gossip_obj, err)
		fmt.Println(util.RED+"Owner sent invalid object.", util.RESET)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stored_obj, found := c.GetObject(gossip_obj.GetID())
	if found && stored_obj.Type == gossip_obj.Type && stored_obj.Period == gossip_obj.Period{
		// If the object is already stored, still return OK.{
		fmt.Println("Recieved duplicate object from Owner.")
		err := ProcessDuplicateObject(c, gossip_obj, stored_obj)
		if err != nil {
			http.Error(w, "Duplicate Object recieved!", http.StatusOK)
		} else {
			// TODO: understand how duplicate POM works
			http.Error(w, "error", http.StatusOK)
		}
		return

	} else {
		// Prints the body of the post request to the server console
		fmt.Println(util.GREEN+"Recieved new, valid", gossip_obj.Type, "from owner.", util.RESET)
		ProcessValidObjectFromOwner(c, gossip_obj)
		c.SaveStorage()
	}
}

func getGossiperServerType() {
	fmt.Println("Which mode of Goissper server do you want to start?")
	fmt.Println("1. local host testing environment, Assume benigh monitor-gossiper connection")
	fmt.Println("2. NTTP mode")
	fmt.Scanln(&GossiperServerType)
}

func PeriodicTasks(c *GossiperContext) {
	// Immediately queue up the next task to run at next MMD.
	// Doing this first means: no matter how long the rest of the function takes,
	// the next call will always occur after the correct amount of time.
	f := func() {
		PeriodicTasks(c)
	}
	time.AfterFunc(time.Duration(c.Config.Public.MMD)*time.Second, f)
	for k := range *c.Storage{
		delete (*c.Storage,k)
	}
	err := c.ClearStorage()
	if err != nil{
		fmt.Println(util.RED+"Clear Storage error"+util.RESET)
		return
	}
}

func InitializeGossiperStorage (c* GossiperContext){
	c.StorageDirectory = "testData/gossiperdata/"+c.StorageID+"/"
	c.StorageFile = "GossipStorage.Json"
	util.CreateFile(c.StorageDirectory+c.StorageFile)

}

func StartGossiperServer(c *GossiperContext) {
	// Check if the storage file exists in this directory
	// Only need to store Degree2_PoM
	InitializeGossiperStorage(c)
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
	// Create the http client to be used.
	// This is thorough and allows for HTTP client configuration,
	// although we don't need it yet.
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	GossiperServerType = 2
	getGossiperServerType()
	// HTTP Server Loop
	//go PeriodicTasks(c)
	handleRequests(c)
}
