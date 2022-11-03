package client
import (
	"fmt"
	"CTng/util"
	"log"
	"net/http"
	//"io/ioutil"
	"encoding/json"
	"CTng/monitor"
	"CTng/gossip"
	"CTng/crypto"
	"github.com/gorilla/mux"
	"bytes"
	"strings"
	"time"
	"errors"
)

const PROTOCOL = "http://"

func bindClientContext(context *ClientContext, fn func(context *ClientContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}
//post method
//We ask the monitor to post the update by giving them the last update period
//the monitor will then send us all the missing updates
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


func Handleupdates(c *ClientContext, w http.ResponseWriter, r *http.Request){

	var update monitor.Clientupdate
	err := json.NewDecoder(r.Body).Decode(&update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	HandlePoMs(c,update.PoMs,update.PoMsig)
	//HandleSTHs(c,update.STHs)
	//HandleREVs(c,update.REVs)
}

func HandlePoMs(c *ClientContext, poms *gossip.Gossip_Storage, sig string)error{
	rsasig, err := crypto.RSASigFromString(sig)
	if err != nil {
		return errors.New("No_Sig_Match")
	}
	payload, _:= json.Marshal(*poms)
	var cryptoconf = *c.Config.Crypto 
	result := cryptoconf.Verify([]byte(payload), rsasig)
	if result != nil{
		fmt.Println(result)
		return result
	}
}

func handleClientRequests(c *ClientContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions
	gorillaRouter.HandleFunc("/receive-updates", bindClientContext(c, Handleupdates)).Methods("POST")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.Config.Port, nil))
}


func PeriodicTasks(c *ClientContext) {
	// Immediately queue up the next task to run at next MMD.
	// Doing this first means: no matter how long the rest of the function takes,
	// the next call will always occur after the correct amount of time.
	f := func() {
		PeriodicTasks(c)
	}
	time.AfterFunc(time.Duration(c.Config.MMD)*time.Second, f)
	// Run the periodic tasks.
	QueryMonitors(c)
	//wait for some time (after all the monitor-gossip system converges)
	//time.Sleep(10*time.Second);
}

func StartClientServer(c *ClientContext) {
	//Warning: the time wait here is hard coded to be 10 seconds after the beginning of each period
	//will need to be adjusted according to the network delay
	time_wait := gossip.Getwaitingtime()+10;
	time.Sleep(time.Duration(time_wait)*time.Second);
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// Run a go routine to handle tasks that must occur every MMD
	go PeriodicTasks(c)
	// Start HTTP server loop on the main thread
	handleClientRequests(c)
}


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