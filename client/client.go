package client

import (
	"CTng/util"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"

	//"io/ioutil"
	"CTng/crypto"
	"CTng/gossip"
	"CTng/monitor"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"

type ProofOfInclusion struct {
	SiblingHashes [][]byte
	NeighborHash  []byte
}

type CTngExtension struct {
	STH gossip.Gossip_object `json:"STH"`
	POI ProofOfInclusion     `json:"POI"`
	RID int                  `json:"RID"`
}

func bindClientContext(context *ClientContext, fn func(context *ClientContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

// post method
// We ask the monitor to post the update by giving them the last update period
// the monitor will then send us all the missing updates
// it will go to next monitor if the default update monitor is at fault or is not responding
func QueryMonitors(c *ClientContext) {
	// Convert gossip object to JSON
	Newquery := monitor.Clientquery{
		Client_URL:       c.Config.Client_URL,
		LastUpdatePeriod: c.LastUpdatePeriod,
	}
	msg, _ := json.Marshal(Newquery)
	// HTTP POST the data to the url or IP address.
	resp, err := c.Client.Post("http://"+c.Config.Default_update_monitor+"/monitor/get-updates", "application/json", bytes.NewBuffer(msg))
	fmt.Println(util.GREEN+"Query sent to the monitor: ", c.Config.Default_update_monitor, "at", gossip.GetCurrentPeriod(), util.RESET)
	if err != nil {
		for _, url := range c.Config.Monitor_URLs {
			//fmt.Println("Attempting to sending data to", url)
			// HTTP POST the data to the url or IP address.
			_, err := c.Client.Post("http://"+url+"/monitor/get-updates", "application/json", bytes.NewBuffer(msg))
			if err != nil {
				if strings.Contains(err.Error(), "Client.Timeout") ||
					strings.Contains(err.Error(), "connection refused") {
					fmt.Println(util.RED+"Connection failed to "+url+".", util.RESET)
				} else {
					fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
				}
				continue
			} else {
				break
			}
		}
	} else {
		//fmt.Println(util.GREEN+"Query sent to the monitor: ",  c.Config.Default_update_monitor,"at",gossip.GetCurrentPeriod(),util.RESET)
		defer resp.Body.Close()
	}
}

func PushtoMonitor(c *ClientContext, sp SignedPoMs) {
	msg, _ := json.Marshal(sp)
	resp, err := c.Client.Post("http://"+c.Config.Default_check_monitor+"/monitor/checkforme", "application/json", bytes.NewBuffer(msg))
	if err != nil {
		if strings.Contains(err.Error(), "Client.Timeout") ||
			strings.Contains(err.Error(), "connection refused") {
			fmt.Println(util.RED+"Connection failed to "+c.Config.Default_check_monitor+".", util.RESET)
		} else {
			fmt.Println(util.RED+err.Error(), "sending to "+c.Config.Default_check_monitor+".", util.RESET)
		}
	}
	defer resp.Body.Close()
}

func GetSignedPoMs(c *ClientContext, mc monitor.Clientupdate) SignedPoMs {
	poms_signed := SignedPoMs{
		PoMs:   *mc.PoMs,
		Period: mc.Period,
		Sig:    mc.PoMsig,
	}
	return poms_signed
}
func Handleupdates(c *ClientContext, w http.ResponseWriter, r *http.Request) {
	var update monitor.Clientupdate
	err := json.NewDecoder(r.Body).Decode(&update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		fmt.Println("Json decoding failed")
		return
	}
	fmt.Println(util.GREEN + update.Period + util.RESET)
	fmt.Println(util.GREEN+"update received at ", update.Period, util.RESET)
	//HandleSTHs(c,update.STHs)
	//HandleREVs(c,update.REVs)
	//HandlePoMs(c,update.PoMs,update.PoMsig)
	//update the last update Period
	c.LastUpdatePeriod = update.Period
	//Push the received Signed PoMs to the checking monitor for integrity check
	//var pom_signed SignedPoMs = GetSignedPoMs(c, update)
	//PushtoMonitor(c, pom_signed)
}

func HandleSTHs(c *ClientContext, STHs *gossip.Gossip_Storage) {
	for _, gossipObject := range *STHs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_STH_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandleREVs(c *ClientContext, REVs *gossip.Gossip_Storage) {
	for _, gossipObject := range *REVs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_REV_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandlePoMs(c *ClientContext, poms *gossip.Gossip_Storage, sig string) {
	err := VerifyPoMs(c, poms, sig)
	if err != nil {
		for _, gossipObject := range *poms {
			(*c.Storage_CONFLICT_POM)[gossipObject.GetID()] = gossipObject
		}
	} else {
		fmt.Println(err)
	}
}

func VerifyPoMs(c *ClientContext, poms *gossip.Gossip_Storage, sig string) error {
	rsasig, err := crypto.RSASigFromString(sig)
	if err != nil {
		return errors.New("No_Sig_Match")
	}
	payload, _ := json.Marshal(*poms)
	var cryptoconf = *c.Config.Crypto
	result := cryptoconf.Verify([]byte(payload), rsasig)
	fmt.Println(result)
	return result
}

func handleClientRequests(c *ClientContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions
	gorillaRouter.HandleFunc("/receive-updates", bindClientContext(c, Handleupdates)).Methods("POST")
	gorillaRouter.HandleFunc("/receive-conviction", bindClientContext(c, Handleconviction)).Methods("POST")
	gorillaRouter.HandleFunc("/receive-cert", bindClientContext(c, Handlesubjects)).Methods("Get")
	// Start the HTTP server.
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.Config.Port, nil))
}

// Parse CTng extension from certificate
func Parse_CTng_extension(cert *x509.Certificate) *CTngExtension {
	ctng_ext_M := []byte(cert.CRLDistributionPoints[0])
	ctng_UM := new(CTngExtension)
	json.Unmarshal(ctng_ext_M, &ctng_UM)
	return ctng_UM
}

func verifySignatures(
	c *ClientContext,
	cert x509.Certificate,
	poms *gossip.Gossip_Storage,
	sths *gossip.Gossip_Storage,
	revs *gossip.Gossip_Storage,
) error {
	rsasig, err := crypto.RSASigFromString(string(cert.Signature))
	if err != nil {
		return errors.New("No_Sig_Match")
	}
	payload, _ := json.Marshal(cert)
	var cryptoconf = *c.Config.Crypto
	result := cryptoconf.Verify([]byte(payload), rsasig)
	if result != nil {
		return result
	}
	for _, pom := range *poms {
		err := pom.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	for _, sth := range *sths {
		err := sth.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	for _, rev := range *revs {
		err := rev.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkCertAgainstPOMList(cert x509.Certificate, poms *gossip.Gossip_Storage) error {
	if len(*poms) == 0 {
		return nil
	}
	for _, pom := range *poms {
		if cert.Issuer.String() == pom.Payload[0] {
			return errors.New("CA in POM list")
		}
		goodLogger := false
		certLoggers := Parse_CTng_extension(&cert).STH.Signers
		for _, logger := range certLoggers {
			if logger != pom.Payload[0] {
				goodLogger = true
				break
			}
		}
		if !goodLogger {
			return errors.New("No good logger for cert")
		}
	}
	return nil
}
func Handlesubjects(c *ClientContext, w http.ResponseWriter, r *http.Request) {
}

func Handleconviction(c *ClientContext, w http.ResponseWriter, r *http.Request) {
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
	fmt.Println("Client sleeping and waiting")
	//time_wait := gossip.Getwaitingtime()+10;
	//time.Sleep(time.Duration(time_wait)*time.Second);
	fmt.Println("Client Initiated")
	c.LastUpdatePeriod = "0"
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// Run a go routine to handle tasks that must occur every MMD
	go PeriodicTasks(c)
	// Start HTTP server loop on the main thread
	handleClientRequests(c)
}
