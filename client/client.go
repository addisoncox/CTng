package client

import (
	"CTng/CA"
	"CTng/Logger"
	"CTng/util"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"

	//"io/ioutil"
	"CTng/crypto"
	"CTng/gossip"
	"CTng/monitor"
	"encoding/json"
	"errors"
	"time"

	"github.com/gorilla/mux"
)

type ProofOfInclusion struct {
	SiblingHashes [][]byte
	NeighborHash  []byte
}

type CTngExtension struct {
	STH gossip.Gossip_object `json:"STH"`
	POI ProofOfInclusion     `json:"POI"`
	RID int                  `json:"RID"`
}

const PROTOCOL = "http://"

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
	/*
		// Convert gossip object to JSON
		Newquery := monitor.Clientquery{
			Client_URL: c.Config.Client_URL,
			LastUpdatePeriod: c.LastUpdatePeriod,
		}
		msg, _ := json.Marshal(Newquery)
		// HTTP POST the data to the url or IP address.
		resp, err := c.Client.Post("http://"+c.Config.Default_update_monitor+"/monitor/get-updates", "application/json", bytes.NewBuffer(msg))
		fmt.Println(util.GREEN+"Query sent to the monitor: ",  c.Config.Default_update_monitor,"at",gossip.GetCurrentPeriod(),util.RESET)
		if err != nil {
			for _, url := range  c.Config.Monitor_URLs {
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
				}else{
					break
				}
			}
		}else{
			//fmt.Println(util.GREEN+"Query sent to the monitor: ",  c.Config.Default_update_monitor,"at",gossip.GetCurrentPeriod(),util.RESET)
			defer resp.Body.Close()
		}
	*/
}

func Handleupdates(c *ClientContext, w http.ResponseWriter, r *http.Request) {
	var update monitor.ClientUpdate
	err := json.NewDecoder(r.Body).Decode(&update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		fmt.Println("Json decoding failed")
		return
	}
	fmt.Println(util.GREEN + update.Period + util.RESET)
	fmt.Println(util.GREEN+"update received at ", update.Period, util.RESET)
	HandleSTHs(c, &update.STHs)
	HandleREVs(c, &update.REVs)
	HandleACCs(c, &update.ACCs)
	HandleCONs(c, &update.CONs)
	err = update.NUM.Verify(c.Config.Crypto)
	if err != nil {
		//handle this
	}
	err = update.NUM_FULL.Verify(c.Config.Crypto)
	if err != nil {
		//
	}
	// check NUM_FULL against prev num
	if update.NUM_FULL.NUM_ACC_FULL != c.Storage_NUM.NUM_ACC_FULL ||
		update.NUM.NUM_CON_FULL != c.Storage_NUM.NUM_CON_FULL {
		fmt.Println("Got NUM_FULL != prev NUM")
		return
	}
	c.Storage_NUM = &update.NUM
	c.Storage_NUM_FULL = &update.NUM_FULL
	//update the last update Period
	c.LastUpdatePeriod = update.Period
	//Push the received Signed PoMs to the checking monitor for integrity check
	//var pom_signed SignedPoMs = GetSignedPoMs(c, update)
	//PushtoMonitor(c, pom_signed)
}

func HandleSTHs(c *ClientContext, STHs *[]gossip.Gossip_object) {
	for _, gossipObject := range *STHs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_STH_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandleREVs(c *ClientContext, REVs *[]gossip.Gossip_object) {
	for _, gossipObject := range *REVs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_REV_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandleACCs(c *ClientContext, ACCs *[]gossip.Gossip_object) {
	for _, gossipObject := range *ACCs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_ACCUSATION_POM)[gossipObject.GetID()] = gossipObject
		}
	}
}

func HandleCONs(c *ClientContext, CONs *[]gossip.Gossip_object) {
	for _, gossipObject := range *CONs {
		err := gossipObject.Verify(c.Config.Crypto)
		if err == nil {
			(*c.Storage_CONFLICT_POM)[gossipObject.GetID()] = gossipObject
		}
	}
}

func Parse_CTng_extension(cert *x509.Certificate) *CTngExtension {
	ctng_ext_M := []byte(cert.CRLDistributionPoints[0])
	ctng_UM := new(CTngExtension)
	json.Unmarshal(ctng_ext_M, &ctng_UM)
	return ctng_UM
}

func verifySignatures(
	c *ClientContext,
	cert x509.Certificate,
	conflictPoms *gossip.Gossip_Storage,
	accusationPoms *gossip.Gossip_Storage,
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
	for _, pom := range *conflictPoms {
		err := pom.Verify(c.Config.Crypto)
		if err != nil {
			return err
		}
	}
	for _, pom := range *accusationPoms {
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

func verifyPOI(sth Logger.STH, poi ProofOfInclusion, cert x509.Certificate) bool {
	return Logger.VerifyPOI(sth, CA.ProofOfInclusion(poi), cert)
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

// will finish these 2 after the client is working as intended
func Handlesubjects(c *ClientContext, w http.ResponseWriter, r *http.Request) {
	var cert x509.Certificate
	err := json.NewDecoder(r.Body).Decode(&cert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = checkCertAgainstPOMList(cert, c.Storage_CONFLICT_POM)
	if err != nil {
		//handle rejection
	}
	err = verifySignatures(c, cert, c.Storage_CONFLICT_POM, c.Storage_ACCUSATION_POM, c.Storage_STH_FULL, c.Storage_REV_FULL)
	if err != nil {
		//handleRejection
	}
	ctngExtension := Parse_CTng_extension(&cert)
	var loggerSTH Logger.STH
	//payload[1] holds marshalled logger STH
	json.Unmarshal([]byte(ctngExtension.STH.Payload[1]), &loggerSTH)
	if !verifyPOI(loggerSTH, ctngExtension.POI, cert) {
		//handle POI verification failed
	}
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
