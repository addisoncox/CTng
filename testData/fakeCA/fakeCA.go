package fakeCA

/*
Code Ownership:
Isaac - Responsible for all functions
Finn - Helped with review+implementation ideas
*/
import (
	//"CTngv1/GZip"
	"CTngv1/crypto"
	"CTngv1/gossip"
	"CTngv1/util"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"
	"encoding/hex"
	"github.com/gorilla/mux"
	"strconv"
)

var CA_SIZE int

type CAConfig struct {
	Signer              crypto.CTngID
	Port                string
	NRevoke             int
	MRD                 int
	Private             rsa.PrivateKey
	CRVs                [][]byte //should be array of CRVs
	Day                 int      //I use int so I don't have to round and convert timestamps but that would be ideal
	MisbehaviorInterval int
}

type Revocation struct {
	day       int
	delta_CRV []byte
	srh       SRH
}


type SRH struct {
	RootHash  string
	TreeSize  int
	Period string
}
//Caution: this file is plagued with Global Variables for conciseness.
var config CAConfig
var SRHS []gossip.Gossip_object
var fakeSRHs []gossip.Gossip_object
var request_count int
var currentPeriod int
var caType int

func generateRevocation(CA CAConfig,miss int, Period_num int) gossip.Gossip_object{
	// Generate a random-ish SRH, add to SRHS.
	hashmsg := "Root Hash" + fmt.Sprint(currentPeriod+request_count)
	hash, _ := crypto.GenerateSHA256([]byte(hashmsg))
	SRH1 := SRH{
		//Timestamp: gossip.GetCurrentTimestamp(),
		RootHash:  hex.EncodeToString(hash),
		TreeSize:  currentPeriod * 12571285,
		Period: gossip.GetCurrentPeriod(),
	}
	// Generate delta CRV and then compress it
	first_arr := CA.CRVs[CA.Day] //this assumes we never have CRV of len 0 (fresh CA)
	CA.Day += 1
	CA.CRVs[CA.Day] = make([]byte, CA_SIZE, CA_SIZE)

	var delta_crv = make([]byte, CA_SIZE, CA_SIZE)
	// Make the dCRV here by randomly flipping Config.NRevoke bits
	for i := 0; i < CA.NRevoke; i++ {
		change := rand.Intn(len(delta_crv))
		flip := byte(1)
		flip = flip << uint(rand.Intn(8))
		delta_crv[change] = flip
	}
	//fmt.Println(SRH1,delta_crv)
	// creates the new CRV from the old one+dCRV
	for i, _ := range first_arr {
		CA.CRVs[CA.Day][i] = first_arr[i] ^ delta_crv[i]
	} //this is scuffed/slow for giant CRVs O(n), also I am assuming CRVs are same size, can modify for different sizes
	REV := Revocation{
		day:       CA.Day,
		delta_CRV: delta_crv,
		srh: SRH1,
	}
	payload3, _ := json.Marshal(REV)
	payload := string(CA.Signer)+"CRV"+string(payload3)
	signature, _ := crypto.RSASign([]byte(payload), &config.Private, config.Signer)
	gossipREV := gossip.Gossip_object{
		Application: "CTng",
		Type:        gossip.REV,
		Period:      strconv.Itoa(Period_num),
		Signer:      string(config.Signer),
		Signature:   [2]string{signature.String(), ""},
		Crypto_Scheme: "RSA",
		Payload:     [3]string{string(CA.Signer),"CRV",string(payload3)},
	}
	return gossipREV
}

func periodicTasks() {
	// Queue the next tasks to occur at next MRD.
	time.AfterFunc(time.Duration(config.MRD)*time.Second, periodicTasks)
	// Generate CRV and SRH
	fmt.Println("CA Running Tasks at Period", gossip.GetCurrentPeriod())
	/*
	Rev1 := generateRevocation(config, caType-request_count)
	request_count++
	fakeRev1 := generateRevocation(config, caType-request_count) //Should be incorrect SRH
	SRHS = append(SRHS, Rev1)
	fakeSRHs = append(fakeSRHs, fakeRev1)
	*/
	currentPeriod++
}


//Hard code to simulate a CA server that will generate subdomain to communicate
func requestSRH(w http.ResponseWriter, r *http.Request) {
	SRH_index,err := strconv.Atoi(gossip.GetCurrentPeriod())
	if err == nil{}
	json.NewEncoder(w).Encode(SRHS[SRH_index])
}

func fill_with_data(){
	SRHS = SRHS[:0]
	fakeSRHs = fakeSRHs[:0]
	for i:=0; i<60; i++{
		srh1 := generateRevocation(config, caType, i)
		fakeSRH1 := generateRevocation(config, caType, i)
		SRHS = append(SRHS, srh1)
	    fakeSRHs = append(fakeSRHs, fakeSRH1)
	}
}
/*
func requestSRH(w http.ResponseWriter, r *http.Request) {
	//Disconnecting CA:
	request_count++
	if caType == 3 && currentPeriod%config.MisbehaviorInterval == 0 {
		// No response or any bad request response should trigger the accusation
		return
	}
	// Split-World CA
	if caType == 2 && request_count%2 == 0 && currentPeriod%config.MisbehaviorInterval == 0 {
		json.NewEncoder(w).Encode(fakeSRHs[currentPeriod-1])
		return
	}
	json.NewEncoder(w).Encode(SRHs[currentPeriod-1])
}*/

/*
func getCAType() {
	fmt.Println("What type of CA would you like to use?")
	fmt.Println("1. Normal, behaving CA (default)")
	fmt.Println("2. Split-World (Two different SRHs on every", config.MisbehaviorInterval, "MRD)")
	fmt.Println("3. Disconnecting CA (unresponsive every", config.MisbehaviorInterval, "MRD)")
	fmt.Println("4. Invalid SRH on every ", config.MisbehaviorInterval, "MRD) (CURRENTLY UNIMPLEMENTED)")
	fmt.Scanln(&caType)
}*/

// Runs a fake CA server with the ability to act roguely.
func RunFakeCA(configFile string) {
	// Global Variable initialization
	CA_SIZE = 1024
	caType = 1
	currentPeriod = 0
	request_count = 0
	SRHS = make([]gossip.Gossip_object, 0, 60)
	fakeSRHs = make([]gossip.Gossip_object, 0, 60)
	// Read the config file
	config = CAConfig{}
	configBytes, err := util.ReadByte(configFile)
	if err != nil {
		fmt.Println("Error reading config file: ", err)
		return
	}
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Println("Error reading config file: ", err)
	}

	config.CRVs = make([][]byte, 999, 999)
	config.CRVs[0] = make([]byte, CA_SIZE, CA_SIZE)
	config.Day = 0
	//getCAType()
	caType = 1
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	gorillaRouter.HandleFunc("/ctng/v2/get-revocation", requestSRH).Methods("GET")
	http.Handle("/", gorillaRouter)
	fmt.Println("Listening on port", config.Port)
	fill_with_data()
	go periodicTasks()
	http.ListenAndServe(":"+config.Port, nil)
}
