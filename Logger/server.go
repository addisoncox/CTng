package Logger



import (
	//"CTng/gossip"
	//"CTng/crypto"
	//"CTng/util"
	//"bytes"
	"encoding/json"
	"fmt"
	//"io/ioutil"
	"crypto/x509"
	"log"
	"net/http"
	"time"
	//"strings"
	"strconv"
	"github.com/gorilla/mux"
)

const PROTOCOL = "http://"



//bind Logger context to the function
func bindLoggerContext(context *LoggerContext, fn func(context *LoggerContext, w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(context, w, r)
	}
}

func handleLoggerRequests(c *LoggerContext) {
	// MUX which routes HTTP directories to functions.
	gorillaRouter := mux.NewRouter().StrictSlash(true)
	// POST functions
	
	// receive precerts from CA
	gorillaRouter.HandleFunc("/Logger/receive-precerts", bindLoggerContext(c, receive_pre_cert)).Methods("POST")
	//start the HTTP server
	http.Handle("/", gorillaRouter)
	// Listen on port set by config until server is stopped.
	log.Fatal(http.ListenAndServe(":"+c.Config.Port, nil))
}

// receive precert from CA
func receive_pre_cert(c *LoggerContext, w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request body into a precert
	var precert x509.Certificate
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&precert)
	if err != nil {
		panic(err)
	}
	// add to precert pool
	c.CurrentPrecertPool.AddPrecert(precert)
	fmt.Println("Received precert from CA")
}


func GetCurrentPeriod() string{
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Miniutes, err := strconv.Atoi(timerfc[14:16])
	Periodnum := strconv.Itoa(Miniutes)
	if err != nil {
	}
	return Periodnum
}

func GerCurrentSecond() string{
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Second, err := strconv.Atoi(timerfc[17:19])
	Secondnum := strconv.Itoa(Second)
	if err != nil {
	}
	return Secondnum
}

// Periodic task
func PeriodicTask(ctx *LoggerContext) {
	f := func() {
		PeriodicTask(ctx)
	}
	time.AfterFunc(time.Duration(ctx.Config.MMD)*time.Second, f)
	f1 := func() {
		fmt.Println(GerCurrentSecond())
		fmt.Println(time.Now().UTC().Format(time.RFC3339))
		fmt.Println("Logger Periodic Task", GetCurrentPeriod(), "has been online for", ctx.OnlinePeriod, "periods")
		ctx.OnlinePeriod = ctx.OnlinePeriod + 1
	}
	time.AfterFunc(time.Duration(ctx.Config.MMD-5)*time.Second, f1)
}


// Start the logger
func StartLogger(c *LoggerContext) {
	// set up HTTP client
	tr := &http.Transport{}
	c.Client = &http.Client{
		Transport: tr,
	}
	// start at second 0
	currentsecond := GerCurrentSecond()
	// if current second is not 0
	if currentsecond != "0" {
		// wait for 60 - current second
		second, err := strconv.Atoi(currentsecond)
		if err != nil {
		}
		second = 60 - second
		//print wait time
		fmt.Println("Logger will start after", second, "seconds")
		//time.Sleep(time.Duration(second) * time.Second)
	}
	// handle request and wait 55 seconds
	go PeriodicTask(c)
	handleLoggerRequests(c)
}