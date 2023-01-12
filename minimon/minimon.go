package minimon

import (
	"CTng/gossip"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

// Implements a minimal monitor server. Includes endpoints to retrieve STHs, REVs, and POMs.
func Start() {
	http.HandleFunc("/sth", func(w http.ResponseWriter, r *http.Request) {
		handleFileRequest(w, r, "testData/monitordata/1/STH_FULL.json")
	})
	http.HandleFunc("/rev", func(w http.ResponseWriter, r *http.Request) {
		handleFileRequest(w, r, "testData/monitordata/1/REV_FULL.json")
	})
	http.HandleFunc("/pom", func(w http.ResponseWriter, r *http.Request) {
		handleFileRequest(w, r, "testData/monitordata/1/ACCUSATION_POM.json")
	})
	fmt.Println("Monitor listening on port 3000...")
	if err := http.ListenAndServe("localhost:3000", nil); err != nil {
		log.Fatal(err)
	}
}

func handleFileRequest(w http.ResponseWriter, r *http.Request, fileName string) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Replace file location with config object
	content, err := os.ReadFile(fileName)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Parse file as array of gossip objects
	var sths []gossip.Gossip_object
	if err = json.Unmarshal(content, &sths); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// If period is specified as a query parameter, then we return the STH corresponding to the
	// requested period, otherwise we return all the STHs stored
	period := r.URL.Query().Get("period")

	// No query parameter given
	if period == "" {
		fmt.Fprint(w, string(content))
		return
	}

	var filteredSTHs []gossip.Gossip_object
	for _, sth := range sths {
		if sth.Period == period {
			filteredSTHs = append(filteredSTHs, sth)
		}
	}

	if len(filteredSTHs) == 0 {
		fmt.Fprint(w, filteredSTHs)
		return
	}

	content, err = json.MarshalIndent(filteredSTHs, "", "    ")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, string(content))
}
