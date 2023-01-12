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
	http.HandleFunc("/sth", createRequestHandler("testData/monitordata/1/STH_FULL.json"))
	http.HandleFunc("/rev", createRequestHandler("testData/monitordata/1/REV_FULL.json"))
	http.HandleFunc("/pom", createRequestHandler("testData/monitordata/1/CONFLICT_POM.json"))
	fmt.Println("Monitor listening on port 3000...")
	if err := http.ListenAndServe("localhost:3000", nil); err != nil {
		log.Fatal(err)
	}
}

func createRequestHandler(fileName string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// TODO: Replace file location with config object
		content, err := os.ReadFile(fileName)
		if err != nil {
			http.Error(w, "Internal server error: Could not read data", http.StatusInternalServerError)
			return
		}

		// Parse file as array of gossip objects
		var objects []gossip.Gossip_object
		if err = json.Unmarshal(content, &objects); err != nil {
			http.Error(w, "Internal server error: Could not unmarshal data", http.StatusInternalServerError)
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

		var filteredObjects []gossip.Gossip_object
		for _, obj := range objects {
			if obj.Period == period {
				filteredObjects = append(filteredObjects, obj)
			}
		}

		if len(filteredObjects) == 0 {
			fmt.Fprint(w, filteredObjects)
			return
		}

		content, err = json.MarshalIndent(filteredObjects, "", "    ")
		if err != nil {
			http.Error(w, "Internal server error: Could not marshal response", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, string(content))
	}
}
