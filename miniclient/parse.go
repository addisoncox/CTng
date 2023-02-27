package miniclient

import (
	"encoding/json"
	"fmt"
)

// type SRH = map[string]string
type SRH struct {
	Signature string `json:"sig"`
	Id string `json:"id"`
}

func GetSRH(data MonitorData) []SRH {
	var out []SRH
	for _, sth := range data {
		var payload map[string]string
		err := json.Unmarshal([]byte(sth.Payload[2]), &payload)
		if err != nil {
			fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		// Parse SRH as a struct with signature and id fields
		var srh SRH
		err = json.Unmarshal([]byte(payload["SRH"]), &srh)
		if err != nil {
			fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		out = append(out, srh)
	}
	return out
}

func GetDeltaCRV(data MonitorData) []string {
	// Parse payload[2] as Revocation
	var out []string
	for _, rev := range data {
		var payload map[string]any
		err := json.Unmarshal([]byte(rev.Payload[2]), &payload)
		if err != nil {
			fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		out = append(out, payload["Delta_CRV"].(string))
	}
	return out
}

func GetRootHash(data MonitorData) []string {
	var out []string
	for _, sth := range data {
		var payload map[string]any
		err := json.Unmarshal([]byte(sth.Payload[1]), &payload)
		if err != nil {
			fmt.Println(payload)
			fmt.Println(err)
			return out
		}

		out = append(out, payload["RootHash"].(string))
	}
	return out
}
