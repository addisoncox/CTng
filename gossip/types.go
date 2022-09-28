package gossip

import (
	"CTngv1/config"
	"CTngv1/util"
	"CTngv1/crypto"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
    //"strconv"	
)

// The only valid application type
const CTNG_APPLICATION = "CTng"

// Identifiers for different types of gossip that can be sent.
const (
	STH      = "http://ctng.uconn.edu/101"
	REV      = "http://ctng.uconn.edu/102"
	//From monitor to gossiper
	STH_FRAG = "http://ctng.uconn.edu/201"
	REV_FRAG = "http://ctng.uconn.edu/202"
	ACC_FRAG = "http://ctng.uconn.edu/203"
	// From gossiper to monitor
	// Or in the case of a new monitor is connected to the system, the existing monitor will send them to the new monitor
	// Also used to serve the realying party
	STH_FULL = "http://ctng.uconn.edu/301" 
	REV_FULL = "http://ctng.uconn.edu/302" 
	ACCUSATION_POM  = "http://ctng.uconn.edu/303"
	CONFLICT_POM = "http://ctng.uconn.edu/304"
)

// This function prints the "name string" of each Gossip object type. It's used when printing this info to console.
func TypeString(t string) string {
	switch t {
	case STH:
		return "STH"
	case REV:
		return "REV"
	case STH_FRAG:
		return "STH_FRAG"
	case REV_FRAG:
		return "REV_FRAG"
	case ACC_FRAG:
		return "ACC_FRAG"
	case STH_FULL:
		return "STH_FULL"
	case REV_FULL:
		return "REV_FULL"
	case ACCUSATION_POM:
		return "ACCUSATION_POM"
	case CONFLICT_POM:
		return "CONGLICT_POM"
	default:
		return "UNKNOWN"
	}
}

// Types of errors that can occur when parsing a Gossip_object
const (
	No_Sig_Match = "Signatures don't match"
	Mislabel     = "Fields mislabeled"
	Invalid_Type = "Invalid Type"
)

// Gossip_object representations of these types can be utilized in many places, as opposed to
// converting them back and forth from an intermediate representation.
type Gossip_object struct {
	Application string `json:"application"`
	Period string `json:"period"`
	Type        string `json:"type"`
	Signer string `json:"signer"`
	//**************************The number of signers should be equal to the Threshold, it just happened to be 2 in our case***************************************
	Signers map[int]string `json:"signers"`
	Signature [2]string `json:"signature"`
	// Timestamp is a UTC RFC3339 string
	Timestamp string `json:"timestamp"`
	Crypto_Scheme string `json:"crypto_scheme"`
	Payload [3]string `json:"payload,omitempty"`
}

type Gossip_ID struct{
	Period     string `json:"period"`
	Type       string `json:"type"`
	Entity_URL string `json:"entity_URL"`
}


//This returns the ID of a gossip object, which is the primary key in our Gossip_Object_TSS_DB, and in our Gossip Storage
func (g Gossip_object) GetID() Gossip_ID{
	new_ID := Gossip_ID{
		Period: g.Period,
		Type: g.Type,
		Entity_URL: g.Payload[0],
	}
	return new_ID
}
//Struct to keep track of the number of accusations for an object

type Entity_Gossip_Object_TSS_Counter struct {
	Signers     []string
	Partial_sigs []crypto.SigFragment
	Num     int
}

//This DB stores sth_frags. rec_frags and acc_frags with the counter object
type Gossip_Object_TSS_DB map[Gossip_ID]*Entity_Gossip_Object_TSS_Counter
//This Storage stores 
type Gossip_Storage map[Gossip_ID]Gossip_object

// Gossiper Context
// Ths type represents the current state of a gossiper HTTP server.
// This is the state of a gossiper server. It contains:
// The gossiper Configuration,
// Storage utilized by the gossiper,
// Any objects needed throughout the gossiper's lifetime (such as the http client).
type GossiperContext struct {
	Config      *config.Gossiper_config
	StorageID   string
	Storage     *Gossip_Storage
	Obj_TSS_DB *Gossip_Object_TSS_DB
	StorageFile string 
	StorageDirectory string
	Client  *http.Client
	Verbose bool
}

// Saves the Storage object to the value in c.StorageFile.
func (c *GossiperContext) SaveStorage() error {
	// Turn the gossipStorage into a list, and save the list.
	// This is slow as the size of the DB increases, but since we want to clear the DB each Period it will not infinitely grow..
	storageList := []Gossip_object{}
	for _, gossipObject := range *c.Storage{
		storageList = append(storageList, gossipObject)
	}
	err := util.WriteData(c.StorageDirectory+"/"+c.StorageFile, storageList)
	//err := util.WriteData(c.StorageFile, storageList)
	return err
}
func (c *GossiperContext) ClearStorage() error{
	err := os.Remove(c.StorageDirectory+"/"+c.StorageFile)
	return err
}
// Read every gossip object from c.StorageFile.
// Store all files in c.Storage by their ID.
func (c *GossiperContext) LoadStorage() error {
	// Get the array that has been written to the storagefile.
	storageList := []Gossip_object{}
	//period := c.Config.Public.Period_interval
	bytes, err := util.ReadByte(c.StorageFile)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes, &storageList)
	if err != nil {
		return err
	}
	// Store the objects by their ID, based on the current period defined in the gossiper context.
	// Note that if the period changes (particularly, increases) between loads of the gossiper, some objects may be overwritten/lost.
	// So careful!
	for _, gossipObject := range storageList {
		(*c.Storage)[gossipObject.GetID()] = gossipObject
	}
	return nil
}

// Stores an object in storage by its ID. Note that the ID utilizes Config.Public.Period_interval.
func (c *GossiperContext) StoreObject(o Gossip_object) {
	(*c.Storage)[o.GetID()] = o
}

// Returns 2 fields: the object, and whether or not the object was successfully found.
// If the object isn't found then all fields of the Gossip_object will also be empty.
func (c *GossiperContext) GetObject(id Gossip_ID) (Gossip_object, bool) {
	obj := (*c.Storage)[id]
	if reflect.DeepEqual(obj, Gossip_object{}) {
		return obj, false
	}
	return obj, true
}

// Given a gossip object, check if the an object with the same ID exists in the storage.
func (c *GossiperContext) IsDuplicate(g Gossip_object) bool {
	id := g.GetID()
	_, exists := c.GetObject(id)
	return exists
}

func (c *GossiperContext) HasPoM(entity_URL string, period string) bool{
	//first check accusation pom
	ID := Gossip_ID{
		Period : period,
		Type : ACCUSATION_POM,
		Entity_URL : entity_URL,
	}
	if _, ok := (*c.Storage)[ID]; ok {
		return true
	}
	//then check conflict pom
	ID = Gossip_ID{
		Period: "0",
		Type: CONFLICT_POM,
		Entity_URL: entity_URL,
	}
	if _, ok := (*c.Storage)[ID]; ok {
		return true
	}
	return false
}
