package gossip

import (
	"CTng/config"
	"CTng/util"
	"CTng/crypto"
	"encoding/json"
	"net/http"	
	"reflect"
	"fmt"
)


// Types of errors that can occur when parsing a Gossip_object
const (
	No_Sig_Match = "Signatures don't match"
	Mislabel     = "Fields mislabeled"
	Invalid_Type = "Invalid Type"
)

// Gossip_object representations of these types can be utilized in many places, as opposed to
// converting them back and forth from an intermediate representation.
type Entity_Gossip_Object_TSS_Counter struct {
	Signers     []string
	Partial_sigs []crypto.SigFragment
	Num     int
}

//This DB stores sth_frags. rec_frags and acc_frags with the counter object
type Gossip_Object_TSS_DB map[Gossip_ID]*Entity_Gossip_Object_TSS_Counter

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
	// we only save the CONFLICT POM
	storageList := []Gossip_object{}
	for key, gossipObject := range *c.Storage{
		if key.Type == CONFLICT_POM{
			storageList = append(storageList, gossipObject)
		}
	}
	err := util.WriteData(c.StorageDirectory+"/"+c.StorageFile, storageList)
	return err
}

//wipe all temp data
func (c *GossiperContext) WipeStorage(){
	for key, _ := range *c.Storage{
		if key.Type != CONFLICT_POM|| key.Period!=GetCurrentPeriod(){
			delete(*c.Storage,key)
		}
	}
	for key, _:= range *c.Obj_TSS_DB{
		if key.Period!=GetCurrentPeriod(){
			delete(*c.Obj_TSS_DB,key)
		}
	}
	fmt.Println(util.BLUE,"Temp storage has been wiped.",util.RESET)
}
// Read every gossip object from c.StorageFile.
// Store all files in c.Storage by their ID.
func (c *GossiperContext) LoadStorage() error {
	// Get the array that has been written to the storagefile.
	storageList := []Gossip_object{}
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
