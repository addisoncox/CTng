package monitor

import (
	"CTng/config"
	"CTng/gossip"
	"CTng/util"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
)

type MonitorContext struct {
	Config       *config.Monitor_config
	Storage_TEMP *gossip.Gossip_Storage
	// Gossip objects from the gossiper will be assigned to their dedicated storage
	Storage_CONFLICT_POM       *gossip.Gossip_Storage
	Storage_CONFLICT_POM_DELTA *gossip.Gossip_Storage
	Storage_ACCUSATION_POM     *gossip.Gossip_Storage
	Storage_STH_FULL           *gossip.Gossip_Storage
	Storage_REV_FULL           *gossip.Gossip_Storage
	Storage_NUM_FULL           *gossip.NUM_FULL
	// Utilize Storage directory: A folder for the files of each MMD.
	// Folder should be set to the current MMD "Period" String upon initialization.
	StorageDirectory string
	StorageID        string
	// The below could be used to prevent a Monitor from sending duplicate Accusations,
	// Currently, if a monitor accuses two entities in the same Period, it will trigger a gossip PoM.
	// Therefore, a monitor can only accuse once per Period. I believe this is a temporary solution.
	Verbose bool
	Client  *http.Client
	Mode    int
}

func (c *MonitorContext) GetObjectNumber(objtype string) int {
	switch objtype {
	case gossip.CON_FULL:
		return len(*c.Storage_CONFLICT_POM)
	case gossip.ACC_FULL:
		return len(*c.Storage_ACCUSATION_POM)
	case gossip.STH_FULL:
		return len(*c.Storage_STH_FULL)
	case gossip.REV_FULL:
		return len(*c.Storage_REV_FULL)
	}
	return 0
}
func (c *MonitorContext) Clean_Conflicting_Object() {
	GID := gossip.Gossip_ID{}
	for key := range *c.Storage_STH_FULL {
		GID = gossip.Gossip_ID{
			Period:     "0",
			Type:       gossip.CON_FULL,
			Entity_URL: key.Entity_URL,
		}
		if _, ok := (*c.Storage_CONFLICT_POM)[GID]; ok {
			fmt.Println(util.BLUE + "Logger: " + key.Entity_URL + "has Conflict_PoM on file, cleared the STH from this Logger this MMD" + util.RESET)
			delete(*c.Storage_STH_FULL, key)
		}
	}
	for key := range *c.Storage_REV_FULL {
		GID = gossip.Gossip_ID{
			Period:     "0",
			Type:       gossip.CON_FULL,
			Entity_URL: key.Entity_URL,
		}
		if _, ok := (*c.Storage_CONFLICT_POM)[GID]; ok {
			fmt.Println(util.BLUE + "CA: " + key.Entity_URL + "has Conflict_PoM on file, cleared the REV from this CA this MRD" + util.RESET)
			delete(*c.Storage_REV_FULL, key)
		}
	}
}

func (c *MonitorContext) SaveStorage(Period string, update ClientUpdate) error {
	// should be string

	// Create the storage directory, should be StorageDirectory/Period
	newdir := c.StorageDirectory + "/Period_" + Period
	util.CreateDir(newdir)
	// Create the storage files
	/*
		sth_path := newdir + "/STH_FULL_at_Period_" + gossip.GetCurrentPeriod() + ".json"
		rev_path := newdir + "/REV_FULL_at_Period_" + gossip.GetCurrentPeriod() + ".json"
		conflict_path := newdir + "/CON_FULL_at_Period_" + gossip.GetCurrentPeriod() + ".json"
		accusation_path := newdir + "/ACC_PoM_at_Period_" + gossip.GetCurrentPeriod() + ".json"
	*/
	clientUpdate_path := newdir + "/ClientUpdate.json"
	/*
		util.CreateFile(sth_path)
		util.CreateFile(rev_path)
		util.CreateFile(conflict_path)
		util.CreateFile(accusation_path)
	*/
	util.CreateFile(clientUpdate_path)
	// Write the storage files
	/*
		util.WriteData(sth_path, storageList_sth_full)
		util.WriteData(rev_path, storageList_rev_full)
		util.WriteData(conflict_path, storageList_conflict_pom)
		util.WriteData(accusation_path, storageList_accusation_pom)
	*/
	util.WriteData(clientUpdate_path, update)
	fmt.Println(util.BLUE, "File Storage Complete for Period: ", gossip.GetCurrentPeriod(), util.RESET)
	return nil
}

func (c *MonitorContext) LoadOneStorage(name string, filepath string) error {
	storageList := []gossip.Gossip_object{}
	bytes, err := util.ReadByte(filepath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes, &storageList)
	if err != nil {
		return err
	}
	switch name {
	case gossip.CON_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_CONFLICT_POM)[gossipObject.GetID()] = gossipObject
		}
	case gossip.ACC_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_ACCUSATION_POM)[gossipObject.GetID()] = gossipObject
		}
	case gossip.STH_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_STH_FULL)[gossipObject.GetID()] = gossipObject
		}
	case gossip.REV_FULL:
		for _, gossipObject := range storageList {
			(*c.Storage_REV_FULL)[gossipObject.GetID()] = gossipObject
		}
	}
	return errors.New("Mismatch")
}

func (c *MonitorContext) GetObject(id gossip.Gossip_ID) gossip.Gossip_object {
	GType := id.Type
	switch GType {
	case gossip.CON_FULL:
		obj := (*c.Storage_CONFLICT_POM)[id]
		return obj
	case gossip.ACC_FULL:
		obj := (*c.Storage_ACCUSATION_POM)[id]
		return obj
	case gossip.STH_FULL:
		obj := (*c.Storage_STH_FULL)[id]
		return obj
	case gossip.REV_FULL:
		obj := (*c.Storage_REV_FULL)[id]
		return obj
	case gossip.STH:
		obj := (*c.Storage_TEMP)[id]
		return obj
	case gossip.REV:
		obj := (*c.Storage_TEMP)[id]
		return obj
	}
	return gossip.Gossip_object{}

}
func (c *MonitorContext) IsDuplicate(g gossip.Gossip_object) bool {
	//no public period time for monitor :/
	id := g.GetID()
	obj := c.GetObject(id)
	return reflect.DeepEqual(obj, g)
}

func (c *MonitorContext) StoreObject(o gossip.Gossip_object) {
	switch o.Type {
	case gossip.CON_FULL:
		(*c.Storage_CONFLICT_POM)[o.GetID()] = o
		(*c.Storage_CONFLICT_POM_DELTA)[o.GetID()] = o
		fmt.Println(util.BLUE, "CONFLICT_POM Stored", util.RESET)
	case gossip.ACC_FULL:
		//ACCUSATION POM does not need to be stored, but this function is here for testing purposes
		(*c.Storage_ACCUSATION_POM)[o.GetID()] = o
		fmt.Println(util.BLUE, "ACCUSATION_POM Stored", util.RESET)
	case gossip.STH_FULL:
		(*c.Storage_STH_FULL)[o.GetID()] = o
		fmt.Println(util.BLUE, "STH_FULL Stored", util.RESET)
	case gossip.REV_FULL:
		(*c.Storage_REV_FULL)[o.GetID()] = o
		fmt.Println(util.BLUE, "REV_FULL Stored", util.RESET)
	default:
		(*c.Storage_TEMP)[o.GetID()] = o
	}

}

//wipe all temp data
func (c *MonitorContext) WipeStorage() {
	for key := range *c.Storage_TEMP {
		if key.Period != gossip.GetCurrentPeriod() {
			delete(*c.Storage_ACCUSATION_POM, key)
		}
	}
	for key := range *c.Storage_ACCUSATION_POM {
		if key.Period != gossip.GetCurrentPeriod() {
			delete(*c.Storage_ACCUSATION_POM, key)
		}
	}
	for key := range *c.Storage_CONFLICT_POM_DELTA {
		if key.Period != gossip.GetCurrentPeriod() {
			delete(*c.Storage_CONFLICT_POM_DELTA, key)
		}
	}
	fmt.Println(util.BLUE, "Temp storage has been wiped.", util.RESET)
}

func (c *MonitorContext) InitializeMonitorStorage(filepath string) {
	c.StorageDirectory = filepath + "/" + c.StorageID + "/"
}

func (c *MonitorContext) CleanUpMonitorStorage() {
	//delete all files in storage directory
	err := util.DeleteFilesAndDirectories(c.StorageDirectory)
	if err != nil {
		fmt.Println(err)
	}
}

func InitializeMonitorContext(public_config_path string, private_config_path string, crypto_config_path string, storageID string) *MonitorContext {
	conf, err := config.LoadMonitorConfig(public_config_path, private_config_path, crypto_config_path)
	if err != nil {
		//panic(err)
	}
	// Space is allocated for all storage fields, and then make is run to initialize these spaces.
	storage_temp := new(gossip.Gossip_Storage)
	*storage_temp = make(gossip.Gossip_Storage)
	storage_conflict_pom := new(gossip.Gossip_Storage)
	*storage_conflict_pom = make(gossip.Gossip_Storage)
	storage_conflict_pom_delta := new(gossip.Gossip_Storage)
	*storage_conflict_pom_delta = make(gossip.Gossip_Storage)
	storage_accusation_pom := new(gossip.Gossip_Storage)
	*storage_accusation_pom = make(gossip.Gossip_Storage)
	storage_sth_full := new(gossip.Gossip_Storage)
	*storage_sth_full = make(gossip.Gossip_Storage)
	storage_rev_full := new(gossip.Gossip_Storage)
	*storage_rev_full = make(gossip.Gossip_Storage)
	ctx := MonitorContext{
		Config:                     &conf,
		Storage_TEMP:               storage_temp,
		Storage_CONFLICT_POM:       storage_conflict_pom,
		Storage_CONFLICT_POM_DELTA: storage_conflict_pom_delta,
		Storage_ACCUSATION_POM:     storage_accusation_pom,
		Storage_STH_FULL:           storage_sth_full,
		Storage_REV_FULL:           storage_rev_full,
		Storage_NUM_FULL:           &gossip.NUM_FULL{},
		StorageID:                  storageID,
		Mode:                       0,
	}
	ctx.Config = &conf
	return &ctx
}
