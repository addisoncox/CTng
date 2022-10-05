package gossip


import (
	"CTngv1/util"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"CTngv1/crypto"
	"errors"
	"time"
	"strconv"
)

// GetCurrentTimestamp returns the current UTC timestamp in RFC3339 format
// This is the standard which we've decided upon in  the specs.
func GetCurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func GetCurrentPeriod() string{
	timerfc := time.Now().UTC().Format(time.RFC3339)
	Miniutes, err := strconv.Atoi(timerfc[14:16])
	Periodnum := strconv.Itoa(Miniutes)
	if err != nil {
	}
	return Periodnum
}

func Verify_gossip_pom(g Gossip_object, c *crypto.CryptoConfig) error {
	if g.Type == CONFLICT_POM {
		var err1, err2 error
		if g.Signature[0] != g.Signature[1] {
			if g.Crypto_Scheme == "BLS"{
				fragsig1, sigerr1 := crypto.SigFragmentFromString(g.Signature[0])
				fragsig2, sigerr2 := crypto.SigFragmentFromString(g.Signature[1])
				// Verify the signatures were made successfully
				if sigerr1 != nil || sigerr2 != nil && !fragsig1.Sign.IsEqual(fragsig2.Sign) {
					err1 = c.FragmentVerify(g.Payload[1], fragsig1)
					err2 = c.FragmentVerify(g.Payload[2], fragsig2)
				}
			}else{
				rsaSig1, sigerr1 := crypto.RSASigFromString(g.Signature[0])
				rsaSig2, sigerr2 := crypto.RSASigFromString(g.Signature[1])
				// Verify the signatures were made successfully
				if sigerr1 != nil || sigerr2 != nil {
					err1 = c.Verify([]byte(g.Payload[1]), rsaSig1)
					err2 = c.Verify([]byte(g.Payload[2]), rsaSig2)
				}}
			}
			if err1 == nil && err2 == nil {
				return nil
			} else {
				return errors.New("Message Signature Mismatch" + fmt.Sprint(err1) + fmt.Sprint(err2))
			}
		} else {
			//if signatures are the same, there are no conflicting information
			return errors.New("This is not a valid gossip pom")
		}
}

//verifies signature fragments match with payload
func Verify_PayloadFrag(g Gossip_object, c *crypto.CryptoConfig) error {
	if g.Signature[0] != "" && g.Payload[0] != "" {
		sig, _ := crypto.SigFragmentFromString(g.Signature[0])
		err := c.FragmentVerify(g.Payload[0]+g.Payload[1]+g.Payload[2], sig)
		if err != nil {
			return errors.New(No_Sig_Match)
		}
		return nil
	} else {
		return errors.New(Mislabel)
	}
}

//verifies threshold signatures match payload
func Verify_PayloadThreshold(g Gossip_object, c *crypto.CryptoConfig) error {
	if g.Signature[0] != "" && g.Payload[0] != "" {
		sig, _ := crypto.ThresholdSigFromString(g.Signature[0])
		err := c.ThresholdVerify(g.Payload[0]+g.Payload[1]+g.Payload[2], sig)
		if err != nil {
			return errors.New(No_Sig_Match)
		}
		return nil
	} else {
		return errors.New(Mislabel)
	}
}

// Verifies RSAsig matches payload, wait.... i think this just works out of the box with what we have
func Verify_RSAPayload(g Gossip_object, c *crypto.CryptoConfig) error {
	if g.Signature[0] != "" && g.Payload[0] != "" {
		sig, err := crypto.RSASigFromString(g.Signature[0])
		if err != nil {
			return errors.New(No_Sig_Match)
		}
		return c.Verify([]byte(g.Payload[0]+g.Payload[1]+g.Payload[2]), sig)

	} else {
		return errors.New(Mislabel)
	}
}

//Verifies Gossip object based on the type:
//STH and Revocations use RSA
//Trusted information Fragments use BLS SigFragments
//PoMs use Threshold signatures
func (g Gossip_object) Verify(c *crypto.CryptoConfig) error {
	// If everything Verified correctly, we return nil
	switch g.Type {
	case STH:
		return Verify_RSAPayload(g, c)
	case REV:
		return Verify_RSAPayload(g, c)
	case STH_FRAG:
		return Verify_PayloadFrag(g, c)
	case REV_FRAG:
		return Verify_PayloadFrag(g, c)
	case ACC_FRAG:
		return Verify_PayloadFrag(g, c)
	case STH_FULL:
		return Verify_PayloadThreshold(g, c)
	case REV_FULL:
		return Verify_PayloadThreshold(g, c)
	case ACCUSATION_POM:
		return Verify_PayloadThreshold(g, c)
	case CONFLICT_POM:
		return Verify_gossip_pom(g, c)
	default:
		return errors.New(Invalid_Type)
	}
}




// Sends a gossip object to all connected gossipers.
// This function assumes you are passing valid data. ALWAYS CHECK BEFORE CALLING THIS FUNCTION.
func GossipData(c *GossiperContext, gossip_obj Gossip_object) error {
	// Convert gossip object to JSON
	msg, err := json.Marshal(gossip_obj)
	if err != nil {
		fmt.Println(err)
	}

	// Send the gossip object to all connected gossipers.
	for _, url := range c.Config.Connected_Gossipers {
		//fmt.Println("Attempting to sending data to", url)
		// HTTP POST the data to the url or IP address.
		resp, err := c.Client.Post("http://"+url+"/gossip/push-data", "application/json", bytes.NewBuffer(msg))
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") ||
				strings.Contains(err.Error(), "connection refused") {
				fmt.Println(util.RED+"Connection failed to "+url+".", util.RESET)
				// Don't accuse gossipers for inactivity.
				// defer Accuse(c, url)
			} else {
				fmt.Println(util.RED+err.Error(), "sending to "+url+".", util.RESET)
			}
			continue
		}
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		//fmt.Println("Gossiped to " + url + " and recieved " + resp.Status)
	}
	return nil
}

// Sends a gossip object to the owner of the gossiper.
func SendToOwner(c *GossiperContext, obj Gossip_object) {
	// Convert gossip object to JSON
	msg, err := json.Marshal(obj)
	if err != nil {
		fmt.Println(err)
	}
	// Send the gossip object to the owner.
	resp, postErr := c.Client.Post("http://"+c.Config.Owner_URL+"/monitor/recieve-gossip-from-gossiper", "application/json", bytes.NewBuffer(msg))
	if postErr != nil {
		fmt.Println("Error sending object to owner: " + postErr.Error())
	} else {
		// Close the response, mentioned by http.Post
		// Alernatively, we could return the response from this function.
		defer resp.Body.Close()
		if c.Verbose {
			fmt.Println("Owner responded with " + resp.Status)
		}
	}
	// Handling errors from owner could go here.
}

// Once an object is verified, it is stored and given its neccessary data path.
// At this point, the object has not yet been stored in the database.
// What we know is that the signature is valid for the provided data.
func ProcessValidObject(c *GossiperContext, obj Gossip_object) {
	// This function is incomplete -- requires more individual object direction
	// Note: Object needs to be stored before Gossiping so it is recognized as a duplicate.
	c.StoreObject(obj)
	var err error = nil
	switch obj.Type {
	case STH:
		err = GossipData(c, obj)
	case REV:
		err = GossipData(c, obj)
	case STH_FRAG:
		err = GossipData(c, obj)
		fmt.Println("Finshed Gossiping ",obj.Type, ". Starting to process it.")
		Process_STH_FRAG(c, obj)
	case REV_FRAG:
		err = GossipData(c, obj)
		fmt.Println("Finshed Gossiping ",obj.Type, ". Starting to process it.")
		Process_REV_FRAG(c, obj)
	case ACC_FRAG:
		err = GossipData(c, obj)
		fmt.Println("Finshed Gossiping ",obj.Type, ". Starting to process it.")
		Process_ACC_FRAG(c, obj)
	case STH_FULL:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case REV_FULL:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case ACCUSATION_POM:
		SendToOwner(c, obj)
		err = GossipData(c, obj)
	case CONFLICT_POM:
		SendToOwner(c, obj)
		err = GossipData(c, obj)

	default:
		fmt.Println("Recieved unsupported object type.")
	}
	if err != nil {
		// ...
	}
}

// Once an object is verified, it is stored and given its neccessary data path.
// At this point, the object has not yet been stored in the database.
// What we know is that the signature is valid for the provided data.
func ProcessValidObjectFromOwner(c *GossiperContext, obj Gossip_object) {
	ProcessValidObject(c, obj)
}

// Process a valid gossip object which is a duplicate to another one.
// If the signature/payload is identical, then we can safely ignore the duplicate.
// Otherwise, we generate a PoM for two objects sent in the same period.
func ProcessDuplicateObject(c *GossiperContext, obj Gossip_object, dup Gossip_object) error{
	//If the object has PoM already, it is dead already
	if c.HasPoM(obj.Payload[0],obj.Period){
		return nil
	}
	//If the object type is the same
	//In the same Periord
	//Signed by the same Entity
	//But the signature is different
	//MALICIOUS, you are exposed
	//note PoMs can have different signatures
	if obj.Type == dup.Type && obj.Period == dup.Period && obj.Signer == dup.Signer && obj.Signature[0] != dup.Signature[0] && obj.Type!= CONFLICT_POM && obj.Type != ACCUSATION_POM{
		D2_POM:= Gossip_object{
			Application: obj.Application,
			Type:        CONFLICT_POM,
			Period:      "0",
			Signer:      "",
			Timestamp:   GetCurrentTimestamp(),
			Signature:   [2]string{obj.Signature[0], dup.Signature[0]},
			Payload:     [3]string{obj.Signer, obj.Payload[0]+obj.Payload[1]+obj.Payload[2],dup.Payload[0]+dup.Payload[1]+dup.Payload[2]},
		}
		//store the object and send to monitor
		fmt.Println(util.RED, "Entity: ", D2_POM.Payload[0], " is Malicious!", util.RESET)
		SendToOwner(c,D2_POM)
		c.StoreObject(D2_POM)
		GossipData(c,D2_POM)
	}
	return nil
}

//This function is invoked after checking PoM and Duplicate
func Process_STH_FRAG(gc *GossiperContext, new_obj Gossip_object) error{
	c := gc.Config.Crypto
	key := new_obj.GetID()
	fmt.Println(key)
	newkey:=Gossip_ID{
		Period: key.Period,
		Type: STH_FULL,
		Entity_URL: key.Entity_URL,
	}
	p_sig, err := crypto.SigFragmentFromString(new_obj.Signature[0])
	if err != nil {
		fmt.Println("partial sig conversion error (from string)")
		return err
	}
	//If there is already an STH_FULL Object
	if _, ok:= (*gc.Storage)[newkey]; ok{
		fmt.Println(util.BLUE + "There already exists a STH_FULL Object" + util.RESET)
		return nil
	} 
	//If there isn't a STH_FULL Object yet, but there exists some other sth_frag
	if val, ok := (*gc.Obj_TSS_DB)[key]; ok {
		val.Signers[val.Num] = new_obj.Signer
		if err != nil {
			fmt.Println("partial sig conversion error (from string)")
			return err
		}
		val.Partial_sigs[val.Num] = p_sig
		val.Num = val.Num + 1
		fmt.Println("Finished updating Counters, the new number is", val.Num)
		//now we check if the number of sigs have reached the threshold
		if val.Num>=c.Threshold{
			TSS_sig, _ := c.ThresholdAggregate(val.Partial_sigs)
			TSS_sig_string,_ := TSS_sig.String()
			sigfield := new([2]string)
			(*sigfield)[0] = TSS_sig_string
			signermap := make(map[int]string)
			for i := 0; i<c.Threshold; i++{
				signermap[i] = val.Signers[i]
			}
			STH_FULL_obj := Gossip_object{
				Application: new_obj.Application,
				Type:        STH_FULL,
				Period:      new_obj.Period,
				Signer:      "",
				Signers:     signermap,
				Timestamp:   GetCurrentTimestamp(),
				Signature:   *sigfield,
				Crypto_Scheme: "BLS",
				Payload:     new_obj.Payload,
			}
			//Store the POM
			fmt.Println(util.BLUE+"STH_FULL generated and Stored"+util.RESET)
			gc.StoreObject(STH_FULL_obj)
			//send to the monitor
			SendToOwner(gc,STH_FULL_obj)
			return nil
		}
	}
	//if the this is the first STH_FRAG received
	fmt.Println("This is the first partial sig registered")
	new_counter := new(Entity_Gossip_Object_TSS_Counter)
	*new_counter = Entity_Gossip_Object_TSS_Counter{
		Signers:     []string{new_obj.Signer,""},
		Num:      1,
		Partial_sigs: []crypto.SigFragment{p_sig,p_sig},
	}
	(*gc.Obj_TSS_DB)[key] = new_counter
	fmt.Println("Number of counters in TSS DB is: ", len(*gc.Obj_TSS_DB))
	return nil
}


func Process_ACC_FRAG(gc *GossiperContext, new_obj Gossip_object) error{
	c := gc.Config.Crypto
	key := new_obj.GetID()
	fmt.Println(key)
	p_sig, err := crypto.SigFragmentFromString(new_obj.Signature[0])
	if err != nil {
		fmt.Println("partial sig conversion error (from string)")
		return err
	}
	//if the entity accused already have other accusations on file
	if val, ok := (*gc.Obj_TSS_DB)[key]; ok{
		//update the number of accusations, list of accusers, and list of partial sigs
		val.Signers[val.Num] = new_obj.Signer
		val.Partial_sigs[val.Num] = p_sig
		val.Num = val.Num + 1
		//now we check if the number of accusations have reached the threshold
		if val.Num>=c.Threshold{
			TSS_sig, _ := c.ThresholdAggregate(val.Partial_sigs)
			TSS_sig_string,_ := TSS_sig.String()
			sigfield := new([2]string)
			(*sigfield)[0] = TSS_sig_string
			signermap := make(map[int]string)
			for i := 0; i<c.Threshold; i++{
				signermap[i] = val.Signers[i]
			}
			ACCUSATION_POM_obj := Gossip_object{
				Application: new_obj.Application,
				Type:        ACCUSATION_POM,
				Period:      new_obj.Period,
				Signer:      "",
				Signers:     signermap,
				Timestamp:   GetCurrentTimestamp(),
				Signature:   *sigfield,
				Crypto_Scheme: "BLS",
				Payload:     new_obj.Payload,
			}
			//Store the POM
			fmt.Println(util.BLUE+"Accusation PoM generated and Stored"+util.RESET)
			gc.StoreObject(ACCUSATION_POM_obj)
			//send to the monitor
			SendToOwner(gc,ACCUSATION_POM_obj)
			return nil
		}
	}
	//if the entity is accused the first time
	fmt.Println("This is the first partial sig registered")
	new_counter := new(Entity_Gossip_Object_TSS_Counter)
	*new_counter = Entity_Gossip_Object_TSS_Counter{
		Signers:     []string{new_obj.Signer,""},
		Num:      1,
		Partial_sigs: []crypto.SigFragment{p_sig,p_sig},
	}
	(*gc.Obj_TSS_DB)[key] = new_counter
	fmt.Println("Number of counters in TSS DB is: ", len(*gc.Obj_TSS_DB))
	return nil
}

func Process_REV_FRAG(gc *GossiperContext, new_obj Gossip_object) error{
	c := gc.Config.Crypto
	key := new_obj.GetID()
	fmt.Println(key)
	newkey:=Gossip_ID{
		Period: key.Period,
		Type: REV_FULL,
		Entity_URL: key.Entity_URL,
	}
	p_sig, err := crypto.SigFragmentFromString(new_obj.Signature[0])
	//If there is already an REV_FULL Object
	if _, ok:= (*gc.Storage)[newkey]; ok{
		fmt.Println(util.BLUE + "There already exists a REV_FULL Object" + util.RESET)
		return nil
	} 
	//If there isn't a REV_FULL Object yet, but there exists some other sth_frag
	if val, ok := (*gc.Obj_TSS_DB)[key]; ok {
		val.Signers[val.Num] = new_obj.Signer
		if err != nil {
			fmt.Println("partial sig conversion error (from string)")
			return err
		}
		val.Partial_sigs[val.Num] = p_sig
		val.Num = val.Num + 1
		//now we check if the number of sigs have reached the threshold
		if val.Num>=c.Threshold{
			TSS_sig, _ := c.ThresholdAggregate(val.Partial_sigs)
			TSS_sig_string,_ := TSS_sig.String()
			sigfield := new([2]string)
			(*sigfield)[0] = TSS_sig_string
			signermap := make(map[int]string)
			for i := 0; i<c.Threshold; i++{
				signermap[i] = val.Signers[i]
			}
			REV_FULL_obj := Gossip_object{
				Application: new_obj.Application,
				Type:        REV_FULL,
				Period:      new_obj.Period,
				Signer:      "",
				Signers:     signermap, 
				Timestamp:   GetCurrentTimestamp(),
				Signature:   *sigfield,
				Crypto_Scheme: "BLS",
				Payload:     new_obj.Payload,
			}
			//Store the POM
			fmt.Println(util.BLUE+"REV_FULL generated and Stored"+util.RESET)
			gc.StoreObject(REV_FULL_obj)
			//send to the monitor
			SendToOwner(gc,REV_FULL_obj)
			return nil
		}
	}
	//if the this is the first STH_FRAG received
	fmt.Println("This is the first partial sig registered")
	new_counter := new(Entity_Gossip_Object_TSS_Counter)
	*new_counter = Entity_Gossip_Object_TSS_Counter{
		Signers:     []string{new_obj.Signer,""},
		Num:      1,
		Partial_sigs: []crypto.SigFragment{p_sig,p_sig},
	}
	(*gc.Obj_TSS_DB)[key] = new_counter
	fmt.Println("Number of counters in TSS DB is: ", len(*gc.Obj_TSS_DB))
	return nil
}