package config

import (
	"CTng/crypto"
	//"math/big"
)

// The structs that are read/written to files.
type Monitor_public_config struct {
	All_CA_URLs      []string
	All_Logger_URLs  []string
	Gossip_wait_time int
	MMD              int
	MRD              int
	Length           uint64 // max size of revocators
	Http_vers        []string
}

type Gossiper_public_config struct {
	Communiation_delay int
	Gossip_wait_time   int
	Max_push_size      int
	Period_interval    int64
	Expiration_time    int // if 0, no expiration.
	MMD                int
	MRD                int
	Gossiper_URLs      []string
	Signer_URLs        []string // List of all potential signers' DNS names.
}

type Monitor_config struct {
	Crypto_config_location string
	CA_URLs                []string
	Logger_URLs            []string
	Signer                 string
	Gossiper_URL           string
	Inbound_gossiper_port  string
	Port                   string
	Crypto                 *crypto.CryptoConfig
	Public                 *Monitor_public_config
}

type Gossiper_config struct {
	Crypto_config_location string 
	Connected_Gossipers []string
	Owner_URL           string
	Port                string
	Crypto              *crypto.CryptoConfig
	Public              *Gossiper_public_config
}