package config
/*
// Unused, but the below info
type Config_Input struct {
	Monitor_URLs []string
	//Below is f: aka the "threshold number - 1"
	// Each logger needs 2(f+1) connections.
	// Each monitor needs f+1 monitor connections.
	// Gossip_Wait_Time is threfore determined by the
	// resulting diameter of the monitor network. 
	Max_Rogue_Parties int
	MMD               int // MRD derived from this
	CA_URLs           []string
	Logger_URLs       []string
	// Gossipers, for now, can be set to communicate on
	// the same local network as the monitor.
	Default_Gossiper_Port string
}

type CA_public_config struct {
	All_CA_URLs     []string
	All_Logger_URLs []string
	MMD             int
	MRD             int
	Http_vers       []string
	Length          uint64 // max size of revocators
	NormalizeNumber big.Int
}

type CA_config struct {
	Crypto_config_location string
	Logger_URLs            []string
	Signer                 string
	Port                   string
	Crypto                 *crypto.CryptoConfig
	Public                 *CA_public_config
}

type Logger_public_config struct {
	All_CA_URLs     []string
	All_Logger_URLs []string
	MMD             int
	MRD             int
	Http_vers       []string
	Length          uint64 // max size of revocators
}

type Logger_config struct {
	Crypto_config_location string
	CA_URLs                []string
	Signer                 string
	Port                   string
	Crypto                 *crypto.CryptoConfig
	Public                 *Logger_public_config
	// MisbehaviorInterval    int
	// LoggerType             int
	// LoggerType:
	//  1. Normal, behaving Logger (default)
	//  2. Split-World (Two different STHS on every MisbehaviorInterval MMD)
	//  3. Disconnecting Logger (unresponsive every MisbehaviorInterval MMD)
}

/Identical to above, but for the ca.
func LoadCAConfig(publicpath string, privatepath string, cryptopath string) (CA_config, error) {
	c := new(CA_config)
	c_pub := new(CA_public_config)
	LoadConfiguration(c, privatepath)
	LoadConfiguration(c_pub, publicpath)
	c.Public = c_pub
	crypto, err := crypto.ReadBasicCryptoConfig(cryptopath)
	c.Crypto = crypto
	if err != nil {
		return *c, err
	}
	return *c, nil
}

//Identical to above, but for the logger.
func LoadLoggerConfig(publicpath string, privatepath string, cryptopath string) (Logger_config, error) {
	c := new(Logger_config)
	c_pub := new(Logger_public_config)
	LoadConfiguration(c, privatepath)
	LoadConfiguration(c_pub, publicpath)
	c.Public = c_pub
	crypto, err := crypto.ReadBasicCryptoConfig(cryptopath)
	c.Crypto = crypto
	if err != nil {
		return *c, err
	}
	return *c, nil
}

*/