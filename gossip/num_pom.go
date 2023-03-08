package gossip

import (
	"CTng/crypto"
)

// Content tbs = NUM_ACC_FULL || NUM_CON_FULL || PERIOD || SIGNER_MONITOR
// Content tbs is the same for all NUM types
type NUM struct {
	NUM_ACC_FULL   string
	NUM_CON_FULL   string
	Period         string
	Signer_Monitor string
	Crypto_Scheme  string
	Signature      string
}

// Content tbs = NUM_ACC_FULL || NUM_CON_FULL || PERIOD
type NUM_FRAG struct {
	NUM_ACC_FULL    string
	NUM_CON_FULL    string
	Period          string
	Signer_Gossiper string
	Crypto_Scheme   string
	Signature       string
}

type NUM_FULL struct {
	NUM_ACC_FULL  string
	NUM_CON_FULL  string
	Period        string
	Signers       map[int]string
	Crypto_Scheme string
	Signature     string
}

func (n *NUM) Verify(cryptoconf *crypto.CryptoConfig) error {
	// Verify that the signature is valid
	sig, _ := crypto.RSASigFromString(n.Signature)
	return cryptoconf.Verify([]byte(n.NUM_ACC_FULL+n.NUM_CON_FULL+n.Period+n.Signer_Monitor), sig)
}

func (n *NUM_FRAG) Verify(cryptoconf *crypto.CryptoConfig) error {
	// Verify that the signature is valid
	sig, _ := crypto.SigFragmentFromString(n.Signature)
	return cryptoconf.FragmentVerify(n.NUM_ACC_FULL+n.NUM_CON_FULL+n.Period, sig)
}

func (n *NUM_FULL) Verify(cryptoconf *crypto.CryptoConfig) error {
	// Verify that the signature is valid
	sig, _ := crypto.ThresholdSigFromString(n.Signature)
	return cryptoconf.ThresholdVerify(n.NUM_ACC_FULL+n.NUM_CON_FULL+n.Period, sig)
}

// generate NUM wil be a montior function

// generate NUM_FRAG wil be a gossiper function
func Generate_NUM_FRAG(n *NUM, cryptoconf *crypto.CryptoConfig) *NUM_FRAG {
	// Generate a signature fragment
	sig, _ := cryptoconf.ThresholdSign(n.NUM_ACC_FULL + n.NUM_CON_FULL + n.Period + n.Signer_Monitor)
	return &NUM_FRAG{
		NUM_ACC_FULL:    n.NUM_ACC_FULL,
		NUM_CON_FULL:    n.NUM_CON_FULL,
		Period:          n.Period,
		Signer_Gossiper: cryptoconf.SelfID.String(),
		Crypto_Scheme:   "bls",
		Signature:       sig.String(),
	}
}

// when calling this function, we assume that every entry in NUM_FRAG_LIST have the same NUM_ACC_FULL, NUM_CON_FULL, Period, Signer_Monitor, Crypto_Scheme
func Generate_NUM_FULL(NUM_FRAG_LIST []*NUM_FRAG, cryptoconf *crypto.CryptoConfig) *NUM_FULL {
	partial_sigs := make([]crypto.SigFragment, len(NUM_FRAG_LIST))
	for i, num_frag := range NUM_FRAG_LIST {
		partial_sigs[i], _ = crypto.SigFragmentFromString(num_frag.Signature)
	}
	TSS_Sig, _ := cryptoconf.ThresholdAggregate(partial_sigs)
	TSS_sig_string, _ := TSS_Sig.String()
	signermap := make(map[int]string)
	for i := 0; i < len(NUM_FRAG_LIST); i++ {
		signermap[i] = NUM_FRAG_LIST[i].Signer_Gossiper
	}
	return &NUM_FULL{
		NUM_ACC_FULL:  NUM_FRAG_LIST[0].NUM_ACC_FULL,
		NUM_CON_FULL:  NUM_FRAG_LIST[0].NUM_CON_FULL,
		Period:        NUM_FRAG_LIST[0].Period,
		Signers:       signermap,
		Crypto_Scheme: "bls",
		Signature:     TSS_sig_string,
	}
}
