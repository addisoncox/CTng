package Logger

import (
	"CTng/crypto"
	"CTng/gossip"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	"github.com/google/certificate-transparency-go/x509"
)

type STH struct {
	Timestamp string
	RootHash  string
	TreeSize  int
}

type ProofOfInclusion struct {
	siblingHashes [][]byte
}

type RevocationID uint

type MerkleNode struct {
	hash     []byte
	neighbor *MerkleNode
	left     *MerkleNode
	right    *MerkleNode
	poi      ProofOfInclusion
	sth      gossip.Gossip_object
	rid      RevocationID
}

func buildMerkleTreeFromCerts(certs []x509.Certificate, config LoggerConfig, periodNum int) MerkleNode {
	n := len(certs)
	nodes := make([]MerkleNode, n)
	for i := 0; i < n; i++ {
		certBytes, _ := json.Marshal(certs[i])
		nodes[i] = MerkleNode{hash: hash(certBytes), rid: RevocationID(i)}
	}
	if len(nodes)%2 == 1 {
		certBytes, _ := json.Marshal(certs[n-1])
		nodes = append(nodes, MerkleNode{hash: hash(certBytes), rid: RevocationID(n - 1)})
	}
	root := recursiveBuildMerkleTree(nodes)
	STH1 := STH{
		Timestamp: gossip.GetCurrentTimestamp(),
		RootHash:  string(root.hash),
		TreeSize:  n,
	}
	payload0 := string(config.Signer)
	sth_payload, _ := json.Marshal(STH1)
	payload1 := string(sth_payload)
	payload2 := ""
	signature, _ := crypto.RSASign([]byte(payload0+payload1+payload2), &config.Private, crypto.CTngID(config.Signer))
	gossipSTH := gossip.Gossip_object{
		Application:   "CTng",
		Type:          gossip.STH,
		Period:        strconv.Itoa(periodNum),
		Signer:        string(config.Signer),
		Timestamp:     STH1.Timestamp,
		Signature:     [2]string{signature.String(), ""},
		Crypto_Scheme: "RSA",
		Payload:       [3]string{payload0, payload1, payload2},
	}
	addPOIAndSTH(root, make([][]byte, 0), gossipSTH)
	return root
}

func buildMerkleTreeFromBytes(dataBlocks [][]byte, config LoggerConfig, periodNum int) MerkleNode {
	n := len(dataBlocks)
	nodes := make([]MerkleNode, n)
	for i := 0; i < n; i++ {
		nodes[i] = MerkleNode{hash: hash(dataBlocks[i]), rid: RevocationID(i)}
	}
	if len(nodes)%2 == 1 {
		nodes = append(nodes, MerkleNode{hash: hash(dataBlocks[n-1]), rid: RevocationID(n - 1)})
	}
	root := recursiveBuildMerkleTree(nodes)
	STH1 := STH{
		Timestamp: gossip.GetCurrentTimestamp(),
		RootHash:  string(root.hash),
		TreeSize:  n,
	}
	payload0 := string(config.Signer)
	sth_payload, _ := json.Marshal(STH1)
	payload1 := string(sth_payload)
	payload2 := ""
	signature, _ := crypto.RSASign([]byte(payload0+payload1+payload2), &config.Private, crypto.CTngID(config.Signer))
	gossipSTH := gossip.Gossip_object{
		Application:   "CTng",
		Type:          gossip.STH,
		Period:        strconv.Itoa(periodNum),
		Signer:        string(config.Signer),
		Timestamp:     STH1.Timestamp,
		Signature:     [2]string{signature.String(), ""},
		Crypto_Scheme: "RSA",
		Payload:       [3]string{payload0, payload1, payload2},
	}
	addPOIAndSTH(root, make([][]byte, 0), gossipSTH)
	return root
}

func hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func addPOIAndSTH(node MerkleNode, siblingHashes [][]byte, sth gossip.Gossip_object) {
	if node.left == nil && node.right == nil {
		node.poi = ProofOfInclusion{siblingHashes: siblingHashes}
		node.sth = sth
		return
	}
	if node.neighbor != nil {
		siblingHashes = append(siblingHashes, node.neighbor.hash)
	}
	addPOIAndSTH(*node.left, siblingHashes, sth)
	addPOIAndSTH(*node.right, siblingHashes, sth)
}

func recursiveBuildMerkleTree(nodes []MerkleNode) MerkleNode {
	n := len(nodes)
	if n%2 == 1 {
		nodes = append(nodes, MerkleNode{
			left:     nodes[n-1].left,
			right:    nodes[n-1].right,
			neighbor: nodes[n-1].neighbor,
			hash:     nodes[n-1].hash,
		})
	}
	mid := len(nodes) / 2
	if len(nodes) <= 2 {
		return MerkleNode{
			left:  &nodes[0],
			right: &nodes[1],
			hash:  hash(append(nodes[0].hash, nodes[1].hash...)),
		}
	}
	left := recursiveBuildMerkleTree(nodes[:mid])
	right := recursiveBuildMerkleTree(nodes[mid:])
	left.neighbor = &right
	right.neighbor = &left
	hash := hash(append(nodes[0].hash, nodes[1].hash...))
	return MerkleNode{left: &left, right: &right, hash: hash}
}
