package logger

import(
	"fmt"
	"github.com/google/certificate-transparency-go/x509"
	//"CTng/crypto"
	//"math"

)
type Merkle_tree struct{
	RootHash []byte
	Treesize int
	Tree map[int][][]byte
}

type Precertstorage struct{
	Map_precerts map[string][]x509.Certificate
	//and the end of each MMD, we flatten the map the slice and build the merkle tree on it
	Slice_precerts []x509.Certificate
	Merkletree Merkle_tree
	NumCA int
}
/*
func (Precerts *Precertstorage) Buildtree(){
	for _, element := range Precerts.Map_precerts{

	}
}
*/

func CreateWildCardCert()x509.Certificate{
	return x509.Certificate{}
}

func (Precerts *Precertstorage) Flatten(){
	for _, element := range Precerts.Map_precerts {
		for _, content := range element {
			Precerts.Slice_precerts = append(Precerts.Slice_precerts,content)
		}
	}
}

/*
func buildmerkletree (precerts []x509.Certificate, Mtree Merkle_tree){
	tree_size := len(precerts)
	tree_level := math.Ceil(math.Log2(treesize))
	for i := 1; i < tree_level; i++ {
		if i == 1{
			for j:=0; j< math.ceil(tree_size/i)
			{
				hashmsg := String(precerts[j])||String(Precerts[k])
				hash, _ := crypto.GenerateSHA256([]byte(hashmsg))
				Mtree.Tree[i] = append(Mtree.Tree[i],Hash)
			}
		}else{
			for j:=0; j< math.ceil(tree_size/i)
			{
				hashmsg := String(precerts[j])||String(Precerts[k])
				hash, _ := crypto.GenerateSHA256([]byte(hashmsg))
			}
		}
		
	}
}*/

func Storage_init(num_CA int) Precertstorage{
	Map_precerts := make(map[string][]x509.Certificate)
	Slice_precerts := make([]x509.Certificate,0,100) 
	new_tree := make(map[int][][]byte)
	roothash := make([]byte,0,100)
	var emptytree = Merkle_tree{
		RootHash: roothash,
		Treesize: 0,
		Tree: new_tree,
	}
	var precertificate_storage = &Precertstorage{
		Map_precerts: Map_precerts,
		Slice_precerts: Slice_precerts,
		Merkletree: emptytree,
		NumCA: num_CA,
	}
	fmt.Println(precertificate_storage.NumCA)
	return *precertificate_storage
}