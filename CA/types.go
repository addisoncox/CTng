package CA

import (
	"CTng/config"
	//"CTng/crypto"
	"CTng/gossip"
	"net/http"
	"github.com/Workiva/go-datastructures/bitarray"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"encoding/pem"
)

type CAContext struct {
	Config            *config.CA_config
	SRHs              []gossip.Gossip_object
	Revocators        []*Revocator           // array of all the CRV's
	Certificates      *CertPool       //pool of all the certificates the CA generated
	IssuerCertificate x509.Certificate       // the certificate that the ca can sign on pther certifiactes with
	Request_Count     int
	Current_Period    int
	Client            *http.Client
}

type Place struct {
	Vector int
	Index  int
}

type Revocator interface {
	GetRevInfo() bitarray.BitArray                                 // returns current updated revocation information (newest CRV)
	RevokeCertificate(crt *x509.Certificate)                       // set the recieved certificate as revoked
	IsRevoked(crt *x509.Certificate) (bool, error)                 //
	GetDelta() bitarray.BitArray                                   // returns the current delta vector
	CalculateChanges(deltaVec bitarray.BitArray) bitarray.BitArray // gets delta vector and returns the new vector
	UpdateChanges(deltaVec bitarray.BitArray)                      // gets delta vector and updates the current vector with it
	UpdateCASign(sign tls.DigitallySigned)                         // gets CA signature on the vector????????
	UpdateLoggerSign(sign tls.DigitallySigned)                     // gets Logger signature on the vector and saves it
	GetDeltaVector() bitarray.BitArray
	GetVector() bitarray.BitArray
}

type Revocation struct {
	Signer       string
	Delta_CRV    [][]byte
	Vectors_Hash []byte
	Timestamp    string
	Period       int
}

type CertPool struct {
	bySubjectKeyId map[string][]int
	byName         map[string][]int
	certs          []*x509.Certificate
}

func (s *CertPool) GetSizeOfCertPool() uint64 {
	return uint64(len(s.certs))
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool() *CertPool {
	return &CertPool{
		bySubjectKeyId: make(map[string][]int),
		byName:         make(map[string][]int),
	}
}

func (s *CertPool) copy() *CertPool {
	p := &CertPool{
		bySubjectKeyId: make(map[string][]int, len(s.bySubjectKeyId)),
		byName:         make(map[string][]int, len(s.byName)),
		certs:          make([]*x509.Certificate, len(s.certs)),
	}
	for k, v := range s.bySubjectKeyId {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.bySubjectKeyId[k] = indexes
	}
	for k, v := range s.byName {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.byName[k] = indexes
	}
	copy(p.certs, s.certs)
	return p
}

// findPotentialParents returns the indexes of certificates in s which might
// have signed cert. The caller must not modify the returned slice.
func (s *CertPool) findPotentialParents(cert *x509.Certificate) []int {
	if s == nil {
		return nil
	}

	var candidates []int
	if len(cert.AuthorityKeyId) > 0 {
		candidates = s.bySubjectKeyId[string(cert.AuthorityKeyId)]
	}
	if len(candidates) == 0 {
		candidates = s.byName[cert.Issuer.CommonName]
	}
	return candidates
}

func (s *CertPool) Contains(cert *x509.Certificate) bool {
	if s == nil {
		return false
	}

	candidates := s.byName[cert.Subject.CommonName]
	for _, c := range candidates {
		if s.certs[c].Equal(cert) {
			return true
		}
	}

	return false
}

// AddCert adds a certificate to a pool.
func (s *CertPool) AddCert(cert *x509.Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertPool")
	}

	// Check that the certificate isn't being added twice.
	if s.Contains(cert) {
		return
	}

	n := len(s.certs)
	s.certs = append(s.certs, cert)

	if len(cert.SubjectKeyId) > 0 {
		keyId := string(cert.SubjectKeyId)
		s.bySubjectKeyId[keyId] = append(s.bySubjectKeyId[keyId], n)
	}
	name := cert.Subject.CommonName
	s.byName[name] = append(s.byName[name], n)
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (s *CertPool) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if x509.IsFatal(err) {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
func (s *CertPool) Subjects() []string {
	res := make([]string, len(s.certs))
	for i, c := range s.certs {
		res[i] = c.Subject.CommonName
	}
	return res
}

// find the first cert for this subject in the cert pool
func (s *CertPool) GetCertByName(subjectName string) *x509.Certificate {
	// check if exist certificate for this subject in the cert pool
	index, isPresent := s.byName[subjectName]
	if isPresent {
		return s.certs[index[0]]
	} else {
		return nil
	}
}