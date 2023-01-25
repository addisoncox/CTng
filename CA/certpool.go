package CA

// This is a fork of x509.Certificate Transparency go/x509/cert_pool.go
// The original file is licensed under the BSD 3-Clause License


import (
	"CTng/gossip"
	"encoding/pem"
	"encoding/json"
	"crypto/x509"
)

// CertPool is a set of certificates.
type CertPool struct {
	bySubjectKeyId map[string][]int
	byName         map[string][]int
	certs          []*x509.Certificate
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
		candidates = s.byName[string(cert.RawIssuer)]
	}
	return candidates
}

func (s *CertPool) contains(cert *x509.Certificate) bool {
	if s == nil {
		return false
	}

	candidates := s.byName[string(cert.RawSubject)]
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
		panic("adding nil x509.Certificate to CertPool")
	}

	// Check that the certificate isn't being added twice.
	if s.contains(cert) {
		return
	}

	n := len(s.certs)
	s.certs = append(s.certs, cert)

	if len(cert.SubjectKeyId) > 0 {
		keyId := string(cert.SubjectKeyId)
		s.bySubjectKeyId[keyId] = append(s.bySubjectKeyId[keyId], n)
	}
	name := string(cert.RawSubject)
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
		if err != nil {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
func (s *CertPool) Subjects() [][]byte {
	res := make([][]byte, len(s.certs))
	for i, c := range s.certs {
		res[i] = c.RawSubject
	}
	return res
}

// Get a Cerificate from the pool by its subjectkeyid
func (s *CertPool) GetCertBySubjectKeyID(subjectKeyId string) *x509.Certificate{
	if s == nil {
		return nil
	}

	candidates := s.bySubjectKeyId[subjectKeyId]
	if len(candidates) == 0 {
		return nil
	}

	return s.certs[candidates[0]]
}


func (c *CertPool) GetLength() int {
	return len(c.certs)
}
// Update one certificate in the pool by its subjectkeyid
func (s *CertPool) UpdateCertBySubjectKeyID(subjectKeyId string, cert *x509.Certificate) {
	if s == nil {
		return
	}

	candidates := s.bySubjectKeyId[subjectKeyId]
	if len(candidates) == 0 {
		return
	}

	s.certs[candidates[0]] = cert
}



// Update all certificates in the pool by their LID
func (s *CertPool) UpdateCertsByLID(lid string, sth gossip.Gossip_object) {
	if s == nil {
		return
	}
	for _, cert := range s.certs {
		// iterate over all Ctng extensions in CRLdistributionPoints
		for _, ext := range cert.CRLDistributionPoints {
			// Unmarshal the CTng extension 
			var ctngext CTngExtension
			//convert ext to []byte
			err := json.Unmarshal([]byte(ext), &ctngext)
			if err != nil {
				continue
			}
			// if the extension has the same LID as the one we are looking for
			if ctngext.STH.Signer == lid {
				// update the extension
				ctngext.STH = sth
			}
			// convert the extension back to string
			extension_bytes, err := json.Marshal(ctngext)
			if err != nil {
				continue
			}
			ext = string(extension_bytes)	

		}
	}
}