package testserver

import (
	"github.com/nipuntalukdar/bitset"
	"net/http"
)
type TestServerContext struct {
	Client            *http.Client
	CRVsize           int
	CRV               bitset.Bitset
}