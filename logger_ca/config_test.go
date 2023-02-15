package logger_ca


import (
	"CTng/Gen"
	"testing"
)

func TestConfigGeneration(t *testing.T) {
	// Generate the config files for the CAs
	Gen.Generateall(4,2,1,1,7,60,60,"")
}
