package merkle

import (
	"CTng/Logger"
	"testing"

	"github.com/google/certificate-transparency-go/x509"
)

func GenerateLoggerConfig() *Logger.LoggerConfig {

	loggerConfig := Logger.GenerateLoggerConfig()
	loggerConfig.CAs = make(map[string]string)
	loggerConfig.CAs["CA 1"] = "localhost:9000"
	loggerConfig.CAs["CA 2"] = "localhost:9001"
	return loggerConfig
}

func TestBuildMerkleTreeFromCerts(t *testing.T) {
	certs := make([]x509.Certificate, 0)
	for i := 0; i < 10; i++ {
		certs = append(certs, x509.Certificate{})
	}
	periodNum := 0
	config := GenerateLoggerConfig()
	buildMerkleTreeFromCerts(certs, *config, periodNum)
}
