package certmin

import (
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetrieveCertsFromAddr(t *testing.T) {
	certs, warn, err := RetrieveCertsFromAddr("faa", 1*time.Second)
	assert.Nil(t, certs)
	assert.NoError(t, warn)
	assert.Error(t, err)

	certs, warn, err = RetrieveCertsFromAddr("faa", 0)
	assert.Nil(t, certs)
	assert.NoError(t, warn)
	assert.Error(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, warn, err = RetrieveCertsFromAddr("github.com:443", 5*time.Second)
		assert.NoError(t, warn)
		assert.NoError(t, err)
		assert.True(t, len(certs) >= 2)

		certs, warn, err = RetrieveCertsFromAddr("8.8.8.8:443", 5*time.Second)
		assert.NoError(t, warn)
		assert.NoError(t, err)
		assert.True(t, len(certs) >= 2)
	}
}

func TestRetrieveChainFromIssuerURLs(t *testing.T) {
	certs, err := DecodeCertFile("t/myserver.crt")
	assert.NoError(t, err)
	// No Issuer URL
	chain, err := RetrieveChainFromIssuerURLs(certs[0], 1*time.Second)
	assert.NoError(t, err)
	assert.Equal(t, []*x509.Certificate{certs[0]}, chain)

	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err := DecodeCertFile("t/kuleuven-be.pem")
		assert.NoError(t, err)
		chain, err := RetrieveChainFromIssuerURLs(certs[0], 5*time.Second)
		assert.NoError(t, err)
		assert.True(t, len(chain) >= 2)
	}
}

func TestRecursiveHopCerts(t *testing.T) {
	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err := DecodeCertFile("t/kuleuven-be.pem")
		assert.NoError(t, err)
		var chain []*x509.Certificate
		var lastErr error
		recursiveHopCerts(certs[0], &chain, &lastErr, 5*time.Second)
		leftOver := recursiveHopCerts(certs[0], &chain, &lastErr, 5*time.Second)
		assert.Nil(t, leftOver)
		assert.True(t, len(chain) >= 2)
	}
}
