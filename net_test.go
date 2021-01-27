package certmin

import (
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ExampleRetrieveCertsFromAddr() {
	certs, warn, err := RetrieveCertsFromAddr("github.com:443", 1*time.Second)
	if warn != nil {
		// The certificates can be retrieved, but an TLS error was found
		// like an expired certificate or a server name mismatch.
		fmt.Printf("warning: %s\n", warn)
	}

	if err != nil {
		// The certicate can no be retrieved, e.g. because of a DNS or networking error.
		fmt.Printf("warning: %s\n", err)
	} else {
		// certs holds all the certificates sent by the remote server,
		// i.e. the chain. In this example, the CN of the first certificate
		// is printed. This is safe because an error is returned if no
		// certificates were retrieved).
		fmt.Printf("CN: %s\n", certs[0].Subject.CommonName)
	}
}

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
	certs, err := DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	// No Issuer URL
	chain, err := RetrieveChainFromIssuerURLs(certs[0], 1*time.Second)
	assert.NoError(t, err)
	assert.Equal(t, []*x509.Certificate{certs[0]}, chain)

	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err := DecodeCertFile("t/kuleuven-be.pem", "")
		assert.NoError(t, err)
		chain, err := RetrieveChainFromIssuerURLs(certs[0], 5*time.Second)
		assert.NoError(t, err)
		assert.True(t, len(chain) >= 2)
	}
}

func TestConnectAndRetrieve(t *testing.T) {
	if os.Getenv("AUTHOR_TESTING") != "" {
		if os.Getenv("AUTHOR_TESTING") != "" {
			certs, err := connectAndRetrieve("github.com:443", 5*time.Second, false)
			assert.NoError(t, err)
			assert.True(t, len(certs) >= 2)
		}
	}
}

func TestRecursiveHopCerts(t *testing.T) {
	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err := DecodeCertFile("t/kuleuven-be.pem", "")
		assert.NoError(t, err)
		var chain []*x509.Certificate
		var lastErr error
		recursiveHopCerts(certs[0], &chain, &lastErr, 5*time.Second)
		leftOver := recursiveHopCerts(certs[0], &chain, &lastErr, 5*time.Second)
		assert.Nil(t, leftOver)
		assert.True(t, len(chain) >= 2)
	}
}
