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
	// Other formats are allowed like github.com:8443 or smtps://smtp.gmail.com
	certs, warn, err := RetrieveCertsFromAddr("github.com", 1*time.Second)
	if err != nil {
		// The certificates can no be retrieved
		// (e.g. because of a DNS or networking error).
		fmt.Printf("error: %s\n", err)
		return
	}

	if warn != nil {
		// The certificates can be retrieved, but a TLS error was found
		// (e.g. an expired certificate or a server name mismatch).
		fmt.Printf("warning: %s\n", warn)
	}

	// certs holds all the certificates sent by the remote server,
	// i.e. the chain. In this example, the CN of the first certificate
	// is printed. This is safe because an error is returned if no
	// certificates were retrieved).
	fmt.Printf("CN: %s\n", certs[0].Subject.CommonName)
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

func ExampleRetrieveChainFromIssuerURLs() {
	// Retrieve a *x509.Certificate, e.g. locally:
	certs, err := DecodeCertFile("t/myserver.crt", "")
	if err != nil {
		return
	}

	// Get the remote chain by recursive following the Issuer URLs.
	chain, err := RetrieveChainFromIssuerURLs(certs[0], 1*time.Second)
	if err != nil {
		return
	}

	// Print, by example, the length of the retrieved chain
	fmt.Printf("the chain has %d certificates\n", len(chain))
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

func TestParseURL(t *testing.T) {
	remote, err := parseURL("https://foo")
	assert.Equal(t, "foo:443", remote)
	assert.Nil(t, err)

	remote, err = parseURL("ldaps://foo")
	assert.Equal(t, "foo:636", remote)
	assert.Nil(t, err)

	remote, err = parseURL("foo://foo")
	assert.Equal(t, "foo:443", remote)
	assert.Nil(t, err)

	remote, err = parseURL("https://foo:123")
	assert.Equal(t, "foo:123", remote)
	assert.Nil(t, err)

	remote, err = parseURL("foo://foo:123")
	assert.Equal(t, "foo:123", remote)
	assert.Nil(t, err)

	remote, err = parseURL("BLAH:123")
	assert.Equal(t, "BLAH:123", remote)
	assert.Nil(t, err)

	remote, err = parseURL("BLAH/BOE")
	assert.Equal(t, "BLAH:443", remote)
	assert.Nil(t, err)

	_, err = parseURL("foo://foo:1AA23")
	assert.NotNil(t, err)
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
