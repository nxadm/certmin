package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRetrieveCerts(t *testing.T) {
	certs, err := retrieveCerts("foo", "faa")
	assert.Nil(t, certs)
	assert.Error(t, err)
	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err = retrieveCerts("tcp", "github.com:443")
		assert.NoError(t, err)
		assert.True(t, len(certs) > 0)
	}
}

func TestRetrieveRemotes(t *testing.T) {
	if os.Getenv("AUTHOR_TESTING") == "" {
		t.SkipNow()
	}
	certs, err := retrieveRemotes([]string{"github.com", "github.com:443"}, "tcp", true)
	assert.NotNil(t, certs)
	assert.Error(t, err)

	certs, err = retrieveRemotes([]string{"github.com:443", "github.io:443"}, "tcp", true)
	assert.NotNil(t, certs)
	assert.Nil(t, err)

}

//func retrieveRemotes(certLocs []string, network string, remoteChain bool) ([]*x509.Certificate, error) {
