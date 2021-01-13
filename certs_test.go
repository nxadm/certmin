package main

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testSerials = []string{
		"1",
		"76359301477803385872276235234032301461",
		"290123421899608141648701916708796095456",
	}
)

func TestGetCertificates(t *testing.T) {
	certs, err := getCertificates("t/myserver.crt", false)
	assert.NotEmpty(t, certs)
	assert.NoError(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err = getCertificates("github.com", false)
		assert.NotEmpty(t, certs)
		assert.NoError(t, err)
	}
}

func TestSplitMultiCertFile(t *testing.T) {
	certs, err := splitMultiCertFile("t/chain.crt")
	assert.NoError(t, err)
	for idx, serial := range testSerials {
		assert.Equal(t, serial, certs[idx].SerialNumber.String())
	}

	_, err = splitMultiCertFile("t/chain-invalid-extra-nl.crt")
	assert.NoError(t, err)

	_, err = splitMultiCertFile("t/empty.crt")
	assert.Error(t, err)
	_, err = splitMultiCertFile("/dev/null")
	assert.Error(t, err)
	_, err = splitMultiCertFile(strings.Join(testSerials, ""))
	assert.Error(t, err)
}

func TestVerifyChainFromX509(t *testing.T) {
	ca, err := splitMultiCertFile("t/ca.crt")
	assert.NoError(t, err)
	cert, err := splitMultiCertFile("t/myserver.crt")
	assert.NoError(t, err)
	assert.True(t, verifyChainFromX509([]*x509.Certificate{ca[0]}, nil, cert[0]))
	cert, err = splitMultiCertFile("t/myserver-fromca2.crt")
	assert.NoError(t, err)
	assert.False(t, verifyChainFromX509([]*x509.Certificate{ca[0]}, nil, cert[0]))
}
