package main

import (
	"crypto/x509"
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

func TestSkimCerts(t *testing.T) {
	assert.NotPanics(t, func() { skimCerts([]string{}) })
}

func TestVerifyCertAndKey(t *testing.T) {
	assert.True(t, verifyCertAndKey("t/myserver.crt", "t/myserver.key"))
	assert.False(t, verifyCertAndKey("t/myserver.crt", "t/myserver-fromca2.key"))
}

//func verifyChainFromFiles(rootFiles, intermediateFiles []string, certFile string) {
func TestVerifyChainFromFiles(t *testing.T) {
	assert.True(t, verifyChainFromFiles([]string{"t/ca.crt"}, nil, "t/myserver.crt"))
	assert.False(t, verifyChainFromFiles(nil, nil, ""))
	assert.False(t, verifyChainFromFiles([]string{"t/empty.crt"}, nil, "t/myserver.crt"))
	assert.False(t, verifyChainFromFiles([]string{"t/ca.crt"}, nil, "t/chain.crt"))
	assert.False(t, verifyChainFromFiles([]string{"t/ca.crt"}, nil, "t/myserver-fromca2.crt"))
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
	_, err = splitMultiCertFile("t/empty.crt")
	assert.Error(t, err)
}

func TestVerifyChain(t *testing.T) {
	ca, err := splitMultiCertFile("t/ca.crt")
	assert.NoError(t, err)
	cert, err := splitMultiCertFile("t/myserver.crt")
	assert.NoError(t, err)
	assert.True(t, verifyChain([]*x509.Certificate{ca[0]}, nil, cert[0]))
	cert2, err := splitMultiCertFile("t/myserver-fromca2.crt")
	assert.False(t, verifyChain([]*x509.Certificate{ca[0]}, nil, cert2[0]))
}
