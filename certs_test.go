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

func TestSkimCerts(t *testing.T) {
	output, err := skimCerts([]string{"t/myserver.crt"}, false)
	assert.Regexp(t, "Subject:\\s+CN=myserver", output)
	assert.Nil(t, err)

	_, err = skimCerts([]string{"main.go"}, false)
	assert.NotNil(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		output, err = skimCerts([]string{"https://github.com"}, false)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com:443"}, false)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com"}, false)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com"}, true)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)
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

func TestVerifyChain(t *testing.T) {
	ca, err := splitMultiCertFile("t/ca.crt")
	assert.NoError(t, err)
	cert, err := splitMultiCertFile("t/myserver.crt")
	assert.NoError(t, err)
	verified, err := verifyChain([]*x509.Certificate{ca[0]}, nil, cert[0])
	assert.True(t, verified)
	assert.Nil(t, err)
	cert, err = splitMultiCertFile("t/myserver-fromca2.crt")
	assert.Nil(t, err)
	verified, err = verifyChain([]*x509.Certificate{ca[0]}, nil, cert[0])
	assert.False(t, verified)
	assert.Nil(t, err)
}

func TestVerifyChainFromLoc(t *testing.T) {
	verified, err := verifyChainFromLoc(
		[]string{"t/ca.crt"}, nil, "t/myserver.crt", false)
	assert.True(t, verified)
	assert.Nil(t, err)
	//assert.False(t, verifyChainFromLoc(nil, nil, "", "", false))
	//assert.False(t, verifyChainFromLoc(
	//	[]string{"t/empty.crt"}, nil, "t/myserver.crt", "", false))
	//assert.False(t, verifyChainFromLoc(
	//	[]string{"t/ca.crt"}, nil, "t/chain.crt", "", false))
	//assert.False(t, verifyChainFromLoc(
	//	[]string{"t/ca.crt"}, nil, "t/myserver-fromca2.crt", "", false))

	//if os.Getenv("AUTHOR_TESTING") != "" {
	//	assert.True(t, verifyChainFromLoc(
	//		nil, nil, "github.com:443", "tcp", true))
	//}
}
//
//func TestVerifyKey(t *testing.T) {
//	assert.True(t, verifyKey("t/myserver.crt", "t/myserver.key", ""))
//	assert.False(t, verifyKey("t/myserver.crt", "t/myserver-fromca2.key", ""))
//}
