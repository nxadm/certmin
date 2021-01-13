package main

//import (
//	"crypto/x509"
//	"os"
//	"strings"
//	"testing"
//
//	"github.com/stretchr/testify/assert"
//)
//
//var (
//	testSerials = []string{
//		"1",
//		"76359301477803385872276235234032301461",
//		"290123421899608141648701916708796095456",
//	}
//)
//
//func TestSkimCerts(t *testing.T) {
//	output := skimCerts([]string{"t/myserver.crt"}, "", false)
//	assert.Regexp(t, "Subject:\\s+CN=myserver", output)
//
//	if os.Getenv("AUTHOR_TESTING") != "" {
//		output = skimCerts([]string{"github.com:443"}, "tcp", false)
//		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
//	}
//}
//
//func TestSplitMultiCertFile(t *testing.T) {
//	certs, err := splitMultiCertFile("t/chain.crt")
//	assert.NoError(t, err)
//	for idx, serial := range testSerials {
//		assert.Equal(t, serial, certs[idx].SerialNumber.String())
//	}
//
//	_, err = splitMultiCertFile("t/chain-invalid-extra-nl.crt")
//	assert.NoError(t, err)
//
//	_, err = splitMultiCertFile("t/empty.crt")
//	assert.Error(t, err)
//	_, err = splitMultiCertFile("/dev/null")
//	assert.Error(t, err)
//	_, err = splitMultiCertFile(strings.Join(testSerials, ""))
//	assert.Error(t, err)
//}
//
//func TestVerifyChain(t *testing.T) {
//	ca, err := splitMultiCertFile("t/ca.crt")
//	assert.NoError(t, err)
//	cert, err := splitMultiCertFile("t/myserver.crt")
//	assert.NoError(t, err)
//	assert.True(t, verifyChain([]*x509.Certificate{ca[0]}, nil, cert[0]))
//	cert, err = splitMultiCertFile("t/myserver-fromca2.crt")
//	assert.False(t, verifyChain([]*x509.Certificate{ca[0]}, nil, cert[0]))
//}
//
//func TestVerifyChainFromLoc(t *testing.T) {
//	assert.True(t, verifyChainFromLoc(
//		[]string{"t/ca.crt"}, nil, "t/myserver.crt", "", false))
//	assert.False(t, verifyChainFromLoc(nil, nil, "", "", false))
//	assert.False(t, verifyChainFromLoc(
//		[]string{"t/empty.crt"}, nil, "t/myserver.crt", "", false))
//	assert.False(t, verifyChainFromLoc(
//		[]string{"t/ca.crt"}, nil, "t/chain.crt", "", false))
//	assert.False(t, verifyChainFromLoc(
//		[]string{"t/ca.crt"}, nil, "t/myserver-fromca2.crt", "", false))
//
//	if os.Getenv("AUTHOR_TESTING") != "" {
//		assert.True(t, verifyChainFromLoc(
//			nil, nil, "github.com:443", "tcp", true))
//	}
//}
//
//func TestVerifyKey(t *testing.T) {
//	assert.True(t, verifyKey("t/myserver.crt", "t/myserver.key", ""))
//	assert.False(t, verifyKey("t/myserver.crt", "t/myserver-fromca2.key", ""))
//}
