package certmin

//
//import (
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
//func TestGetCertificates(t *testing.T) {
//	certs, remote, err := getCertificates("t/myserver.crt", false, false)
//	assert.NotEmpty(t, certs)
//	assert.False(t, remote)
//	assert.NoError(t, err)
//
//	if os.Getenv("AUTHOR_TESTING") != "" {
//		certs, remote, err = getCertificates("github.com", false, false)
//		assert.NotEmpty(t, certs)
//		assert.True(t, remote)
//		assert.NoError(t, err)
//	}
//}
//
//func TestIsRootCA(t *testing.T) {
//	certs, err := splitMultiCertFile("t/myserver.crt")
//	assert.Nil(t, err)
//	assert.False(t, isRootCA(certs[0]))
//
//	certs, err = splitMultiCertFile("t/ca.crt")
//	assert.Nil(t, err)
//	assert.True(t, isRootCA(certs[0]))
//}
//
//func TestOrderRemoteChain(t *testing.T) {
//	certs, err := splitMultiCertFile("t/chain-out-of-order.crt")
//	assert.NotNil(t, certs)
//	assert.NoError(t, err)
//	ordered := orderRemoteChain(certs)
//	assert.NotNil(t, ordered)
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
//func TestVerifyChainFromX509(t *testing.T) {
//	ca, err := splitMultiCertFile("t/ca.crt")
//	assert.NoError(t, err)
//	cert, err := splitMultiCertFile("t/myserver.crt")
//	assert.NoError(t, err)
//	verified, output := verifyChainFromX509(ca, nil, cert[0])
//	assert.NoError(t, err)
//	assert.Equal(t, "", output)
//
//	cert, err = splitMultiCertFile("t/myserver-fromca2.crt")
//	assert.NoError(t, err)
//	verified, output = verifyChainFromX509(ca, nil, cert[0])
//	assert.False(t, verified)
//	assert.NotEqual(t, "", output)
//}
