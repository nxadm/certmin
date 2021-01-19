package certmin

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

//
//import (
//	"os"
//	"strings"
//	"testing"
//
//	"github.com/stretchr/testify/assert"
//)
//
var (
	testSerials = []string{
		"1",
		"76359301477803385872276235234032301461",
		"290123421899608141648701916708796095456",
	}
)

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
func TestIsRootCA(t *testing.T) {
	certs, err := DecodeCertFile("t/myserver.crt")
	assert.Nil(t, err)
	assert.False(t, IsRootCA(certs[0]))

	certs, err = DecodeCertFile("t/ca.crt")
	assert.Nil(t, err)
	assert.True(t, IsRootCA(certs[0]))
}

//
//func TestOrderRemoteChain(t *testing.T) {
//	certs, err := splitMultiCertFile("t/chain-out-of-order.crt")
//	assert.NotNil(t, certs)
//	assert.NoError(t, err)
//	ordered := orderRemoteChain(certs)
//	assert.NotNil(t, ordered)
//}
//

func TestDecodeCertBytes(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/chain.crt")
	assert.NoError(t, err)
	certs, err := DecodeCertBytes(certBytes)
	assert.NoError(t, err)
	for idx, serial := range testSerials {
		assert.Equal(t, serial, certs[idx].SerialNumber.String())
	}

	certBytes, err = ioutil.ReadFile("t/chain-invalid-extra-nl.crt")
	assert.NoError(t, err)
	_, err = DecodeCertBytes(certBytes)
	assert.NoError(t, err)

	certBytes, err = ioutil.ReadFile("t/empty.crt")
	assert.NoError(t, err)
	_, err = DecodeCertBytes(certBytes)
	assert.Error(t, err)

	_, err = DecodeCertBytes(nil)
	assert.Error(t, err)
}

func TestDecodeCertFile(t *testing.T) {
	certs, err := DecodeCertFile("t/chain.crt")
	assert.NoError(t, err)
	for idx, serial := range testSerials {
		assert.Equal(t, serial, certs[idx].SerialNumber.String())
	}

	_, err = DecodeCertFile("t/chain-invalid-extra-nl.crt")
	assert.NoError(t, err)

	_, err = DecodeCertFile("t/empty.crt")
	assert.Error(t, err)
	_, err = DecodeCertFile("/dev/null")
	assert.Error(t, err)
	_, err = DecodeCertFile(strings.Join(testSerials, ""))
	assert.Error(t, err)
}

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
