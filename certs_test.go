package certmin

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"strings"
	"testing"
)

var (
	testGeantSerial = "290123421899608141648701916708796095456"
	testSerials     = []string{
		"1",
		"76359301477803385872276235234032301461",
		"290123421899608141648701916708796095456",
	}
)

func TestEncodeCertAsPEMBytes(t *testing.T) {
	certs, err := DecodeCertFile("t/myserver.crt")
	assert.NoError(t, err)
	assert.True(t, len(certs) > 0)
	bytes, err := EncodeCertAsPEMBytes(certs[0])
	assert.Contains(t, string(bytes), "-BEGIN CERTIFICATE-")
}

func TestIsRootCA(t *testing.T) {
	certs, err := DecodeCertFile("t/myserver.crt")
	assert.NoError(t, err)
	assert.False(t, IsRootCA(certs[0]))

	certs, err = DecodeCertFile("t/ca.crt")
	assert.Nil(t, err)
	assert.True(t, IsRootCA(certs[0]))
}

func TestSortCerts(t *testing.T) {
	certs, err := DecodeCertFile("t/chain-out-of-order.crt")
	assert.NotNil(t, certs)
	assert.NoError(t, err)

	ordered := SortCerts(certs, false)
	assert.NotNil(t, ordered)
	assert.Equal(t, 7, len(ordered))
	assert.Equal(t, testGeantSerial, ordered[1].SerialNumber.String())

	ordered = SortCerts(certs, true)
	assert.NotNil(t, ordered)
	assert.Equal(t, 7, len(ordered))
	assert.Equal(t, testGeantSerial, ordered[len(ordered)-2].SerialNumber.String())
}

func TestSplitCertsAsTree(t *testing.T) {
	certs, err := DecodeCertFile("t/chain-out-of-order.crt")
	assert.NotNil(t, certs)
	assert.NoError(t, err)

	tree := SplitCertsAsTree(certs)
	assert.NotNil(t, tree)
	assert.Contains(t, tree.Certificate.Subject.CommonName, "exporl")
	assert.Equal(t, 5, len(tree.Intermediates))
	assert.Equal(t, 1, len(tree.Roots))
}

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

	// DER
	certBytes, err = ioutil.ReadFile("t/GEANTOVRSACA4.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytes(certBytes)
	assert.NoError(t, err)
	if assert.NotNil(t, certs) {
		assert.Equal(t, testGeantSerial, certs[0].SerialNumber.String())
	}
}

func TestDecodeCertFile(t *testing.T) {
	certs, err := DecodeCertFile("t/chain.crt")
	assert.NoError(t, err)
	for idx, serial := range testSerials {
		assert.Equal(t, serial, certs[idx].SerialNumber.String())
	}

	// DER
	certs, err = DecodeCertFile("t/GEANTOVRSACA4.crt")
	assert.NoError(t, err)
	if assert.True(t, len(certs) == 1) {
		assert.Equal(t, testGeantSerial, certs[0].SerialNumber.String())
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
