package certmin

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testGeantSerial = "290123421899608141648701916708796095456"
	testSerials     = []string{
		"1",
		"76359301477803385872276235234032301461",
		"290123421899608141648701916708796095456",
	}
)

func TestDecodeCertBytes(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/myserver.der")
	assert.NoError(t, err)
	certs, err := DecodeCertBytes(certBytes, "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")

	certBytes, err = ioutil.ReadFile("t/myserver.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytes(certBytes, "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")

	certBytes, err = ioutil.ReadFile("t/myserver.p7c")
	assert.NoError(t, err)
	certs, err = DecodeCertBytes(certBytes, "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")

	certBytes, err = ioutil.ReadFile("t/myserver.p7b")
	assert.NoError(t, err)
	certs, err = DecodeCertBytes(certBytes, "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")

	certBytes, err = ioutil.ReadFile("t/myserver.pfx")
	assert.NoError(t, err)
	certs, err = DecodeCertBytes(certBytes, testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")
}

func TestDecodeCertBytesPKCS1DER(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/myserver.der")
	assert.NoError(t, err)
	certs, err := DecodeCertBytesPKCS1DER(certBytes)
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")
}

func TestDecodeCertBytesPKCS1PEM(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/myserver.crt")
	assert.NoError(t, err)
	certs, err := DecodeCertBytesPKCS1PEM(certBytes)
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")
}

func TestDecodeCertBytesPKCS7DER(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/myserver.p7c")
	assert.NoError(t, err)
	certs, err := DecodeCertBytesPKCS7DER(certBytes)
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")
}

func TestDecodeCertBytesPKCS7PEM(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/myserver.p7b")
	assert.NoError(t, err)
	certs, err := DecodeCertBytesPKCS7PEM(certBytes)
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")
}

func TestDecodeCertBytesPKCS12(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/myserver.pfx")
	assert.NoError(t, err)
	certs, err := DecodeCertBytesPKCS12(certBytes, testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")
}

func TestDecodeCertFile(t *testing.T) {
	certs, err := DecodeCertFile("t/chain.crt", "")
	assert.NoError(t, err)
	for idx, serial := range testSerials {
		assert.Equal(t, serial, certs[idx].SerialNumber.String())
	}

	// DER
	certs, err = DecodeCertFile("t/GEANTOVRSACA4.crt", "")
	assert.NoError(t, err)
	if assert.True(t, len(certs) == 1) {
		assert.Equal(t, testGeantSerial, certs[0].SerialNumber.String())
	}

	_, err = DecodeCertFile("t/chain-invalid-extra-nl.crt", "")
	assert.NoError(t, err)

	_, err = DecodeCertFile("t/empty.crt", "")
	assert.Error(t, err)
	_, err = DecodeCertFile("/dev/null", "")
	assert.Error(t, err)
	_, err = DecodeCertFile(strings.Join(testSerials, ""), "")
	assert.Error(t, err)

	// PCKS12 with passsword
	certs, err = DecodeCertFile("t/myserver.pfx", testPassword)
	assert.NoError(t, err)
	assert.Contains(t, certs[0].Subject.CommonName, "myserver")
}
