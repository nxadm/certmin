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
	assert.NotNil(t, certs)
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

	certBytes, err = ioutil.ReadFile("t/myserver.der")
	assert.NoError(t, err)
	certs, err = DecodeCertBytes(certBytes)
	assert.NoError(t, err)
	if assert.NotNil(t, certs) {
		assert.Equal(t, "myserver", certs[0].Subject.CommonName)
	}


	// PKCS7
	certBytes, err = ioutil.ReadFile("t/dstrootcax3.p7c")
	assert.NoError(t, err)
	certs, err = DecodeCertBytes(certBytes)
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	//if assert.NotNil(t, certs) {
	//	assert.Equal(t, testGeantSerial, certs[0].SerialNumber.String())
	//}	certBytes, err = ioutil.ReadFile("t/dstrootcax3.p7c")
	//	assert.NoError(t, err)
	//	_, err = DecodeCertBytes(certBytes)
	//	assert.NoError(t, err)
	//	//if assert.NotNil(t, certs) {
	//	//	assert.Equal(t, testGeantSerial, certs[0].SerialNumber.String())
	//	//}
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

func TestVerifyChain(t *testing.T) {
	ca, err := DecodeCertFile("t/ca.crt")
	assert.NoError(t, err)
	certs, err := DecodeCertFile("t/myserver.crt")
	assert.NoError(t, err)
	verified, output := VerifyChain(&CertTree{
		Certificate: certs[0],
		Roots:       ca,
	})
	assert.Equal(t, "", output)

	certs, err = DecodeCertFile("t/myserver-fromca2.crt")
	assert.NoError(t, err)
	verified, output = VerifyChain(&CertTree{
		Certificate: certs[0],
		Roots:       ca,
	})
	assert.False(t, verified)
	assert.NotEqual(t, "", output)
}

//func TestVerifyKey(t *testing.T) {
//	output, err := verifyKey("t/myserver.crt", "t/myserver.key", nil)
//	assert.Contains(t, output, "the certificate and key match")
//	assert.Nil(t, err)
//
//	output, err = verifyKey("t/myserver.crt", "t/myserver-fromca2.key", nil)
//	assert.Contains(t, output, "the certificate and key do not match")
//	assert.Nil(t, err)
//
//	// rsa
//	output, err = verifyKey("t/myserver.crt", "t/myserver_enc.key", testPasswordBytes)
//	assert.Contains(t, output, "the certificate and key match")
//	assert.Nil(t, err)
//
//	// ec
//	output, err = verifyKey("t/ecdsa_prime256v1.crt", "t/ecdsa_prime256v1.key", nil)
//	assert.Contains(t, output, "the certificate and key match")
//	assert.Nil(t, err)
//
//	output, err = verifyKey("t/ecdsa_prime256v1_2.crt", "t/ecdsa_prime256v1_2_enc.key", testPasswordBytes)
//	assert.Contains(t, output, "the certificate and key match")
//	assert.Nil(t, err)
//
//	//ec with unsupported signature
//	output, err = verifyKey("t/ecdsa_secp384r1.crt", "t/ecdsa_secp384r1.key", nil)
//	assert.Contains(t, output, "the certificate and key match")
//	assert.Nil(t, err)
//
//	output, err = verifyKey("t/ecdsa_secp384r1_2.crt", "t/ecdsa_secp384r1_2_enc.key", testPasswordBytes)
//	assert.Contains(t, output, "the certificate and key match")
//	assert.Nil(t, err)
//
//	// ed22519
//	output, err = verifyKey("t/ed25519.crt", "t/ed25519.key", nil)
//	assert.Contains(t, output, "the certificate and key match")
//	assert.Nil(t, err)
//
//	// TODO: encrypted ed22519, better testfiles
//	//output, err = verifyKey("t/ed25519_2.crt", "t/ed25519_2_enc.key", testPasswordBytes)
//	//assert.Contains(t, output, "the certificate and key match")
//	//assert.Nil(t, err)
//}
