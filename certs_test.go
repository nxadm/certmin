package certmin

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/youmark/pkcs8"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testPassword = "1234"

func TestCertSerialNumberAsHex(t *testing.T) {
	certs, err := DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Equal(t, "ab:4c:df:e9:a2:13:46:9e:6f:ff:36:1d:90:29:5e:be",
		CertSerialNumberAsHex(certs[0].SerialNumber))
}

func TestEncodeCertAsPKCS1PEM(t *testing.T) {
	var certs []*x509.Certificate
	var bytes []byte
	var err error
	certs, err = DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	assert.True(t, len(certs) > 0)
	bytes, err = EncodeCertAsPKCS1PEM(certs[0])
	assert.Contains(t, string(bytes), "-BEGIN CERTIFICATE-")
}

func TestEncodeKeyAsPKCS1PEM(t *testing.T) {
	key, err := DecodeKeyFile("t/myserver.key", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	bytes, err := EncodeKeyAsPKCS1PEM(key)
	assert.Contains(t, string(bytes), "PRIVATE KEY")

	key, err = DecodeKeyFile("t/myserver_enc.key", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	bytes, err = EncodeKeyAsPKCS1PEM(key)
	assert.Contains(t, string(bytes), "PRIVATE KEY")

	key, err = DecodeKeyFile("t/myserver.pfx", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	bytes, err = EncodeKeyAsPKCS1PEM(key)
	assert.Contains(t, string(bytes), "PRIVATE KEY")
}

func TestFindLeaf(t *testing.T) {
	certs, err := DecodeCertFile("t/chain-out-of-order.crt", "")
	assert.NotNil(t, certs)
	assert.NoError(t, err)
	leaf, err := FindLeaf(certs)
	assert.NoError(t, err)
	if assert.NotNil(t, leaf) {
		assert.Contains(t, leaf.Subject.CommonName, "exporl")
	}

	certs, err = DecodeCertFile("t/chain-no-leaf.crt", "")
	assert.NotNil(t, certs)
	assert.NoError(t, err)
	_, err = FindLeaf(certs)
	assert.Error(t, err)

	certs, err = DecodeCertFile("t/chain-2-leaf.crt", "")
	assert.NotNil(t, certs)
	assert.NoError(t, err)
	_, err = FindLeaf(certs)
	assert.Error(t, err)
}

func TestIsRootCA(t *testing.T) {
	certs, err := DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	assert.False(t, IsRootCA(certs[0]))

	certs, err = DecodeCertFile("t/ca.crt", "")
	assert.Nil(t, err)
	assert.True(t, IsRootCA(certs[0]))
}

func TestSortCerts(t *testing.T) {
	certs, err := DecodeCertFile("t/chain-out-of-order.crt", "")
	assert.NotNil(t, certs)
	assert.NoError(t, err)

	ordered := SortCerts(certs, false)
	if assert.NotNil(t, ordered) {
		assert.Equal(t, 7, len(ordered))
		assert.Contains(t, ordered[0].Subject.CommonName, "exporl.med.kuleuven.be")
	}

	ordered = SortCerts(certs, true)
	if assert.NotNil(t, ordered) {
		assert.Equal(t, 7, len(ordered))
		assert.Contains(t, ordered[0].Subject.CommonName, "AAA Certificate Services")
	}
}

func TestSortCertsAsChains(t *testing.T) {
	certs, err := DecodeCertFile("t/chain-out-of-order.crt", "")
	assert.NotNil(t, certs)
	assert.NoError(t, err)
	ordered := SortCerts(certs, false)
	assert.NotNil(t, ordered)

	chainAsCerts, certsByName, order := SortCertsAsChains(certs, false)
	assert.NotNil(t, chainAsCerts)
	assert.NotNil(t, certsByName)
	assert.NotNil(t, order)
	assert.Contains(t, chainAsCerts[ordered[0].Subject.String()][0].Subject.String(), "exporl.med.kuleuven.be")

	chainAsCerts, certsByName, order = SortCertsAsChains(certs, true)
	assert.NotNil(t, chainAsCerts)
	assert.NotNil(t, certsByName)
	assert.NotNil(t, order)
	assert.Contains(t, chainAsCerts[ordered[0].Subject.String()][0].Subject.CommonName, "AAA Certificate Services")
}

func TestSplitCertsAsTree(t *testing.T) {
	certs, err := DecodeCertFile("t/chain-out-of-order.crt", "")
	assert.NotNil(t, certs)
	assert.NoError(t, err)

	tree := SplitCertsAsTree(certs)
	assert.NotNil(t, tree)
	assert.Contains(t, tree.Certificate.Subject.CommonName, "exporl")
	assert.Equal(t, 5, len(tree.Intermediates))
	assert.Equal(t, 1, len(tree.Roots))
}

func TestVerifyChain(t *testing.T) {
	ca, err := DecodeCertFile("t/ca.crt", "")
	assert.NoError(t, err)
	certs, err := DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	verified, output := VerifyChain(&CertTree{
		Certificate: certs[0],
		Roots:       ca,
	})
	assert.Equal(t, "", output)

	certs, err = DecodeCertFile("t/myserver-fromca2.crt", "")
	assert.NoError(t, err)
	verified, output = VerifyChain(&CertTree{
		Certificate: certs[0],
		Roots:       ca,
	})
	assert.False(t, verified)
	assert.NotEqual(t, "", output)
}

func TestVerifyCertAndKey(t *testing.T) {
	certBytes, err := ioutil.ReadFile("t/myserver.crt")
	assert.NoError(t, err)
	certs, err := DecodeCertBytesPKCS1PEM(certBytes)

	key, err := DecodeKeyFile("t/myserver.key", "")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))

	key, err = DecodeKeyFile("t/myserver_enc.key", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))

	key, err = DecodeKeyFile("t/myserver-fromca2.key", "")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.False(t, VerifyCertAndKey(certs[0], key))

	certBytes, err = ioutil.ReadFile("t/ecdsa_prime256v1.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytesPKCS1PEM(certBytes)
	key, err = DecodeKeyFile("t/ecdsa_prime256v1.key", "")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))

	certBytes, err = ioutil.ReadFile("t/ecdsa_prime256v1_2.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytesPKCS1PEM(certBytes)
	key, err = DecodeKeyFile("t/ecdsa_prime256v1_2_enc.key", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))

	certBytes, err = ioutil.ReadFile("t/ecdsa_secp384r1.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytesPKCS1PEM(certBytes)
	key, err = DecodeKeyFile("t/ecdsa_secp384r1.key", "")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))

	certBytes, err = ioutil.ReadFile("t/ecdsa_secp384r1_2.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytesPKCS1PEM(certBytes)
	key, err = DecodeKeyFile("t/ecdsa_secp384r1_2_enc.key", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))

	certBytes, err = ioutil.ReadFile("t/ed25519.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytesPKCS1PEM(certBytes)
	key, err = DecodeKeyFile("t/ed25519.key", "")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))

	certBytes, err = ioutil.ReadFile("t/ed25519_2.crt")
	assert.NoError(t, err)
	certs, err = DecodeCertBytesPKCS1PEM(certBytes)
	key, err = DecodeKeyFile("t/ed25519_2_enc.key", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.True(t, VerifyCertAndKey(certs[0], key))
}

func TestGetPKCS8PEMBlock(t *testing.T) {
	keyBytes, err := ioutil.ReadFile("t/myserver_enc.key")
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)
	block, _ := pem.Decode(keyBytes)
	parsedKey, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(testPassword))
	assert.NoError(t, err)
	assert.NotNil(t, parsedKey)
	pemBlock, err := getPKCS8PEMBlock(parsedKey)
	assert.NoError(t, err)
	assert.NotNil(t, pemBlock)
	assert.Equal(t, "RSA PRIVATE KEY", pemBlock.Type)
}
