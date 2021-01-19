package certmin

//
//import (
//	"os"
//	"testing"
//
//	"github.com/fatih/color"
//	"github.com/stretchr/testify/assert"
//)
//
//var testPasswordBytes = []byte("1234")
//

//
//func TestSkimCerts(t *testing.T) {
//	color.NoColor = true
//	output, err := skimCerts([]string{"t/myserver.crt"}, false, false)
//	assert.Regexp(t, "Subject:\\s+CN=myserver", output)
//	assert.Nil(t, err)
//
//	_, err = skimCerts([]string{"main.go"}, false, false)
//	assert.NotNil(t, err)
//
//	if os.Getenv("AUTHOR_TESTING") != "" {
//		output, err = skimCerts([]string{"https://github.com"}, false, false)
//		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
//		assert.Nil(t, err)
//
//		output, err = skimCerts([]string{"github.com:443"}, false, false)
//		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
//		assert.Nil(t, err)
//
//		output, err = skimCerts([]string{"github.com"}, false, false)
//		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
//		assert.Nil(t, err)
//
//		output, err = skimCerts([]string{"github.com"}, true, false)
//		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
//		assert.Nil(t, err)
//
//		output, err = skimCerts([]string{"github.com"}, true, false)
//		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
//		assert.Nil(t, err)
//	}
//	color.NoColor = false
//}
//
//func TestVerifyChain(t *testing.T) {
//	output, err := verifyChain(
//		[]string{"t/ca.crt"}, nil, []string{"t/myserver.crt"}, false, false)
//	assert.Contains(t, output, "its chain match")
//	assert.Nil(t, err)
//
//	output, err = verifyChain(
//		[]string{"t/empty.crt"}, nil, []string{"t/myserver.crt"}, false, false)
//	assert.NotNil(t, err)
//
//	output, err = verifyChain(
//		[]string{"t/chain.crt"}, nil, []string{"t/chain.crt"}, false, false)
//	assert.NotNil(t, err)
//
//	output, err = verifyChain(
//		[]string{"t/ca2.crt"}, nil, []string{"t/myserver.crt"}, false, false)
//	assert.Contains(t, output, "its chain do not match")
//	assert.Nil(t, err)
//
//	if os.Getenv("AUTHOR_TESTING") != "" {
//		output, err := verifyChain(
//			nil, nil, []string{"github.com"}, true, false)
//		assert.Contains(t, output, "its chain match")
//		assert.Nil(t, err)
//
//		output, err = verifyChain(
//			nil, nil, []string{"github.com"}, false, true)
//		assert.Contains(t, output, "its chain match")
//		assert.Nil(t, err)
//	}
//}
//
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
