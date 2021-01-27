package certmin

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeKeyBytes(t *testing.T) {
	keyBytes, err := ioutil.ReadFile("t/myserver.key")
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)
	key, err := DecodeKeyBytes(keyBytes, "")
	assert.NoError(t, err)
	if assert.NotNil(t, key) {
		assert.Equal(t, "RSA PRIVATE KEY", key.Type)
	}

	keyBytes, err = ioutil.ReadFile("t/myserver_enc.key")
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)
	key, err = DecodeKeyBytes(keyBytes, testPassword)
	assert.NoError(t, err)
	if assert.NotNil(t, key) {
		assert.Contains(t, key.Type, "PRIVATE KEY")
	}

	keyBytes, err = ioutil.ReadFile("t/myserver.pfx")
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)
	key, err = DecodeKeyBytes(keyBytes, testPassword)
	assert.NoError(t, err)
	if assert.NotNil(t, key) {
		assert.Contains(t, key.Type, "PRIVATE KEY")
	}
}

func TestDecodeKeyBytesPKCS1(t *testing.T) {
	keyBytes, err := ioutil.ReadFile("t/myserver.key")
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)
	key, err := DecodeKeyBytesPKCS1(keyBytes)
	assert.NoError(t, err)
	if assert.NotNil(t, key) {
		assert.Equal(t, "RSA PRIVATE KEY", key.Type)
	}
}

func TestDecodeKeyBytesPKCS8(t *testing.T) {
	keyBytes, err := ioutil.ReadFile("t/myserver_enc.key")
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)
	key, err := DecodeKeyBytesPKCS8(keyBytes, testPassword)
	assert.NoError(t, err)
	if assert.NotNil(t, key) {
		assert.Contains(t, key.Type, "PRIVATE KEY")
	}
}

func TestDecodeKeyBytesPKCS12(t *testing.T) {
	keyBytes, err := ioutil.ReadFile("t/myserver.pfx")
	assert.NoError(t, err)
	assert.NotNil(t, keyBytes)
	key, err := DecodeKeyBytesPKCS12(keyBytes, testPassword)
	assert.NoError(t, err)
	if assert.NotNil(t, key) {
		assert.Contains(t, key.Type, "PRIVATE KEY")
	}
}

func TestDecodeKeyFile(t *testing.T) {
	key, err := DecodeKeyFile("t/myserver.key", "")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Contains(t, key.Type, "PRIVATE KEY")

	key, err = DecodeKeyFile("t/myserver_enc.key", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Contains(t, key.Type, "PRIVATE KEY")

	key, err = DecodeKeyFile("t/myserver.pfx", testPassword)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Contains(t, key.Type, "PRIVATE KEY")
}
