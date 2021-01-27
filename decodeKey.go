package certmin

import (
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

// DecodeKeyBytes reads a []byte with a key and returns a *pem.Block and
// an error if encountered.
func DecodeKeyBytes(keyBytes []byte, password string) (*pem.Block, error) {
	var block *pem.Block
	var err error
	var errStrs []string

	for {
		block, err = DecodeKeyBytesPKCS1(keyBytes)
		if err != nil {
			errStrs = append(errStrs, err.Error())
		} else {
			break
		}

		block, err = DecodeKeyBytesPKCS8(keyBytes, password)
		if err != nil {
			errStrs = append(errStrs, err.Error())
		} else {
			break
		}

		block, err = DecodeKeyBytesPKCS12(keyBytes, password)
		if err != nil {
			errStrs = append(errStrs, err.Error())
		} else {
			break
		}

		break
	}

	if err != nil {
		return nil, errors.New(strings.Join(errStrs, "   >>   "))
	}

	return block, nil
}

// DecodeKeyBytesPKCS1 reads a []byte with a PKCS1 PEM encoded key and returns
// a *pem.Block and an error if encountered. If you don't know in what format
// the data is encoded, use DecodeKeyBytes.
func DecodeKeyBytesPKCS1(keyBytes []byte) (*pem.Block, error) {
	if !strings.Contains(string(keyBytes), "-----BEGIN") {
		return nil, errors.New("not a PEM key")
	}
	if strings.Contains(string(keyBytes), "-----BEGIN ENCRYPTED") {
		return nil, errors.New("encrypted key")
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return nil, errors.New("failed to decode private key")
	}

	return block, nil
}

// DecodeKeyBytesPKCS8 reads a []byte with an encrypted PKCS8 PEM encoded key and returns
// a *pem.Block and an error if encountered. If you don't know in what format the data
// is encoded, use DecodeKeyBytes.
func DecodeKeyBytesPKCS8(keyBytes []byte, password string) (*pem.Block, error) {
	if !strings.Contains(string(keyBytes), "-----BEGIN") {
		return nil, errors.New("not a PEM key")
	}
	if !strings.Contains(string(keyBytes), "ENCRYPTED") {
		return nil, errors.New("unencrypted key")
	}

	block, _ := pem.Decode(keyBytes)
	parsedKey, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
	if err != nil {
		return nil, err
	}

	return getPKCS8PEMBlock(parsedKey)
}

// DecodeKeyBytesPKCS12 reads a []byte with an encrypted PKCS12 encoded key and returns
// a *pem.Block and an error if encountered. If you don't know in what format the data
// is encoded, use DecodeKeyBytes.
func DecodeKeyBytesPKCS12(keyBytes []byte, password string) (*pem.Block, error) {
	parsedKey, _, _, err := pkcs12.DecodeChain(keyBytes, password)
	if err != nil {
		return nil, err
	}

	return getPKCS8PEMBlock(parsedKey)
}

// DecodeKeyFile reads a file with PEM encoded key and returns the contents as a *pem.Block
// and an error if encountered.
func DecodeKeyFile(keyFile string, password string) (*pem.Block, error) {
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return DecodeKeyBytes(keyBytes, password)
}
