package certmin

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/youmark/pkcs8"
	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

// DecodeCertBytes reads a []byte with DER or PEM PKCS1, PKCS7 and PKCS12 encoded certificates,
// and returns the contents as a []*x509.Certificate and an error if encountered. A password is
// only needed for PKCS12.
func DecodeCertBytes(certBytes []byte, password string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err error
	var errStrs []string

	for {
		certs, err = DecodeCertBytesPKCS1PEM(certBytes)
		if err != nil {
			errStrs = append(errStrs, err.Error())
		} else {
			break
		}

		certs, err = DecodeCertBytesPKCS1DER(certBytes)
		if err != nil {
			errStrs = append(errStrs, err.Error())
		} else {
			break
		}

		certs, err = DecodeCertBytesPKCS7PEM(certBytes)
		if err != nil {
			errStrs = append(errStrs, err.Error())
		} else {
			break
		}

		certs, err = DecodeCertBytesPKCS7DER(certBytes)
		if err != nil {
			errStrs = append(errStrs, err.Error())
		} else {
			break
		}

		certs, err = DecodeCertBytesPKCS12(certBytes, password)
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

	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}

	return certs, nil
}

// DecodeCertBytesPKCS1DER reads a []byte with PKCS1 DER encoded certificates (e.g. read
// from a file of a HTTP response body), and returns the contents as a  []*x509.Certificate
// and an error if encountered. If you don't know in what format the data is encoded, use
// DecodeCertBytes.
func DecodeCertBytesPKCS1DER(certBytes []byte) ([]*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		err = errors.New("no certificates found")
	}

	return certs, err
}

// DecodeCertBytesPKCS1PEM reads a []byte with PKCS1 PEM encoded certificates (e.g. read
// from a file of a HTTP response body), and returns the contents as a []*x509.Certificate
// and an error if encountered. If you don't know in what format the data is encoded, use
// DecodeCertBytes.
func DecodeCertBytesPKCS1PEM(certBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	pemBytes := certBytes
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}

		if bytes.Equal(rest, pemBytes) {
			return nil, errors.New("not valid PKCS1 PEM data")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		pemBytes = rest
	}

	var err error
	if len(certs) == 0 {
		err = errors.New("no certificates found")
	}

	return certs, err
}

// DecodeCertBytesPKCS7DER reads a []byte with PKCS7 DER encoded certificates (e.g. read
// from a file of a HTTP response body), and returns the contents as a []*x509.Certificate
// and an error if encountered. If you don't know in what format the data is encoded,
// use DecodeCertBytes.
func DecodeCertBytesPKCS7DER(certBytes []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(certBytes)
	if err != nil {
		return nil, err
	}

	certs := p7.Certificates
	if len(certs) == 0 {
		err = errors.New("no certificates found")
	}

	return certs, err
}

// DecodeCertBytesPKCS7PEM reads a []byte with PKCS7 PEM encoded certificates (e.g. read
// from a file of a HTTP response body), and returns the contents as a []*x509.Certificate
// and an error if encountered. If you don't know in what format the data is encoded, use
// DecodeCertBytes.
func DecodeCertBytesPKCS7PEM(certBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	pemBytes := certBytes
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}

		if bytes.Equal(rest, pemBytes) {
			return nil, errors.New("not valid PKCS7 PEM data")
		}

		p7, err := pkcs7.Parse(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, p7.Certificates...)
		pemBytes = rest
	}

	var err error
	if len(certs) == 0 {
		err = errors.New("no certificates found")
	}

	return certs, err
}

// DecodeCertBytesPKCS12 reads a []byte with PKCS12 encoded certificates (e.g. read
// from a file of a HTTP response body) and a password. It returns the contents as
// a []*x509.Certificate  and an error if encountered. If you don't know in what
// format the data is encoded, use DecodeCertBytes.
func DecodeCertBytesPKCS12(certBytes []byte, password string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	_, cert, caCerts, err := pkcs12.DecodeChain(certBytes, password)
	if err != nil {
		return nil, err
	} else {
		certs = append(certs, cert)
		certs = append(certs, caCerts...)
	}

	if len(certs) == 0 {
		err = errors.New("no certificates found")
	}

	return certs, err
}

// DecodeCertFile reads a file with DER or PEM encoded certificates and returns
// the contents as a []*x509.Certificate and an error if encountered.
func DecodeCertFile(certFile, password string) ([]*x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return DecodeCertBytes(certBytes, password)
}

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
