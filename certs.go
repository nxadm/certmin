package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

func getCertificates(loc string, remoteChain bool) ([]*x509.Certificate, error) {
	var addr, file string
	var err error
	var certs []*x509.Certificate

	result, err := parseURL(loc)
	if err == nil {
		addr = result
	} else {
		_, err := os.Stat(loc)
		if !remoteChain && err == nil {
			file = loc
		} else {
			result, err = parseURL("certmin://" + loc)
			if err != nil {
				return nil, err
			}
			addr = result
		}
	}

	if file != "" {
		certs, err = splitMultiCertFile(file) // Errors are shown in output
	} else {
		certs, err = retrieveCerts(addr, remoteChain) // Errors are shown in output
	}

	return certs, err
}

func splitMultiCertFile(certFile string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	pemData, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		pemData = rest
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}

	return certs, nil
}

func verifyChainFromX509(roots, intermediates []*x509.Certificate, cert *x509.Certificate) bool {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}

	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}

	options := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}

	if _, err := cert.Verify(options); err != nil {
		return false
	}

	return true
}
