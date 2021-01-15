package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

func getCertificates(loc string, remoteChain bool) ([]*x509.Certificate, bool, error) {
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
				return nil, false, err
			}
			addr = result
		}
	}

	if file != "" {
		certs, err = splitMultiCertFile(file) // Errors are shown in output

		return certs, false, err
	} else {
		certs, err = retrieveCerts(addr, remoteChain) // Errors are shown in output
		certs = orderRemoteChain(certs)

		return certs, true, err
	}
}

// Just try to order the results and return the original array if
// something fishy is going on
func orderRemoteChain(certs []*x509.Certificate) []*x509.Certificate {
	var ordered []*x509.Certificate
	parentName := make(map[string]string)
	certByName := make(map[string]*x509.Certificate)

	// Get the information needed to follow the chain
	for _, cert := range certs {
		// the chain is fishy
		if _, ok := certByName[cert.Subject.String()]; ok {
			return certs
		}
		if _, ok := parentName[cert.Subject.String()]; ok {
			return certs
		}

		certByName[cert.Subject.String()] = cert
		parentName[cert.Subject.String()] = cert.Issuer.String()
	}

	seen := make(map[string]bool)
	for _, cert := range certs {
		if _, ok := seen[cert.Subject.String()]; ok {
			continue
		}
		ordered = append(ordered, cert)
		for { // follow the chain
			_, ok := certByName[parentName[cert.Subject.String()]] // we have that cert
			_, ok2 := seen[parentName[cert.Subject.String()]]      // the parent has not been seen
			if ok && !ok2 {
				// do we have the next Issuer (e.g. incomplete chain
				if _, ok := certByName[parentName[cert.Subject.String()]]; ok {
					ordered = append(ordered, certByName[parentName[cert.Subject.String()]])
					seen[parentName[cert.Subject.String()]] = true
					cert = certByName[parentName[cert.Subject.String()]]
					continue
				}
			}
			break
		}
	}

	return ordered
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
