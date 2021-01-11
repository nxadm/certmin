package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

const (
	version = "0.1.0"
	website = "https://github.com/nxadm/certmin"
)

func main() {
	action, _ := getAction()
	action()
}

func skimCerts(certFiles []string) bool {
	for _, certFile := range certFiles {
		fmt.Printf("Certificate file %s:\n", certFile)
		certs, _ := splitMultiCertFile(certFile) // Errors are shown in output
		for _, cert := range certs {
			fmt.Printf("Subject:\t%s\n", cert.Subject)
			if len(cert.DNSNames) > 0 {
				fmt.Printf("DNS names:\t%s\n", strings.Join(cert.DNSNames, ", "))
			}
			fmt.Printf("Issuer:\t\t%s\n", cert.Issuer)
			fmt.Printf("Serial number:\t%s\n", cert.SerialNumber)
			fmt.Printf("Not before:\t%s\n", cert.NotBefore)
			fmt.Printf("Not after:\t%s\n", cert.NotAfter)
			if cert.MaxPathLen > 0 {
				fmt.Printf("MaxPathLen:\t%d\n", cert.MaxPathLen)
			}
			if len(cert.OCSPServer) > 0 {
				fmt.Printf("OCSP servers:\t%s\n", strings.Join(cert.OCSPServer, ", "))
			}
			fmt.Println("")
		}

		fmt.Println("---")
	}

	return true
}

func verifyCertAndKey(certFile, keyFile string) bool {
	fmt.Printf("Certificate file %s and key file %s:\n", certFile, keyFile)
	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	fmt.Println("certificate and key match")
	return true
}

func verifyChainFromFiles(rootFiles, intermediateFiles []string, certFile string) bool {
	var roots, intermediates []*x509.Certificate

	for _, file := range rootFiles {
		certs, _ := splitMultiCertFile(file) // Errors are shown in output
		roots = append(roots, certs...)
	}

	for _, file := range intermediateFiles {
		certs, _ := splitMultiCertFile(file) // Errors are shown in output
		intermediates = append(intermediates, certs...)
	}

	certs, _ := splitMultiCertFile(certFile) // Errors are shown in output

	switch {
	case len(certs) != 1:
		fmt.Println("error: only a single cert can be verified")
		return false
	case len(roots) == 0:
		fmt.Println("error: no root certificates found")
		return false
	}

	return verifyChain(roots, intermediates, certs[0])
}

// Internal
func splitMultiCertFile(certFile string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	pemData, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}

	var keepErrStrs []string
	for {
		block, rest := pem.Decode([]byte(pemData))
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("error: can not parse certificate (%s)\n", err)
			keepErrStrs = append(keepErrStrs, err.Error())
			continue
		}
		certs = append(certs, cert)
		pemData = rest
	}

	if keepErrStrs != nil || len(certs) == 0 {
		if len(certs) == 0 {
			keepErrStrs = append([]string{"no certificates found"}, keepErrStrs...)
		}
		keepErr := errors.New(strings.Join(keepErrStrs, ", "))
		fmt.Printf("error: can not parse certificate file (%s)\n", keepErr)
		return certs, keepErr
	}

	return certs, nil
}

func verifyChain(roots, intermediates []*x509.Certificate, cert *x509.Certificate) bool {
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
		fmt.Println("certificate is invalid for the supplied chain")
		return false
	}

	fmt.Println("certificate is valid for the supplied chain")
	return true
}
