package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

func skimCerts(certFiles []string) {
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
}

func verifyCertAndKey(certFile, keyFile string) {
	fmt.Printf("Certificate file %s and key file %s:\n", certFile, keyFile)
	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("certificate and key match")
}

func verifyChainFromFiles(rootFiles, intermediateFiles []string, certFile string) {
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
	if len(certs) != 1 {
		fmt.Println("error: only a single cert can be verified")
	}

	verifyChain(roots, intermediates, certs[0])
}

// Internal
func splitMultiCertFile(certFile string) ([]*x509.Certificate, error) {
	var blocks []*pem.Block
	var certs []*x509.Certificate
	pemData, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}

	for {
		block, rest := pem.Decode([]byte(pemData))
		if block == nil {
			err = fmt.Errorf("error: invalid data in certificate file (%s)\n", err)
			fmt.Printf(err.Error())
			return nil, err
		}
		blocks = append(blocks, block)
		pemData = rest

		if len(rest) == 0 {
			break
		}
	}

	var keepErrStrs []string
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("error: can not parse certificate (%s)\n", err)
			keepErrStrs = append(keepErrStrs, err.Error())
			continue
		}
		certs = append(certs, cert)
	}

	if keepErrStrs == nil {
		return certs, nil
	}
	return certs,
		fmt.Errorf("error: can not parse certificate (%s)\n", strings.Join(keepErrStrs, ", "))
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
