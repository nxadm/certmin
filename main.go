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
	action := getAction()
	action()
}

func skimCerts(certs []string) {
	for _, certFile := range certs {
		fmt.Printf("Certificate file %s:\n", certFile)
		for _, cert := range splitMultiCertFile(certFile) {
			fmt.Printf("Subject:\t%s\n", cert.Subject)
			if len(cert.DNSNames) > 0 {
				fmt.Printf("DNS names:\t%s\n", strings.Join(cert.DNSNames, ", "))
			}
			fmt.Printf("Issuer:\t\t%s\n", cert.Issuer)
			fmt.Printf("Serial number:\t%s\n", cert.SerialNumber)
			fmt.Printf("Not before:\t%s\n", cert.NotBefore)
			fmt.Printf("Not after:\t%s\n", cert.NotAfter)
			if cert.MaxPathLen > 0 {
				fmt.Printf("MaxPathLen:\t%s\n", cert.MaxPathLen)
			}
			if len(cert.OCSPServer) > 0 {
				fmt.Printf("OCSP servers:\t%s\n", strings.Join(cert.OCSPServer, ", "))
			}
			fmt.Println("")
		}

		fmt.Println("---")
	}
}

func splitMultiCertFile(certFile string) []*x509.Certificate {
	var blocks []*pem.Block
	var certs []*x509.Certificate
	pemData, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil
	}

	for {
		block, rest := pem.Decode([]byte(pemData))
		if block == nil {
			fmt.Printf("error: invalid data in certificate file (%s)\n", err)
			return nil
		}
		blocks = append(blocks, block)
		pemData = rest

		if len(rest) == 0 {
			break
		}
	}

	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("error: can not parse certificate (%s)\n", err)
			continue
		}
		certs = append(certs, cert)
	}

	return certs
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

func verifyChainFromFiles(rootFiles, intermediateFiles []string, certFile string) {
	var roots, intermediates []*x509.Certificate

	for _, file := range rootFiles {
		roots = append(roots, splitMultiCertFile(file)...)
	}

	for _, file := range intermediateFiles {
		intermediates = append(intermediates, splitMultiCertFile(file)...)
	}

	certs := splitMultiCertFile(certFile)
	if len(certs) != 1 {
		fmt.Println("error: only a single cert can be verified")
	}

	verifyChain(roots, intermediates, certs[0])
}
