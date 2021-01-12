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

func skimCerts(certLocs []string, network string, remoteChain bool) bool {
	for _, certLoc := range certLocs {
		fmt.Printf("Certificate location %s:\n", certLoc)
		var certs []*x509.Certificate

		if network != "" {
			certs, _ = retrieveRemotes(certLocs, network, remoteChain) // Errors are shown in output
		} else {
			certs, _ = splitMultiCertFile(certLoc) // Errors are shown in output
		}

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

	return true // make it compatible with verify actions
}

func verifyCertAndKey(certLoc, keyFile, network string) bool {
	fmt.Printf("Certificate location %s and key file %s:\n", certLoc, keyFile)
	var err error
	if network != "" {
		certs, err := retrieveCerts(network, certLoc) // Errors are shown in output
		if err != nil || len(certs) == 0 {
			return false
		}
		pemData, err := ioutil.ReadFile(keyFile)
		if err != nil {
			fmt.Printf("error: %s\n", err)
			return false
		}
		_, err = tls.X509KeyPair(certs[0].Raw, pemData)
	} else {
		_, err = tls.LoadX509KeyPair(certLoc, keyFile)
	}

	if err != nil {
		fmt.Println(err.Error())
		return false
	}
	fmt.Println("certificate and key match")
	return true
}

func verifyChainFromFiles(rootFiles, intermediateFiles []string, certLoc, network string, remoteChain bool) bool {
	var roots, inters, certs []*x509.Certificate
	if network != "" {
		certs, err := retrieveCerts(network, certLoc) // Errors are shown in output
		if err != nil {                               // Errors are shown in output
			return false
		}
		if remoteChain && len(certs) > 1 {
			inters = append(inters, certs[1:]...)
		}
	} else {
		certs, _ = splitMultiCertFile(certLoc) // Errors are shown in output
	}

	for _, file := range rootFiles {
		tmpRoots, _ := splitMultiCertFile(file) // Errors are shown in output
		roots = append(roots, tmpRoots...)
	}

	for _, file := range intermediateFiles {
		tmpInter, _ := splitMultiCertFile(file) // Errors are shown in output
		inters = append(inters, tmpInter...)
	}

	// Catch errors
	switch {
	case len(roots) == 0 && !remoteChain:
		fmt.Println("error: no local root certificates found")
		return false
	case len(inters) == 0 && remoteChain:
		fmt.Println("error: no remote intermediate certificates found")
		return false
	case len(certs) != 1 && !remoteChain:
		fmt.Println("error: only a single local certificate can be verified")
		return false
	}

	return verifyChain(roots, inters, certs[0])
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
