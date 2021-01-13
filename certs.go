package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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

func skimCerts(locs []string, remoteChain bool) (string, error) {
	var sb strings.Builder
	for _, loc := range locs {
		fmt.Printf("Certificate location %s:\n", loc)
		certs, err := getCertificates(loc, remoteChain)
		if err != nil {
			return "", err
		}

		for _, cert := range certs {
			keepAndPrintOutput(&sb, fmt.Sprintf("Subject:\t\t%s", cert.Subject), false)
			if len(cert.DNSNames) > 0 {
				keepAndPrintOutput(
					&sb, fmt.Sprintf("DNS names:\t\t%s", strings.Join(cert.DNSNames, ", ")), false)
			}
			keepAndPrintOutput(&sb, fmt.Sprintf("Issuer:\t\t\t%s", cert.Issuer), false)
			keepAndPrintOutput(&sb, fmt.Sprintf("Serial number:\t\t%s", cert.SerialNumber), false)
			if cert.MaxPathLen > 0 {
				keepAndPrintOutput(&sb, fmt.Sprintf("MaxPathLen:\t\t%d", cert.MaxPathLen), false)
			}
			keepAndPrintOutput(&sb,
				fmt.Sprintf("Public key algorithm:\t%s", cert.PublicKeyAlgorithm.String()), false)
			keepAndPrintOutput(&sb,
				fmt.Sprintf("Signature algorithm:\t%s", cert.SignatureAlgorithm.String()), false)
			if len(cert.OCSPServer) > 0 {
				keepAndPrintOutput(
					&sb, fmt.Sprintf("OCSP servers:\t\t%s", strings.Join(cert.OCSPServer, ", ")), false)

			}
			if len(cert.CRLDistributionPoints) > 0 {
				keepAndPrintOutput(
					&sb, fmt.Sprintf("CRL locations:\t\t%s", strings.Join(cert.CRLDistributionPoints, ", ")), false)

			}
			keepAndPrintOutput(
				&sb, fmt.Sprintf("Not before:\t\t%s", cert.NotBefore), false)
			keepAndPrintOutput(
				&sb, fmt.Sprintf("Not after:\t\t%s", cert.NotAfter), false)
			fmt.Println("")
		}

		fmt.Println("---")
	}

	return sb.String(), nil // make it testable
}

func splitMultiCertFile(certFile string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	pemData, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return nil, err
	}

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: can not parse certificate (%s)\n", err)
			return nil, err
		}
		certs = append(certs, cert)
		pemData = rest
	}

	if len(certs) == 0 {
		err = errors.New("no certificates found")
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return nil, err
	}

	return certs, nil
}

func verifyChain(roots, intermediates []*x509.Certificate, cert *x509.Certificate) (bool, error) {
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
		return false, nil
	}

	fmt.Println("certificate is valid for the supplied chain")
	return true, nil
}

func verifyChainFromLoc(rootFiles, interFiles []string, loc string, remoteChain bool) (bool, error) {
	var roots, inters, certs []*x509.Certificate
	var err error

	certs, err = getCertificates(loc, remoteChain)
	if err != nil {
		return false, err
	}

	if remoteChain && len(certs) > 0 {
		roots = append(roots, certs[1:]...)
	}

	for _, file := range rootFiles {
		tmpRoots, _ := splitMultiCertFile(file) // Errors are shown in output
		roots = append(roots, tmpRoots...)
	}

	for _, file := range interFiles {
		tmpInter, _ := splitMultiCertFile(file) // Errors are shown in output
		inters = append(inters, tmpInter...)
	}

	// Catch errors
	switch {
	case !remoteChain && len(certs) != 1:
		err = errors.New("only a single local certificate can be verified")
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return false, err
	case remoteChain && len(roots) == 0:
		err = errors.New("no remote chain certificates found")
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return false, err
	}

	return verifyChain(roots, inters, certs[0])
}

func verifyKey(certLoc, keyFile string) bool {
	//fmt.Printf("Certificate location %s and key file %s:\n", certLoc, keyFile)
	//var err error
	//if network != "" {
	//	certs, err := retrieveCerts(network, certLoc, false) // Errors are shown in output
	//	if err != nil || len(certs) == 0 {
	//		return false
	//	}
	//
	//	pemData, err := ioutil.ReadFile(keyFile)
	//	if err != nil {
	//		fmt.Fprintf(os.Stderr, "error: %s\n", err)
	//		return false
	//	}
	//	_, err = tls.X509KeyPair(certs[0].Raw, pemData)
	//} else {
	//	_, err = tls.LoadX509KeyPair(certLoc, keyFile)
	//}
	//
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "error: %s\n", err)
	//	return false
	//}
	//fmt.Println("certificate and key match")
	return true
}
