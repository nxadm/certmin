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

func skimCerts(locs []string, remoteChain bool) (string, error) {
	var sb strings.Builder
	for _, loc := range locs {
		sb.WriteString("\ncertificate location " + loc + ":\n\n")
		certs, err := getCertificates(loc, remoteChain)
		if err != nil {
			return "", err
		}

		for _, cert := range certs {
			sb.WriteString(fmt.Sprintf("Subject:\t\t%s\n", cert.Subject))
			if len(cert.DNSNames) > 0 {
				sb.WriteString(fmt.Sprintf("DNS names:\t\t%s\n", strings.Join(cert.DNSNames, ", ")))
			}
			sb.WriteString(fmt.Sprintf("Issuer:\t\t\t%s\n", cert.Issuer))
			sb.WriteString(fmt.Sprintf("Serial number:\t\t%s\n", cert.SerialNumber))
			if cert.MaxPathLen > 0 {
				sb.WriteString(fmt.Sprintf("MaxPathLen:\t\t%d\n", cert.MaxPathLen))
			}
			sb.WriteString(fmt.Sprintf("Public key algorithm:\t%s\n", cert.PublicKeyAlgorithm.String()))
			sb.WriteString(fmt.Sprintf("Signature algorithm:\t%s\n", cert.SignatureAlgorithm.String()))
			if len(cert.OCSPServer) > 0 {
				sb.WriteString(fmt.Sprintf("OCSP servers:\t\t%s\n", strings.Join(cert.OCSPServer, ", ")))

			}
			if len(cert.CRLDistributionPoints) > 0 {
				sb.WriteString(fmt.Sprintf("CRL locations:\t\t%s\n", strings.Join(cert.CRLDistributionPoints, ", ")))

			}
			sb.WriteString(fmt.Sprintf("Not before:\t\t%s\n", cert.NotBefore))
			sb.WriteString(fmt.Sprintf("Not after:\t\t%s\n", cert.NotAfter))
			sb.WriteString("\n")
		}

		sb.WriteString("---\n")
	}

	return sb.String(), nil
}

func verifyChain(rootFiles, interFiles []string, loc string, remoteChain bool) (string, error) {
	msgOK := "\nthe certificate and the chain match"
	msgNOK := "\nthe certificate and the chain do not match"

	var roots, inters, certs []*x509.Certificate
	var err error

	certs, err = getCertificates(loc, remoteChain)
	if err != nil {
		return "", err
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
		return "", errors.New("only a single local certificate can be verified")
	case remoteChain && len(roots) == 0:
		return "", errors.New("no remote chain certificates found")
	}

	verified := verifyChainFromX509(roots, inters, certs[0])
	if verified {
		return msgOK, nil
	}

	return msgNOK, nil
}

func verifyKey(loc, keyFile string) (string, error) {
	msgOK := "\nthe certificate and key match"
	msgNOK := "\nthe certificate and key do not match"
	certs, err := getCertificates(loc, false)
	if err != nil {
		return "", err
	}

	if len(certs) != 1 {
		return "", errors.New("only 1 certificate can be verified")
	}

	pemData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	decoded, _ := pem.Decode(pemData)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certs[0].Raw,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: decoded.Bytes,
	})

	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fmt.Printf("HERE: %s\n", err)
		return msgNOK, nil
	}
	return msgOK, nil
}
