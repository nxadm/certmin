package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/youmark/pkcs8"
	"io/ioutil"
	"strings"

	"github.com/fatih/color"
)

type colourKeeper map[string]int

// Only colourise the 8 first subjects
func (colourKeeper *colourKeeper) colourise(msg string) string {
	colourStr := make(map[int]func(format string, a ...interface{}) string)
	colourStr[0] = color.GreenString
	colourStr[1] = color.BlueString
	colourStr[2] = color.MagentaString
	colourStr[3] = color.CyanString
	colourStr[4] = color.HiGreenString
	colourStr[5] = color.HiBlueString
	colourStr[6] = color.HiMagentaString
	colourStr[7] = color.HiCyanString
	if idx, ok := (*colourKeeper)[msg]; ok {
		return colourStr[idx](msg)
	}
	if len(*colourKeeper) < 8 {
		idx := len(*colourKeeper)
		(*colourKeeper)[msg] = idx
		return colourStr[idx](msg)
	}
	return msg
}

func skimCerts(locs []string, remoteChain, remoteInters bool) (string, error) {
	var sb strings.Builder
	colourKeeper := make(colourKeeper)
	for _, loc := range locs {
		sb.WriteString("\ncertificate location " + loc + ":\n\n")
		certs, _, err := getCertificates(loc, remoteChain, remoteInters)
		if err != nil {
			return "", err
		}

		for _, cert := range certs {
			sb.WriteString(fmt.Sprintf("Subject:\t\t%s\n", colourKeeper.colourise(cert.Subject.String())))
			sb.WriteString(fmt.Sprintf("Issuer:\t\t\t%s\n", colourKeeper.colourise(cert.Issuer.String())))
			if len(cert.DNSNames) > 0 {
				sb.WriteString(fmt.Sprintf("DNS names:\t\t%s\n", strings.Join(cert.DNSNames, ", ")))
			}
			sb.WriteString(fmt.Sprintf("Is CA:\t\t\t%t\n", cert.IsCA))
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

func verifyChain(rootFiles, interFiles, locs []string, remoteChain, remoteInters bool) (string, error) {
	var roots, inters []*x509.Certificate
	var sb strings.Builder

	for _, file := range rootFiles {
		tmpRoots, err := splitMultiCertFile(file)
		if err != nil {
			return "", err
		}
		roots = append(roots, tmpRoots...)
	}

	for _, file := range interFiles {
		tmpInter, err := splitMultiCertFile(file)
		if err != nil {
			return "", err
		}
		inters = append(inters, tmpInter...)
	}

	for _, loc := range locs {
		locRoots := roots
		locInters := inters
		certs, remote, err := getCertificates(loc, remoteChain, remoteInters)
		if err != nil {
			return "", err
		}
		if !remote && len(certs) > 1 {
			return "", errors.New("the certificate file contains more than 1 certificate")
		}

		cert := certs[0]
		for _, chainElem := range certs[1:] {
			if isRootCA(chainElem) {
				locRoots = append(locRoots, chainElem)
			} else {
				locInters = append(locInters, chainElem)
			}
		}

		verified, msg := verifyChainFromX509(locRoots, locInters, cert)
		if msg != "" {
			sb.WriteString(msg)
		}

		if verified {
			msg := "certificate " + cert.Subject.String() + " and its chain match"
			sb.WriteString(color.GreenString((msg)))
		} else {
			msg := "certificate " + cert.Subject.String() + " and its chain do not match"
			sb.WriteString(color.RedString((msg)))
		}
	}

	return sb.String(), nil
}

func verifyKey(loc, keyFile string, passwordBytes []byte) (string, error) {
	msgOK := color.GreenString("the certificate and key match")
	msgNOK := color.RedString("the certificate and key do not match")
	certs, _, err := getCertificates(loc, false, false)
	if err != nil {
		return "", err
	}

	if len(certs) != 1 {
		return "", errors.New("only 1 certificate can be verified")
	}

	pemBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return "", err
	}

	keyPEMBlock, _ := pem.Decode(pemBytes)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyPEMBlock.Bytes,
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certs[0].Raw,
	})

	if strings.Contains(keyPEMBlock.Type, "ENCRYPTED") {
		if passwordBytes == nil {
			passwordBytes, err = promptForPassword()
			if err != nil {
				return "", err
			}
		}

		parsedKey, err := pkcs8.ParsePKCS8PrivateKey(keyPEMBlock.Bytes, passwordBytes)
		if err != nil {
			return "", err
		}

		castedRSA, okRSA := parsedKey.(*rsa.PrivateKey)
		castedECDSA, okECDSA := parsedKey.(*ecdsa.PrivateKey)
		castedED25519, okED25519 := parsedKey.(*ed25519.PrivateKey)
		var keyBytes []byte
		switch {
		case okRSA:
			keyBytes, err = x509.MarshalPKCS8PrivateKey(castedRSA)
		case okECDSA:
			keyBytes, err = x509.MarshalPKCS8PrivateKey(castedECDSA)
		case okED25519:
			keyBytes, err = x509.MarshalPKCS8PrivateKey(castedED25519)
		default:
			err = errors.New("unknown signature algorithm of private key")
		}

		if err != nil {
			return "", err
		}

		keyPEM = pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			},
		)
	}

	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return msgNOK, nil
	}
	return msgOK, nil
}
