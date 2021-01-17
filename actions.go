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
	"io/ioutil"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/youmark/pkcs8"
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
	w := tabwriter.NewWriter(&sb, 1, 4, 1, ' ', 0)
	for _, loc := range locs {
		fmt.Fprint(w, "\ncertificate location "+loc+":\n\n")
		certs, _, err := getCertificates(loc, remoteChain, remoteInters)
		if err != nil {
			return "", err
		}

		for idx, cert := range certs {
			fmt.Fprintf(w, "Subject:\t%s\n", colourKeeper.colourise(cert.Subject.String()))
			fmt.Fprintf(w, "Issuer:\t%s\n", colourKeeper.colourise(cert.Issuer.String()))
			if len(cert.DNSNames) > 0 {
				fmt.Fprintf(w, "DNS names:\t%s\n", strings.Join(cert.DNSNames, ", "))
			}
			if len(cert.EmailAddresses) > 0 {
				fmt.Fprintf(w, "Email addresses:\t%s\n", strings.Join(cert.EmailAddresses, ", "))
			}
			if len(cert.IPAddresses) > 0 {
				var ips []string
				for _, ip := range cert.IPAddresses {
					ips = append(ips, ip.String())
				}
				fmt.Fprintf(w, "IP addresses:\t%s\n", strings.Join(ips, ", "))
			}
			if len(cert.URIs) > 0 {
				var uris []string
				for _, uri := range cert.URIs {
					uris = append(uris, uri.String())
				}
				fmt.Fprintf(w, "URIs:\t%s\n", strings.Join(uris, ", "))
			}
			fmt.Fprintf(w, "Serial number:\t%s\n", cert.SerialNumber)
			fmt.Fprintf(w, "Version:\t%d\n", cert.Version)
			if cert.IsCA {
				fmt.Fprintf(w, "Is CA:\t%t\n", true)
			}
			if cert.MaxPathLen > 0 {
				fmt.Fprintf(w, "MaxPathLen:\t%d\n", cert.MaxPathLen)
			}
			if cert.MaxPathLenZero {
				fmt.Fprintf(w, "MaxPathLen is 0:\t\t%t\n", cert.MaxPathLenZero)
			}
			fmt.Fprintf(w, "Public key algorithm:\t%s\n", cert.PublicKeyAlgorithm.String())
			fmt.Fprintf(w, "Signature algorithm:\t%s\n", cert.SignatureAlgorithm.String())
			if cert.PermittedDNSDomainsCritical {
				fmt.Fprintf(w, "Permitted DNS domains critical:\t%t\n", true)
			}
			if len(cert.PermittedDNSDomains) > 0 {
				fmt.Fprintf(w, "Permitted DNS domains:\t%s\n", strings.Join(cert.PermittedDNSDomains, ", "))
			}
			if len(cert.ExcludedDNSDomains) > 0 {
				fmt.Fprintf(w, "Excluded DNS domains:\t%s\n", strings.Join(cert.ExcludedDNSDomains, ", "))
			}
			if len(cert.PermittedURIDomains) > 0 {
				fmt.Fprintf(w, "Permitted URI domains:\t%s\n", strings.Join(cert.PermittedURIDomains, ", "))
			}
			if len(cert.ExcludedURIDomains) > 0 {
				fmt.Fprintf(w, "Excluded URI domains:\t%s\n", strings.Join(cert.ExcludedURIDomains, ", "))
			}
			if len(cert.PermittedEmailAddresses) > 0 {
				fmt.Fprintf(w, "Permitted email addresses:\t%s\n", strings.Join(cert.PermittedEmailAddresses, ", "))
			}
			if len(cert.ExcludedEmailAddresses) > 0 {
				fmt.Fprintf(w, "Excluded email addresses:\t%s\n", strings.Join(cert.ExcludedEmailAddresses, ", "))
			}
			if len(cert.PermittedIPRanges) > 0 {
				var iprs []string
				for _, ipr := range cert.PermittedIPRanges {
					iprs = append(iprs, ipr.String())
				}
				fmt.Fprintf(w, "Permitted IP ranges:\t%s\n", strings.Join(iprs, ", "))
			}
			if len(cert.ExcludedIPRanges) > 0 {
				var iprs []string
				for _, ipr := range cert.ExcludedIPRanges {
					iprs = append(iprs, ipr.String())
				}
				fmt.Fprintf(w, "Excluded IP ranges:\t%s\n", strings.Join(iprs, ", "))
			}
			if len(cert.OCSPServer) > 0 {
				fmt.Fprintf(w, "OCSP servers:\t%s\n", strings.Join(cert.OCSPServer, ", "))
			}
			if len(cert.CRLDistributionPoints) > 0 {
				fmt.Fprintf(w, "CRL locations:\t%s\n", strings.Join(cert.CRLDistributionPoints, ", "))
			}
			fmt.Fprintf(w, "Not before:\t%s\n", cert.NotBefore)
			fmt.Fprintf(w, "Not after:\t%s\n", cert.NotAfter)
			if idx < len(certs)-1 {
				fmt.Fprintln(w)
			}
		}
		fmt.Fprint(w, "---")
	}
	w.Flush()

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

		var keyBytes []byte
		switch key := parsedKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, *ed25519.PrivateKey:
			keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
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
