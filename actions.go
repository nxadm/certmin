package certmin

//
//import (
//	"crypto/ecdsa"
//	"crypto/ed25519"
//	"crypto/rsa"
//	"crypto/tls"
//	"crypto/x509"
//	"encoding/pem"
//	"errors"
//	"fmt"
//	"io/ioutil"
//	"strings"
//	"text/tabwriter"
//
//	"github.com/fatih/color"
//	"github.com/youmark/pkcs8"
//)
//

//func verifyChain(rootFiles, interFiles, locs []string, remoteChain, remoteInters bool) (string, error) {
//	var roots, inters []*x509.Certificate
//	var sb strings.Builder
//
//	for _, file := range rootFiles {
//		tmpRoots, err := splitMultiCertFile(file)
//		if err != nil {
//			return "", err
//		}
//		roots = append(roots, tmpRoots...)
//	}
//
//	for _, file := range interFiles {
//		tmpInter, err := splitMultiCertFile(file)
//		if err != nil {
//			return "", err
//		}
//		inters = append(inters, tmpInter...)
//	}
//
//	for _, loc := range locs {
//		locRoots := roots
//		locInters := inters
//		certs, remote, err := getCertificates(loc, remoteChain, remoteInters)
//		if err != nil {
//			return "", err
//		}
//		if !remote && len(certs) > 1 {
//			return "", errors.New("the certificate file contains more than 1 certificate")
//		}
//
//		cert := certs[0]
//		for _, chainElem := range certs[1:] {
//			if isRootCA(chainElem) {
//				locRoots = append(locRoots, chainElem)
//			} else {
//				locInters = append(locInters, chainElem)
//			}
//		}
//
//		verified, msg := verifyChainFromX509(locRoots, locInters, cert)
//		if msg != "" {
//			sb.WriteString(msg)
//		}
//
//		if verified {
//			msg := "certificate " + cert.Subject.String() + " and its chain match"
//			sb.WriteString(color.GreenString((msg)))
//		} else {
//			msg := "certificate " + cert.Subject.String() + " and its chain do not match"
//			sb.WriteString(color.RedString((msg)))
//		}
//	}
//
//	return sb.String(), nil
//}
//
//func verifyKey(loc, keyFile string, passwordBytes []byte) (string, error) {
//	msgOK := color.GreenString("the certificate and key match")
//	msgNOK := color.RedString("the certificate and key do not match")
//	certs, _, err := getCertificates(loc, false, false)
//	if err != nil {
//		return "", err
//	}
//
//	if len(certs) != 1 {
//		return "", errors.New("only 1 certificate can be verified")
//	}
//
//	pemBytes, err := ioutil.ReadFile(keyFile)
//	if err != nil {
//		return "", err
//	}
//
//	keyPEMBlock, _ := pem.Decode(pemBytes)
//	keyPEM := pem.EncodeToMemory(&pem.Block{
//		Type:  "PRIVATE KEY",
//		Bytes: keyPEMBlock.Bytes,
//	})
//	certPEM := pem.EncodeToMemory(&pem.Block{
//		Type:  "CERTIFICATE",
//		Bytes: certs[0].Raw,
//	})
//
//	if strings.Contains(keyPEMBlock.Type, "ENCRYPTED") {
//		if passwordBytes == nil {
//			passwordBytes, err = promptForPassword()
//			if err != nil {
//				return "", err
//			}
//		}
//
//		parsedKey, err := pkcs8.ParsePKCS8PrivateKey(keyPEMBlock.Bytes, passwordBytes)
//		if err != nil {
//			return "", err
//		}
//
//		var keyBytes []byte
//		switch key := parsedKey.(type) {
//		case *rsa.PrivateKey, *ecdsa.PrivateKey, *ed25519.PrivateKey:
//			keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
//		default:
//			err = errors.New("unknown signature algorithm of private key")
//		}
//		if err != nil {
//			return "", err
//		}
//
//		keyPEM = pem.EncodeToMemory(
//			&pem.Block{
//				Type:  "PRIVATE KEY",
//				Bytes: keyBytes,
//			},
//		)
//	}
//
//	_, err = tls.X509KeyPair(certPEM, keyPEM)
//	if err != nil {
//		return msgNOK, nil
//	}
//	return msgOK, nil
//}
