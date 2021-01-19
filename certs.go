package certmin

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// CertTree represents a chain where certificates are
// assigned as a Certificate, Intermediates and Roots.
type CertTree struct {
	Certificate          *x509.Certificate
	Intermediates, Roots []*x509.Certificate
}

// EncodeCertAsPEMBytes converts *x509.Certificate to a []byte with
// data encoded as PEM and an error.
func EncodeCertAsPEMBytes(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("no certificate found")
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	var buf bytes.Buffer
	err := pem.Encode(&buf, block)

	return buf.Bytes(), err
}

// IsRootCA returns for a given *x509.Certificate true if
// the CA is marked as IsCA and the Subject and the Issuer
// are the same.
func IsRootCA(cert *x509.Certificate) bool {
	return cert.IsCA && cert.Subject.String() == cert.Issuer.String()
}

// DecodeCertBytes reads a []byte with one DER encoded certificate or one or more
// PEM encoded certificates (e.g. read from a file of a HTTP response body), and
// returns the contents as a []*x509.Certificate and an error if encountered.
func DecodeCertBytes(certBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	pemBytes := certBytes
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil || bytes.Equal(rest, pemBytes) { // Invalid or DER encoded
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		pemBytes = rest
	}

	if certs == nil {
		cert, err := x509.ParseCertificate(pemBytes) // DER encoded
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}

	return certs, nil
}

// DecodeCertFile reads a file with one DER encoded certificate or one or more
// PEM encoded certificates and returns the contents as a []*x509.Certificate and
// an error if encountered.
func DecodeCertFile(certFile string) ([]*x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return DecodeCertBytes(certBytes)
}

// SortCerts sorts a []*x509.Certificate from leaf to root CA, or the other
// way around if a the supplied boolean is set to true. Double elements are
// removed. The starting leaf certificate must be the first element of the
// given []*x509.Certificate.
func SortCerts(certs []*x509.Certificate, reverse bool) []*x509.Certificate {
	var ordered []*x509.Certificate

	// Get the information needed to follow the chain
	parentName := make(map[string]string)
	certByName := make(map[string]*x509.Certificate)
	for _, cert := range certs {
		if _, ok := certByName[cert.Subject.String()]; ok {
			continue
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
		seen[cert.Subject.String()] = true
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

	if reverse {
		var reversed []*x509.Certificate
		for idx := len(ordered) - 1; idx >= 0; idx-- {
			reversed = append(reversed, ordered[idx])
		}
		return reversed
	}
	return ordered
}

// SplitCertsAsTree returns a *CertTree where the given certificates
// are assigned as Certificate, Intermediates and Roots. The starting
// leaf certificate must be the first element of the given
// []*x509.Certificate.
func SplitCertsAsTree(certs []*x509.Certificate) *CertTree {
	if len(certs) == 0 {
		return nil
	}

	ordered := SortCerts(certs, false)
	var roots, inters []*x509.Certificate
	for _, cert := range ordered[1:] {
		if IsRootCA(cert) {
			roots = append(roots, cert)
		} else {
			inters = append(inters, cert)
		}
	}

	certTree := CertTree{
		Certificate:   ordered[0],
		Intermediates: inters,
		Roots:         roots,
	}

	return &certTree
}

// VerifyChain verifies the chain of a certificate as part of a CertTree. When the
// Roots field is nil, the OS trust store is used. The function return a boolean with
// the verification result and an string with an associated message with the reason
// of a negative result.
func VerifyChain(tree *CertTree) (bool, string) {
	rootPool := x509.NewCertPool()
	for _, cert := range tree.Roots {
		rootPool.AddCert(cert)
	}

	interPool := x509.NewCertPool()
	for _, cert := range tree.Intermediates {
		interPool.AddCert(cert)
	}

	var verifyOptions x509.VerifyOptions
	if len(rootPool.Subjects()) != 0 {
		verifyOptions.Roots = rootPool
	}
	if len(interPool.Subjects()) != 0 {
		verifyOptions.Intermediates = interPool
	}

	if _, err := tree.Certificate.Verify(verifyOptions); err != nil {
		return false, err.Error()
	}

	return true, ""
}

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
