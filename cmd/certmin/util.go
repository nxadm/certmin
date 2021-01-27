package main

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/nxadm/certmin"
	"golang.org/x/crypto/ssh/terminal"
)

// Compile the regex once
var rxNormalize = regexp.MustCompile("[^a-zA-Z0-9_-]")

// colourKeeper keeps track of certain output that must have the same color.
// e.g. the CN as Subject and Issuer.
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

// appendToCertTree adds roots and intermediates from file to a CertTree
func appendToCertTree(inTree []*x509.Certificate, toAdd []string) ([]*x509.Certificate, error) {
	if toAdd != nil {
		var certs []*x509.Certificate
		for _, file := range toAdd {
			tmpCerts, err := certmin.DecodeCertFile(file, "")
			if err != nil {
				return nil, err
			}
			certs = append(certs, tmpCerts...)
		}
		inTree = append(inTree, certs...)
	}
	return certmin.SortCerts(inTree, false), nil
}

// getCerts does the optional downloading and parsing of certificates
func getCerts(input string, sb *strings.Builder) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var err, warn error

	loc, remote, err := getLocation(input)
	if err != nil {
		return nil, err
	}

	if remote {
		certs, warn, err = certmin.RetrieveCertsFromAddr(loc, timeOut)
		if warn != nil {
			sb.WriteString(color.YellowString(warn.Error()) + "\n\n")
		}
		if err != nil {
			return nil, err
		}
	} else {
		certs, err = certmin.DecodeCertFile(loc, "")
		if err != nil {
			if strings.Contains(err.Error(), "pkcs12: decryption password incorrect") {
				passwordBytes, err := promptForKeyPassword()
				if err != nil {
					return nil, err
				}

				certs, err = certmin.DecodeCertFile(loc, string(passwordBytes))
				if err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}
	return certs, nil
}

// getLocation parses an input string and it return a string with a file
// name or a rewritten hostname:port location, a boolean stating if the
// location is remote and an error.
func getLocation(input string) (string, bool, error) {
	// Local file
	_, err := os.Stat(input)
	if err == nil {
		return input, false, nil
	}

	// Remote
	location, err := parseURL(input)
	if err == nil {
		return location, true, nil
	}
	location, err = parseURL("certmin://" + input) // Add a scheme
	if err == nil {
		return location, true, nil
	}

	return "", false, fmt.Errorf("%s is not a file or a remote location", input)
}

// parseURL parses a given URL and return a string in the form of
// hostname:port or an error if the parsing fails.
func parseURL(remote string) (string, error) {
	parsedURL, err := url.Parse(remote)
	if err != nil {
		return "", err
	}

	host := parsedURL.Host
	if host == "" {
		return "", errors.New("no hostname found")
	}

	scheme := parsedURL.Scheme
	portStr := parsedURL.Port()
	var port int
	if portStr == "" {
		foundPort, err := net.LookupPort("tcp", scheme)
		if err == nil {
			port = foundPort
		} else {
			port = 443
		}
	} else {
		port, err = strconv.Atoi(portStr) // prefer explicit port
		if err != nil {
			return "", fmt.Errorf("invalid port (%s)", portStr)
		}
	}

	return parsedURL.Hostname() + ":" + strconv.Itoa(port), nil
}

// printCert prints the relevant information of certificate
func printCert(cert *x509.Certificate, w *tabwriter.Writer, colourKeeper colourKeeper) {
	fmt.Fprintf(w, "Subject:\t%s\n", colourKeeper.colourise(cert.Subject.String()))
	fmt.Fprintf(w, "Issuer:\t%s\n", colourKeeper.colourise(cert.Issuer.String()))
	if len(cert.IssuingCertificateURL) > 0 {
		fmt.Fprintf(w, "Issuer Certificate URLs:\t%s\n",
			strings.Join(cert.IssuingCertificateURL, ", "))
	}
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

	fmt.Fprintf(w, "Serial number:\t%s\n", serialAsHex(cert.SerialNumber))
	fmt.Fprintf(w, "Version:\t%d\n", cert.Version)

	if cert.IsCA {
		fmt.Fprintf(w, "Is CA:\t%t\n", true)
	}
	if cert.MaxPathLen > 0 {
		fmt.Fprintf(w, "MaxPathLen:\t%d\n", cert.MaxPathLen)
	}
	if cert.MaxPathLenZero {
		fmt.Fprintf(w, "MaxPathLen is 0:\t%t\n", cert.MaxPathLenZero)
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
}

// promptForKeyPassword prompts the user for the password to
// decrypt a private key. It returns the password string and
// an error.
func promptForKeyPassword() (string, error) {
	fmt.Print("Enter the decryption password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}

// serialAsHex converts a *big.Int Serial to a hex string with ":" every 2 characters.
func serialAsHex(serial *big.Int) string {
	bytes := serial.Bytes()
	buf := make([]byte, 0, 3*len(bytes))
	hexRecipient := buf[1*len(bytes) : 3*len(bytes)]
	hex.Encode(hexRecipient, bytes)
	for i := 0; i < len(hexRecipient); i += 2 {
		buf = append(buf, hexRecipient[i], hexRecipient[i+1], ':')
	}
	return string(buf[:len(buf)-1])
}

// writeCertFiles writes certificates to disk
func writeCertFiles(certs []*x509.Certificate, cleanup bool) (string, error) {
	tree := certmin.SplitCertsAsTree(certs)
	if tree.Certificate == nil {
		return "", errors.New("no certificate found")
	}

	baseName := "certmin_" + rxNormalize.ReplaceAllString(tree.Certificate.Subject.CommonName, "_") + "_" +
		time.Now().Format("20060102150405")

	ext := make(map[int]string)
	ext[0] = ".crt"
	ext[1] = "_intermediates.crt"
	ext[2] = "_roots.crt"

	var sb strings.Builder
	sb.WriteString("The following files were written:\n")

	for idx, certArray := range [][]*x509.Certificate{{tree.Certificate}, tree.Intermediates, tree.Roots} {
		var file *os.File
		var err error
		if len(certArray) > 0 {
			file, err = os.Create(baseName + ext[idx])
			if err != nil {
				file, err = os.Create(path.Join(os.TempDir(), baseName+ext[idx]))
				if err != nil {
					return "", err
				}
			}
		}
		for _, cert := range certArray {
			pemBytes, err := certmin.EncodeCertAsPKCS1PEM(cert)
			if err != nil {
				return "", err
			}

			_, err = file.Write(pemBytes)
			if err != nil {
				return "", err
			}
		}

		if file != nil {
			file.Close()
			sb.WriteString(file.Name() + "\n")
		}
		if cleanup {
			defer os.Remove(file.Name())
		}
	}

	return sb.String(), nil
}
