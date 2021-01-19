package main

import (
	"crypto/x509"
	"fmt"
	"github.com/fatih/color"
	"github.com/nxadm/certmin"
	"strings"
	"text/tabwriter"
)

// actionFunc is a type for actions and their expected output as string and error.
type actionFunc func() (string, error)

// skimCerts prints relevant information of local or remote certificates,
// optionally including a remote chain.
func skimCerts(locations []string, params Params) (string, error) {
	var err, warn error
	var certs []*x509.Certificate
	var sb strings.Builder
	var loc string
	var remote bool
	w := tabwriter.NewWriter(&sb, 0, 0, 1, ' ', tabwriter.StripEscape)
	colourKeeper := make(colourKeeper)

	for _, input := range locations {
		sb.WriteString("\ncertificate location " + input + ":\n\n")
		loc, remote, err = getLocation(input)
		if err != nil {
			return "", err
		}

		if remote {
			certs, warn, err = certmin.RetrieveCertsFromAddr(loc, timeOut)
			if warn != nil {
				sb.WriteString(color.YellowString(warn.Error()))
			}
		} else {
			certs, err = certmin.DecodeCertFile(loc)
		}

		if err != nil {
			return "", err
		}

		if params.leaf || params.follow { // We only want the leaf
			certs = certmin.SortCerts(certs, false)
			certs = []*x509.Certificate{certs[0]}
		}

		if params.follow {
			certs, err = certmin.RetrieveChainFromIssuerURLs(certs[0], timeOut)
			if err != nil {
				return "", err
			}
		}

		switch {
		case params.sort:
			certs = certmin.SortCerts(certs, false)
		case params.rsort:
			certs = certmin.SortCerts(certs, true)
		}

		for idx, cert := range certs {
			printCert(cert, w, colourKeeper)
			if idx < len(certs)-1 {
				fmt.Fprintln(w, "\t")
			}
		}
	}

	fmt.Fprint(w, "---")
	w.Flush()
	return sb.String(), nil
}

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
	fmt.Fprintf(w, "Serial number:\t%s\n", cert.SerialNumber)
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

// verifyChain verifies that local or remote certificates match their chain,
// supplied as local files, system-trust and/or remotely.
func verifyChain(locations []string, params Params) (string, error) {
	return "", nil
}

// verifyKey verifies a local or renote certificate and a key match
func verifyKey(location, keyFile string, passwordBytes []byte, prompt, keep bool) (string, error) {
	return "", nil
}
