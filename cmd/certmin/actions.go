package main

import (
	"crypto/x509"
	"fmt"
	"github.com/fatih/color"
	"strings"
	"text/tabwriter"

	"github.com/nxadm/certmin"
)

// actionFunc is a type for actions and their expected output as string and error.
type actionFunc func() (string, error)

// skimCerts prints relevant information of local or remote certificates,
// optionally including a remote chain.
func skimCerts(locations []string, params Params) (string, error) {
	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 0, 1, ' ', tabwriter.StripEscape)

	for _, input := range locations {
		var certs []*x509.Certificate
		colourKeeper := make(colourKeeper)

		sb.WriteString("\nCertificate location " + input + ":\n\n")
		certs, err := getCerts(input, &sb)
		if err != nil {
			w.Flush()
			return sb.String(), err
		}

		if params.leaf || params.follow { // We only want the leaf
			certs = certmin.SortCerts(certs, false)
			certs = []*x509.Certificate{certs[0]}
		}

		if params.follow {
			certs, err = certmin.RetrieveChainFromIssuerURLs(certs[0], timeOut)
			if err != nil {
				w.Flush()
				return sb.String(), err
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
		fmt.Fprint(w, "---\n")

		if params.keep {
			output, err := writeCertFiles(certs, false)
			if err != nil {
				w.Flush()
				return sb.String(), err
			}
			sb.WriteString("\n" + output)
		}

	}

	w.Flush()
	return sb.String(), nil
}

// verifyChain verifies that local or remote certificates match their chain,
// supplied as local files, system-trust and/or remotely.
func verifyChain(locations []string, params Params) (string, error) {
	var sb strings.Builder
	for _, input := range locations {
		var certs []*x509.Certificate
		sb.WriteString("\nCertificate location " + input + ":\n\n")
		certs, err := getCerts(input, &sb)
		if err != nil {
			return sb.String(), err
		}

		cert := certs[0]
		if params.follow {
			certs, err = certmin.RetrieveChainFromIssuerURLs(cert, timeOut)
			if err != nil {
				return sb.String(), err
			}
		}

		tree := certmin.SplitCertsAsTree(certs)
		result, err := appendToCertTree(tree.Roots, params.roots)
		if err != nil {
			return sb.String(), err
		}
		tree.Roots = result
		result, err = appendToCertTree(tree.Intermediates, params.inters)
		if err != nil {
			return sb.String(), err
		}
		tree.Intermediates = result

		verified, _ := certmin.VerifyChain(tree)
		if verified {
			msg := "certificate " + cert.Subject.CommonName + " and its chain match\n"
			sb.WriteString(color.GreenString((msg)))
		} else {
			msg := "certificate " + cert.Subject.CommonName + " and its chain do not match\n"
			sb.WriteString(color.RedString((msg)))
		}
		sb.WriteString("---\n")

		if params.keep {
			output, err := writeCertFiles(certs, false)
			if err != nil {
				return sb.String(), err
			}
			sb.WriteString("\n" + output)
		}

	}

	return sb.String(), nil
}

// verifyKey verifies a local or remote certificate and a key match
func verifyKey(keyFile string, locations []string, params Params) (string, error) {
	var sb strings.Builder
	key, err := certmin.DecodeKeyFile(keyFile, "")
	if err != nil {
		passwordBytes, err := promptForKeyPassword()
		if err != nil {
			return "", err
		}

		key, err = certmin.DecodeKeyFile(keyFile, string(passwordBytes))
		if err != nil {
			return "", err
		}
	}

	for _, input := range locations {
		var certs []*x509.Certificate
		sb.WriteString("\nCertificate location " + input + ":\n\n")
		certs, err := getCerts(input, &sb)
		if err != nil {
			return sb.String(), err
		}
		cert := certs[0]

		verified := certmin.VerifyCertAndKey(cert, key)
		if verified {
			msg := "certificate " + cert.Subject.CommonName + " and its key match\n"
			sb.WriteString(color.GreenString((msg)))
		} else {
			msg := "certificate " + cert.Subject.CommonName + " and its key do not match\n"
			sb.WriteString(color.RedString((msg)))
		}
		sb.WriteString("---\n")

		if params.keep {
			output, err := writeCertFiles([]*x509.Certificate{cert}, false)
			if err != nil {
				return sb.String(), err
			}
			sb.WriteString("\n" + output)
		}

	}

	return sb.String(), nil
}
