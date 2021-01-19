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

// verifyChain verifies that local or remote certificates match their chain,
// supplied as local files, system-trust and/or remotely.
func verifyChain(locations []string, params Params) (string, error) {
	return "", nil
}

// verifyKey verifies a local or renote certificate and a key match
func verifyKey(location, keyFile string, passwordBytes []byte, prompt, keep bool) (string, error) {
	return "", nil
}
