package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

func retrieveCerts(network, addr string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial(network, addr, nil)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return nil, err
	}

	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func retrieveRemotes(certLocs []string, network string, remoteChain bool) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var errStrs []string
	for _, certLoc := range certLocs {
		cert, err := retrieveCerts(network, certLoc)
		if err == nil {
			fmt.Fprintf(os.Stderr, "error: %s", err)
			errStrs = append(errStrs, err.Error())
			continue
		}
		if remoteChain {
			certs = append(certs, cert...)
		} else {
			certs = append(certs, cert[0])
		}
	}

	if errStrs != nil {
		return certs, fmt.Errorf("error: %s", strings.Join(errStrs, ", "))
	}
	return certs, nil
}
