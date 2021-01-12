package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func retrieveCerts(network, addr string, remoteChain bool) ([]*x509.Certificate, error) {
	conn, err := tls.Dial(network, addr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return nil, err
	}
	defer conn.Close()

	if remoteChain {
		return conn.ConnectionState().PeerCertificates, nil

	}
	return []*x509.Certificate{conn.ConnectionState().PeerCertificates[0]}, nil
}
