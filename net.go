package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
)

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
			port = 443
		}
	}

	return parsedURL.Hostname() + ":" + strconv.Itoa(port), nil
}

func retrieveCerts(addr string, remoteChain bool) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", addr, nil)
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
