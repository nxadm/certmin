package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
)

var schemes = map[string]int{
	"ftp":    21,
	"ftps":   990,
	"gopher": 70,
	"http":   80,
	"https":  443,
	"imap2":  143,
	"imap3":  220,
	"imaps":  993,
	"ldap":   389,
	"ldaps":  636,
	"pop3":   110,
	"pop3s":  995,
	"smtp":   25,
	"smtps":  587,
	"ssh":    22,
	"telnet": 23,
}

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
		if defaultPort, ok := schemes[scheme]; ok {
			port = defaultPort
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
