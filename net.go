package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/fatih/color"
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

func retrieveCerts(addr string) ([]*x509.Certificate, error) {
	var conn *tls.Conn
	var err1, err2 error
	conn, err1 = tls.Dial("tcp", addr, nil)
	if err1 != nil {
		conn, err2 = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err2 != nil {
			return nil, err2
		}
		fmt.Fprintf(os.Stderr, color.YellowString("\nWARNING: %s\n"), err1)
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		err := errors.New("no certificates found")
		return nil, err
	}

	return conn.ConnectionState().PeerCertificates, nil
}
