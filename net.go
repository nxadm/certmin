package certmin

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RetrieveCertsFromAddr retrieves all the certificates offered by the remote host. As parameters
// it takes an address string (hostname, hostname:port, scheme://hostname or scheme://hostname:port)
// and a time-out duration for the connection. If a port is not specified or can not be inferred
// from the URI scheme, port 443 is used as a default. The time-out is used for both the TCP and the
// SSL connection, with 0 disabling it.
//
// The return values are a []*x509.Certificate (with the first element being the certificate
// of the server), an error with a TLS warning (e.g. expired TLS cert, mismatch between the hostname
// and the CN or alias) and an error in case of failure.
func RetrieveCertsFromAddr(addr string, timeOut time.Duration) ([]*x509.Certificate, error, error) {
	var certs []*x509.Certificate
	var parsedAddr string
	var err, warn error

	// Normalize the addr
	parsedAddr, err = parseIP(addr)
	if err != nil {
		parsedAddr, err = parseURL(addr)
		if err != nil {
			return nil, nil, err
		}
	}

	certs, warn = connectAndRetrieve(parsedAddr, timeOut, false)
	if warn != nil {
		certs, err = connectAndRetrieve(parsedAddr, timeOut, true)
		if err != nil {
			warn = nil
		}
	}

	return certs, warn, err
}

// RetrieveChainFromIssuerURLs retrieves the chain for a certificate by following the
// Issuing Certificate URLs field in the certificate (if present) and consecutively
// following the Issuing Certificate URLs from issuing certificates. As parameters
// it takes a *x509.Certificate and a time-out duration for the HTTP connection with
// 0 disabling it. The return values are a []*x509.Certificate (with the first element
// being the supplied certificate) and an error in case of failure.
func RetrieveChainFromIssuerURLs(cert *x509.Certificate, timeOut time.Duration) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	var lastErr error
	recursiveHopCerts(cert, &chain, &lastErr, timeOut)
	return chain, lastErr
}

// connectAndRetrieve does the actual TLS calls
func connectAndRetrieve(addr string, timeOut time.Duration, skipVerify bool) ([]*x509.Certificate, error) {
	serverName := regexp.MustCompile(`:\d+$`).ReplaceAllString(addr, "")
	var tlsConfig tls.Config
	if skipVerify {
		tlsConfig.InsecureSkipVerify = true
	} else {
		tlsConfig.ServerName = serverName
	}

	dialer := &net.Dialer{Timeout: timeOut}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("[%s] %s", serverName, err)
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return nil, errors.New("no certificates found")
	}

	return conn.ConnectionState().PeerCertificates, nil
}

// parseIP parses a given ip:port and returns a string in the form of
// hostname:port (with port 443 as default if none given) and an error
// if the parsing fails.
func parseIP(remote string) (string, error) {
	var host, port string
	var err, err2 error

	host, port, err = net.SplitHostPort(remote)
	if err != nil {
		host, port, err2 = net.SplitHostPort(remote + ":443")
		if err2 != nil {
			return "", err
		}
	}

	parts := strings.Split(host, "/")
	if net.ParseIP(parts[0]) != nil {
		return parts[0] + ":" + port, nil
	}
	return "", errors.New("not an IP")
}

// parseURL parses a given URL and return a string in the form of
// hostname:port (with port 443 as default if none given) and an
// error if the parsing fails.
func parseURL(remote string) (string, error) {
	parsedURL, err := url.Parse(remote)
	if err != nil {
		return "", err
	}

	host := parsedURL.Host
	if host == "" {
		return parseURL("certmin://" + remote) // Add a scheme
	}

	scheme := parsedURL.Scheme
	portStr := parsedURL.Port()
	if portStr == "" {
		port, err := net.LookupPort("tcp", scheme)
		if err == nil {
			portStr = strconv.Itoa(port)
		} else {
			portStr = "443"
		}
	}

	return parsedURL.Hostname() + ":" + portStr, nil
}

// recursiveHopCerts follows the URL links recursively
func recursiveHopCerts(
	cert *x509.Certificate, chain *[]*x509.Certificate, lastErr *error, timeOut time.Duration) *x509.Certificate {
	if cert == nil {
		return nil
	}

	client := http.Client{Timeout: timeOut}
	*chain = append(*chain, cert)
	for _, url := range cert.IssuingCertificateURL {
		resp, err := client.Get(url)
		if err != nil {
			*lastErr = err
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			*lastErr = err
			continue
		}
		defer resp.Body.Close()

		decodedCerts, err := DecodeCertBytes(bodyBytes, "")
		if err != nil {
			*lastErr = err
			continue
		}

		*lastErr = nil
		return recursiveHopCerts(decodedCerts[0], chain, lastErr, timeOut)
	}

	return nil
}
