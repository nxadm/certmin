package certmin

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"time"
)

// RetrieveCertsFromAddr retrieves all the certificates offered by the remote host. As parameters
// it takes an address string in the form of hostname:port and a time-out duration for the
// connection. The time-out is used for both the TCP and the SSL connection, with 0 disabling it.
// The return values are an array of certificates (with the first element being the certificate
// of the server), an error with a warning (mismatch between the hostname and the CN or DNS alias
// in the certificate) and an error in case of failure.
func RetrieveCertsFromAddr(addr string, timeOut time.Duration) ([]*x509.Certificate, error, error) {
	conn, err := net.DialTimeout("tcp", addr, timeOut)
	if err != nil {
		return nil, nil, err
	}

	var warning error
	rx := regexp.MustCompile(":\\d+$")
	tlsConn := tls.Client(conn, &tls.Config{ServerName: rx.ReplaceAllString(addr, "")})
	err = tlsConn.SetDeadline(time.Now().Add(timeOut))
	if err != nil {
		return nil, nil, err
	}
	err = tlsConn.Handshake()
	if err != nil {
		tlsConn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		err2 := tlsConn.SetDeadline(time.Now().Add(timeOut))
		if err2 != nil {
			return nil, nil, err2
		}
		err2 = tlsConn.Handshake()
		if err2 != nil {
			return nil, nil, err2
		}
		warning = err
	}
	defer tlsConn.Close()
	defer conn.Close()

	if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		err := errors.New("no certificates found")
		return nil, warning, err
	}

	return tlsConn.ConnectionState().PeerCertificates, warning, nil
}

func RetrieveCertsFromIssuerURLs(cert *x509.Certificate, timeOut time.Duration) ([]*x509.Certificate, error) {
	if cert == nil || len(cert.IssuingCertificateURL) == 0 {
		return nil, errors.New("no Issuing Certificate URLs")
	}

	lastCert := cert
	var tmpCerts []*x509.Certificate
	tmpCerts = append(tmpCerts, cert)
	client := http.Client{Timeout: timeOut}
	var lastErr error
OUTER:
	for lastCert != nil {
		for _, url := range lastCert.IssuingCertificateURL {
			fmt.Printf("HERE %s\n", url)
			resp, err := client.Get(url)
			if err != nil {
				lastErr = err
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			fmt.Printf("%#v\n", string(bodyBytes))
			if err != nil {
				lastErr = err
				continue
			}
			defer resp.Body.Close()
			// TODO: Certificate can be in DER x509.ParsePKIXPublicKey
			decodedCerts, err := DecodeCertBytes(bodyBytes)
			if err != nil {
				lastErr = err
				continue
			}

			tmpCerts = append(tmpCerts, decodedCerts[0])
			lastCert = decodedCerts[0]
			if IsRootCA(decodedCerts[0]) {
				break OUTER
			}
			continue
		}
		break OUTER
	}
	return tmpCerts[1:], lastErr
}
