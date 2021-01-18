package certmin

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"regexp"
	"time"
)

// RetrieveRemoteCerts retrieves all the certificates offered by the remote host. As parameters
// it takes an address string in the form of hostname:port and a time-out duration for the
// connection. The time-out is used for both the TCP and the SSL connection, with 0 disabling it.
// The return values are an array of certificates (with the first element being the certificate
// of the server), an error with a warning (mismatch between the hostname and the CN or DNS alias
// in the certificate) and an error in case of failure.
func RetrieveRemoteCerts(addr string, timeOut time.Duration) ([]*x509.Certificate, error, error) {
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
