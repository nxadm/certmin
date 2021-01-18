package certmin

//
//import (
//	"crypto/tls"
//	"crypto/x509"
//	"errors"
//	"fmt"
//	"net"
//	"net/url"
//	"os"
//	"strconv"
//
//	"github.com/fatih/color"
//)
//

//func retrieveCerts(addr string) ([]*x509.Certificate, error) {
//	var conn *tls.Conn
//	var err1, err2 error
//	conn, err1 = tls.Dial("tcp", addr, nil)
//	if err1 != nil {
//		conn, err2 = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
//		if err2 != nil {
//			return nil, err2
//		}
//		fmt.Fprintf(os.Stderr, color.YellowString("\nWARNING: %s\n"), err1)
//	}
//	defer conn.Close()
//
//	if len(conn.ConnectionState().PeerCertificates) == 0 {
//		err := errors.New("no certificates found")
//		return nil, err
//	}
//
//	return conn.ConnectionState().PeerCertificates, nil
//}
