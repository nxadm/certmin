package certmin

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// promptForKeyPassword prompts the user for the password to
// decrypt a private key. It returns the password as a []byte
// and an error.
func promptForKeyPassword() ([]byte, error) {
	fmt.Print("Enter password of private key: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return bytePassword, nil
}

// parseURL parses a given URL and return a string in the form of
// hostname:port or an error if the parsing fails.
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
