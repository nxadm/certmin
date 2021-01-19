package main

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	"net"
	"net/url"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

type colourKeeper map[string]int

// Only colourise the 8 first subjects
func (colourKeeper *colourKeeper) colourise(msg string) string {
	colourStr := make(map[int]func(format string, a ...interface{}) string)
	colourStr[0] = color.GreenString
	colourStr[1] = color.BlueString
	colourStr[2] = color.MagentaString
	colourStr[3] = color.CyanString
	colourStr[4] = color.HiGreenString
	colourStr[5] = color.HiBlueString
	colourStr[6] = color.HiMagentaString
	colourStr[7] = color.HiCyanString
	if idx, ok := (*colourKeeper)[msg]; ok {
		return colourStr[idx](msg)
	}
	if len(*colourKeeper) < 8 {
		idx := len(*colourKeeper)
		(*colourKeeper)[msg] = idx
		return colourStr[idx](msg)
	}
	return msg
}

// getLocation parses an input string and it return a string with a file
// name or a rewritten hostname:port location, a boolean stating if the
// location is remote and an error.
func getLocation(input string) (string, bool, error) {
	// Local file
	_, err := os.Stat(input)
	if err == nil {
		return input, false, nil
	}

	// Remote
	location, err := parseURL(input)
	if err == nil {
		return location, true, nil
	}
	location, err = parseURL("certmin://" + input) // Add a scheme
	if err == nil {
		return location, true, nil
	}

	return "", false, fmt.Errorf("%s is not a file or a remote location", input)
}

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
			return "", fmt.Errorf("invalid port (%s)", portStr)
		}
	}

	return parsedURL.Hostname() + ":" + strconv.Itoa(port), nil
}
