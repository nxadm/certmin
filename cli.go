package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
)

const usage = `certmin, ` + version + `. A minimalist certificate utility.
See ` + website + ` for more information.

Usage:
  certmin skim [--remote-chain] cert-location1 cert-location2...
  certmin vk   cert-location key-file
  certmin vc   [--remote-chain] cert-location 
    --root=ca-file1 [--root=ca-file2 ...]
    --inter=inter-file1 [--inter=inter-file2 ...]
  certmin [-h]
  certmin [-v]

Certificate locations can be a file, a hostname:port (default 443) string
or a URL.

Actions:
  skim         | sc        : skim PEM certificates (including bundles)
							 and show information.
    --remote-chain         : also retrieve the chain (if offered) when
							 retrieving remote certificates.

  verify-key   | vk        : verify that a PEM certificate and unencrypted key
                             match.

  verify-chain | vc        : verify that a PEM certificate matches its chain.
    --remote-chain         : match against the chain remotely retrieved with
							 the certificate.
    --root                 : root PEM certificate file to verify against (at
                             least 1 file if not remotely retrieved). 
    --inter                : intermediate PEM certificates files to verify
                             against (0 or more).

Global options:
  -h           | --help    : This help message.
  -v           | --version : Version message.
`

//[not yet implemented]
//generate-selfsigned | gs : generate a self-signed PEM certificate.

type actionFunc func() (string, error)

// getAction returns an action function, a msg for early exit and an error.
// getAction returns an action function, a msg for early exit and an error.
func getAction() (actionFunc, string, error) {
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

	if len(os.Args) == 1 {
		flags.Usage()
		os.Exit(0)
	}

	help := flags.BoolP("help", "h", false, "")
	progVersion := flags.BoolP("version", "v", false, "")
	roots := flags.StringSlice("root", []string{}, "")
	inters := flags.StringSlice("inter", []string{}, "")
	remoteChain := flags.BoolP("remote-chain", "r", false, "")

	err := flags.Parse(os.Args)
	if err != nil {
		panic(err)
	}

	all := append(*roots, *inters...)
	var notFound []string
	for _, cert := range all {
		if _, err := os.Stat(cert); err != nil {
			notFound = append(notFound, cert)
		}
	}
	if len(notFound) > 0 {
		return nil, "", fmt.Errorf("can not find the given file (%s)", strings.Join(notFound, ", "))
	}

	return verifyAndDispatch(*help, *progVersion, *remoteChain, *roots, *inters, flags.Args())
}

// verifyAndDispatch takes the cli parameters, verifies them amd returns an action to
// be run and an possible exitstatus.
func verifyAndDispatch(
	help, progVersion, remoteChain bool, roots, inters, args []string) (actionFunc, string, error) {
	switch {
	case help || len(args) == 1:
		return nil, usage, nil
	case progVersion:
		return nil, "certmin, " + version, nil
	case len(args) < 3:
		return nil, "", errors.New("no certificate location given")

	case args[1] == "skim" || args[1] == "sc":
		return func() (string, error) { return skimCerts(args[2:], remoteChain) }, "", nil

	case (args[1] == "verify-chain" || args[1] == "vc") && len(args) != 3:
		return nil, "", errors.New("only a single certificate is valid for verify-chain")
	case (args[1] == "verify-chain" || args[1] == "vc") && (!remoteChain && len(roots) == 0):
		return nil, "", errors.New("no local root certificates given to verify-chain")
	case args[1] == "verify-chain" || args[1] == "vc":
		return func() (string, error) { return verifyChain(roots, inters, args[2], remoteChain) }, "", nil

	case (args[1] == "verify-key" || args[1] == "vk") && remoteChain:
		return nil, "", errors.New("remote-chain is not valid with verify-key")
	case (args[1] == "verify-key" || args[1] == "vk") && len(args) != 4:
		return nil, "", errors.New("verify-key needs 1 certificate location and 1 key file")
	case args[1] == "verify-key" || args[1] == "vk":
		return func() (string, error) { return verifyKey(args[2], args[3]) }, "", nil

	default:
		return nil, "", errors.New("unknown command")
	}
}
