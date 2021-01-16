package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/fatih/color"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"
)

const usage = `certmin, ` + version + `. A minimalist certificate utility.
See ` + website + ` for more information.

Usage:
  certmin skim cert-location1 [cert-location2...] 
	 [--remote-chain] [--remote-inters] [--no-colour] 
  certmin verify-key cert-location key-file [--no-colour]
  certmin verify-chain cert-location [cert-location2...]
	[--remote-chain] [--remote-inters] 
    [--root=ca-file1 --root=ca-file2...]
    [--inter=inter-file1 --inter=inter-file2...]
    [--no-colour]
  certmin [-h]
  certmin [-v]

Certificate locations can be a file, a string in the form of
hostname:port (default 443 if not :port supplied) or an URL.
When verifying a chain, the OS trust store will be used if
if no roots certificates are given or requested. 

Actions:
  skim | sc         : skim PEM certificates (including bundles)
                      and show information.
    --remote-chain  : retrieve the chain (if offered) for
                      remote certificates.

  verify-key | vk   : verify that a PEM certificate and
                      key match.

  verify-chain | vc : verify that a PEM certificate matches its
                      chain.
    --remote-chain  : retrieve the chain (if offered) for
                      remote certificates.
    --remote-inters : retrieve the chain (if offered) for
                      remote certificates, without root CAs.
    --root          : root PEM certificate file to verify.
                      against (optional). 
    --inter         : intermediate PEM certificates files
                      to verify against (optional).

Global options:
  --no-colour | -c : don't colourise the output'
  --help      | -h : this help message.
  --version   | -v : version message.
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
	remoteInters := flags.BoolP("remote-inters", "i", false, "")
	noColour := flags.BoolP("no-colour", "c", false, "")

	err := flags.Parse(os.Args)
	if err != nil {
		panic(err)
	}

	if *noColour {
		color.NoColor = true // disables colorized output
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

	return verifyAndDispatch(*help, *progVersion, *remoteChain, *remoteInters, *roots, *inters, flags.Args())
}

func promptForPassword() ([]byte, error) {
	fmt.Print("Enter password of private key: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return bytePassword, nil
}

// verifyAndDispatch takes the cli parameters, verifies them amd returns an action to
// be run and an possible exitstatus.
func verifyAndDispatch(
	help, progVersion, remoteChain, remoteInters bool, roots, inters, args []string) (actionFunc, string, error) {
	cmds := map[string]bool{
		"sc":           true,
		"skim":         true,
		"vc":           true,
		"verify-chain": true,
		"vk":           true,
		"verify-key":   true,
	}
	var invalidAction bool
	if len(args) > 1 {
		if _, ok := cmds[args[1]]; !ok {
			invalidAction = true
		}
	}

	switch {
	case help:
		return nil, usage, nil
	case progVersion:
		return nil, "certmin, " + version, nil
	case len(args) == 1:
		return nil, usage, nil
	case invalidAction:
		return nil, "", errors.New("invalid action")
	case remoteChain && remoteInters:
		return nil, "", errors.New("--remote-chain and --remote-inters are mutually exclusive")
	case len(args) < 3:
		return nil, "", errors.New("no certificate location given")

	case args[1] == "skim" || args[1] == "sc":
		return func() (string, error) { return skimCerts(args[2:], remoteChain, remoteInters) }, "", nil

	case args[1] == "verify-chain" || args[1] == "vc":
		return func() (string, error) {
			return verifyChain(roots, inters, args[2:], remoteChain, remoteInters)
		}, "", nil

	case (args[1] == "verify-key" || args[1] == "vk") && len(args) != 4:
		return nil, "", errors.New("verify-key needs 1 certificate location and 1 key file")
	case args[1] == "verify-key" || args[1] == "vk":
		return func() (string, error) { return verifyKey(args[2], args[3], nil) }, "", nil

	default:
		return nil, "", errors.New("unknown command")
	}
}
