package main

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	flag "github.com/spf13/pflag"
	"os"
	"strings"
)

const usage = `certmin, ` + version + `. A minimalist certificate utility.
See ` + website + ` for more information.

Usage:
  certmin skim cert-location1 [cert-location2...] 
     [--remotes] [--no-roots] [--follow]
     [--sort] [--keep] [--no-colour]
  certmin verify-chain cert-location [cert-location2...]
    [--root=ca-file1 --root=ca-file2...]
    [--inter=inter-file1 --inter=inter-file2...]
     [--remotes] [--no-roots] [--follow]
    [--sort] [--keep] [--no-colour]
  certmin verify-key key-file cert-location1 [cert-location2...]
    [--keep] [--no-colour]
  certmin [-h]
  certmin [-v]

Certificate locations can be local files or remote addresses. Remote locations
can be a hostname with optionally a port attached by ":" (defaults to port
443) or an URL (scheme://hostname for known schemes like https, ldaps, smtps,
etc. or scheme://hostname:port for non-standard ports). When verifying a
chain, the OS trust store will be used if no roots certificates are given as
files or remotely requested. 

Actions:
  skim         | sc : skim certificates (including bundles).
  verify-chain | vc : match certificates again its chain(s).
  verify-key   | vk : match keys against certificate(s).

Global options (optional):
  --remotes   | -x  : retrieve the chain offered by the remote host.
  --no-roots  | -n  : don't retrieve root certificates.
  --follow    | -f  : follow Issuer Certificate URIs to retrieve chain.
  --root      | -r  : root certificate file(s).
  --inter     | -i  : intermediate certificate file(s).
  --sort      | -s  : sort the certificates and chains from leave to root.
  --keep      | -k  : write the requested certificates and chains to files.
  --no-colour | -c  : don't colourise the output.
  --help      | -h  : this help message.
  --version   | -v  : version message.
`

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
	roots := flags.StringSliceP("root", "r", []string{}, "")
	inters := flags.StringSliceP("inter", "i", []string{}, "")
	remotes := flags.BoolP("remotes", "x", false, "")
	follow := flags.BoolP("follow", "f", false, "")
	noRoots := flags.BoolP("no-roots", "n", false, "")
	sort := flags.BoolP("sort", "s", false, "")
	keep := flags.BoolP("keep", "k", false, "")
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

	return verifyAndDispatch(*help, *progVersion, *remotes, *follow,
		*noRoots, *sort, *keep, *roots, *inters, flags.Args())
}

// verifyAndDispatch takes the cli parameters, verifies them
// and returns an action to be run and an possible exit status.
func verifyAndDispatch(help, progVersion, remotes, follow, noRoots, sort, keep bool,
	roots, inters, args []string) (actionFunc, string, error) {
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
	case remotes && follow:
		return nil, "", errors.New("--remotes and --follow are mutually exclusive")
	case len(args) < 3:
		return nil, "", errors.New("no certificate location given")

	case args[1] == "skim" || args[1] == "sc":
		// Add them quietly
		locs := args[2:]
		locs = append(locs, roots...)
		locs = append(locs, inters...)
		return func() (string, error) {
			return skimCerts(locs, remotes, follow, noRoots, sort, keep)
		}, "", nil

	case args[1] == "verify-chain" || args[1] == "vc":
		return func() (string, error) {
			return verifyChain(args[2:], roots, inters, remotes, follow, noRoots, keep)
		}, "", nil

	case (args[1] == "verify-key" || args[1] == "vk") && len(args) != 4:
		return nil, "", errors.New("verify-key needs 1 certificate location and 1 key file")
	case args[1] == "verify-key" || args[1] == "vk":
		return func() (string, error) { return verifyKey(args[2], args[3], nil, true, keep) }, "", nil

	default:
		return nil, "", errors.New("unknown command")
	}
}
