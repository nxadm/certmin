package main

import (
	"fmt"
	"os"

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

type actionFunc func()

func getAction() (func(), int) {
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

	action, exitStatus :=
		verifyAndDispatch(*help, *progVersion, *remoteChain, *roots, *inters, flags.Args())
	if exitStatus != -1 {
		os.Exit(exitStatus)
	}

	return action, -1 // the exitcode facilitates testing
}

func skimCmdParse(certLocs []string, remoteChain bool) (func(), int) {
	return func() {
		skimCerts(certLocs, remoteChain)
	}, -1
}

func verifyChainCmdParse(roots, inters []string, certLoc string, remoteChain bool) (func(), int) {
	return func() {
		verifyChainFromLoc(roots, inters, certLoc, remoteChain)
	}, -1
}

func verifyKeyCmdParse(certLoc, keyFile string) (func(), int) {
	return func() {
		verifyKey(certLoc, keyFile)
	}, -1
}

// verifyAndDispatch takes the cli parameters, verifies them amd returns an action to
// be run and an possible exitstatus.
func verifyAndDispatch(
	help, progVersion, remoteChain bool, roots, inters, args []string) (actionFunc, int) {
	var exitStatus int
	var action actionFunc

	switch {
	case help || len(args) == 1:
		fmt.Println(usage)
	case progVersion:
		fmt.Println("certmin, " + version)
	case len(args) < 3:
		fmt.Fprintf(os.Stderr, "error: no certificate location given\n")
		exitStatus = 1

	case args[1] == "skim" || args[1] == "sc":
		action, exitStatus = skimCmdParse(args[2:], remoteChain)

	case (args[1] == "verify-chain" || args[1] == "vc") && len(args) != 3:
		fmt.Fprintf(os.Stderr, "error: only a single certificate is valid for verify-chain\n")
		exitStatus = 1
	case (args[1] == "verify-chain" || args[1] == "vc") && (!remoteChain && len(roots) == 0):
		fmt.Fprintf(os.Stderr, "error: no local root certificates given to verify-chain\n")
		exitStatus = 1
	case args[1] == "verify-chain" || args[1] == "vc":
		action, exitStatus = verifyChainCmdParse(roots, inters, args[2], remoteChain)

	case (args[1] == "verify-key" || args[1] == "vk") && remoteChain:
		fmt.Fprintf(os.Stderr, "error: remote-chain is not valid with verify-key\n")
		exitStatus = 1
	case (args[1] == "verify-key" || args[1] == "vk") && len(args) != 4:
		fmt.Fprintf(os.Stderr, "error: verify-key needs 1 certificate localtion and 1 key file\n")
		exitStatus = 1
	case args[1] == "verify-key" || args[1] == "vk":
		action, exitStatus = verifyKeyCmdParse(args[2], args[3])

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command and parameters\n")
		exitStatus = 1
	}

	return action, exitStatus
}
