package main

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
)

const usage = `certmin, ` + version + `. A minimalist certificate utility.
See ` + website + ` for more information.

Usage:
  certmin skim [--tcp|--udp] [--remote-chain] cert-location1 cert-location2...
  certmin vk   [--tcp|--udp] cert-location key-file
  certmin vc   [--tcp|--udp] [--remote-chain] cert-location 
    --root=ca-file1 [--root=ca-file2 ...]
    --inter=inter-file1 [--inter=inter-file2 ...]
  certmin [-h]
  certmin [-v]

Actions:
  skim         | sc        : skim PEM certificate files (including bundles)
							 and show information.
    --remote-chain         : also retrieve the chain (if offered) when
							 retrieving remote certificates (--tcp or --udp).

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
  --tcp                    : retrieve the certificate files through TCP
                             (format "hostname:port"). 
  --udp                    : retrieve the certificate files through UDP
                             (format "hostname:port").
  -h           | --help    : This help message.
  -v           | --version : Version message.
`

//[not yet implemented]
//generate-selfsigned | gs : generate a self-signed PEM certificate.

var mock bool
var mockArgs []string

type actionFunc func()

func getAction() (func(), int) {
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

	if len(os.Args) == 1 && !mock {
		flags.Usage()
		exitWrapper(0)
	}

	help := flags.BoolP("help", "h", false, "")
	progVersion := flags.BoolP("version", "v", false, "")
	roots := flags.StringSlice("root", []string{}, "")
	inters := flags.StringSlice("inter", []string{}, "")
	remoteChain := flags.BoolP("remote-chain", "r", false, "")
	tcp := flags.BoolP("tcp", "t", false, "")
	udp := flags.BoolP("udp", "u", false, "")

	if !mock {
		err := flags.Parse(os.Args)
		if err != nil {
			panic(err)
		}
	} else {
		_ = flags.Parse(mockArgs)
	}

	network := "tcp"
	if *udp {
		network = "udp"
	}

	args := flag.Args()
	action, exitStatus :=
		verifyAndDispatch(help, progVersion, tcp, udp, remoteChain, network, roots, inters, &args)
	if exitStatus != -1 {
		exitWrapper(exitStatus)
	}

	return action, -1 // the exitcode facilitates testing
}

func verifyAndDispatch(
	help, progVersion, tcp, udp, remoteChain *bool, network string, roots, inters, argsPtr *[]string) (actionFunc, int) {
	var exitStatus int
	var action actionFunc
	args := *argsPtr

	switch {
	case *help:
		fmt.Println(usage)
	case *progVersion:
		fmt.Println("certmin, " + version)
	case *tcp && *udp:
		fmt.Fprintf(os.Stderr, "error: --tcp and --udp can not be combined\n")
	case *remoteChain && !(*tcp || *udp):
		fmt.Fprintf(os.Stderr, "error: remote-chain is only valid with --tcp or --udp\n")
	case len(*argsPtr) < 2:
		fmt.Fprintf(os.Stderr, "error: no certificate location given\n")

	case args[1] == "skim" || args[1] == "sc":
		action, exitStatus = skimCmdParse(args[2:], network, *remoteChain)

	case (args[1] == "verify-chain" || args[1] == "vc") && len(args) != 3:
		fmt.Fprintf(os.Stderr, "error: only a single certificate is valid for verify-chain\n")
	case (args[1] == "verify-chain" || args[1] == "vc") && (!*remoteChain && len(*roots) == 0):
		fmt.Fprintf(os.Stderr, "error: no local root certificates given to verify-chain\n")
	case args[1] == "verify-chain" || args[1] == "vc":
		action, exitStatus = verifyChainCmdParse(*roots, *inters, args[2], network, *remoteChain)

	case (args[1] == "verify-key" || args[1] == "vk") && *remoteChain:
		fmt.Fprintf(os.Stderr, "error: remote-chain is not valid with verify-key\n")
	case (args[1] == "verify-key" || args[1] == "vk") && len(args) != 3:
		fmt.Fprintf(os.Stderr, "error: verify-key needs 1 certificate localtion and 1 key file\n")
	case args[1] == "verify-key" || args[1] == "vk":
		action, exitStatus = verifyKeyCmdParse(args[2], args[3], network)

	default:
		fmt.Println(usage)
	}

	return action, exitStatus
}

func skimCmdParse(certLocs []string, network string, remoteChain bool) (func(), int) {
	return func() {
		skimCerts(certLocs, network, remoteChain)
	}, -1
}

func verifyChainCmdParse(roots, inters []string, certLoc, network string, remoteChain bool) (func(), int) {
	return func() {
		verifyChainFromFiles(roots, inters, certLoc, network, remoteChain)
	}, -1
}

func verifyKeyCmdParse(certLoc, keyFile, network string) (func(), int) {
	return func() {
		verifyCertAndKey(certLoc, keyFile, network)
	}, -1
}

func exitWrapper(exitStatus int) func() int {
	if !mock {
		os.Exit(exitStatus)
	}
	return func() int { return exitStatus }
}
