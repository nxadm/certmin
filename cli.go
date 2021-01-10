package main

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
)

const usage = `certmin, ` + version + `. A minimalist certificate utility.
See ` + website + ` for more information.

Usage:
  certmin skim certificate1 certificate2 ...
  certmin vk certificate key
  certmin vc certificate 
    --root=ca-file1 [--root=ca-file2 ...]
    --inter=inter-file1 [--inter=inter-file2 ...]
  certmin [-h]
  certmin [-v]

Actions:
  skim         | s         : skim information from PEM certificates.
  verify-key   | vk        : verify that a PEM certificate matches an unencrypted PEM key.
  verify-chain | vc        : verify that a PEM certificate matches a PEM chain.
    --root                 : root PEM certificates to verify against (at least 1 file). 
    --inter                : intermediate PEM certificates to verify against (0 or more).
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
	if !mock {
		flags.Parse(os.Args)
	} else {
		flags.Parse(mockArgs)
	}

	var exitStatus int
	var action actionFunc
	switch {
	case *help:
		flags.Usage()
	case *progVersion:
		fmt.Println("certmin, " + version)
	case flags.Arg(1) == "skim" || flags.Arg(1) == "s":
		action, exitStatus = skimCmdParse(flags.Args()[2:])
	case flags.Arg(1) == "verify-key" || flags.Arg(1) == "vk":
		action, exitStatus = verifyKeyCmdParse(flags.Args()[2:])
	case flags.Arg(1) == "verify-chain" || flags.Arg(1) == "vc":
		action, exitStatus = verifyChainCmdParse(*roots, *inters, flags.Args()[2:])
	default:
		flags.Usage()
	}

	if exitStatus != -1 {
		exitWrapper(exitStatus)
	}

	return action, exitStatus
}

func skimCmdParse(files []string) (func(), int) {
	if len(files) == 0 {
		fmt.Print(usage)
		return nil, 1
	}

	return func() {
		skimCerts(files)
	}, -1
}

func verifyChainCmdParse(roots, inters, args []string) (func(), int) {
	if len(roots) == 0 || len(args) != 1 {
		fmt.Print(usage)
		return nil, 1
	}

	return func() {
		verifyChainFromFiles(roots, inters, args[1])
	}, -1
}

func verifyKeyCmdParse(files []string) (func(), int) {
	switch len(files) {
	case 0:
		fmt.Print(usage)
		return nil, 0
	case 2:
	default:
		fmt.Print(usage)
		return nil, 1
	}

	return func() {
		verifyCertAndKey(files[0], files[1])
	}, -1
}

func exitWrapper(exitStatus int) func() int {
	if !mock {
		os.Exit(exitStatus)
	}
	return func() int { return exitStatus }
}
