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
  verify-key   | vk        : verify that a PEM certificate matches a PEM key.
  verify-chain | vc        : verify that a PEM certificate matches a PEM chain.
    --root                 : root PEM certificates to verify against (at least 1 file). 
    --inter                : intermediate PEM certificates to verify against (0 or more).
  -h           | --help    : This help message.
  -v           | --version : Version message.
`

//[not yet implemented]
//generate-selfsigned | gs : generate a self-signed PEM certificate.

type actionFunc func()

func getAction() func() {
	flag.Usage = func() { fmt.Print(usage) }
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	help := flag.BoolP("help", "h", false, "")
	progVersion := flag.BoolP("version", "v", false, "")
	flag.Parse()

	var exitStatus int
	var action actionFunc
	switch {
	case *help:
		flag.Usage()
	case *progVersion:
		fmt.Println("certmin, " + version)
	case flag.Arg(0) == "skim" || flag.Arg(0) == "s":
		action, exitStatus = skimCmdParse(flag.Args()[1:])
	case flag.Arg(0) == "verify-key" || flag.Arg(0) == "vk":
		action, exitStatus = verifyKeyCmdParse(flag.Args()[1:])
	case flag.Arg(0) == "verify-chain" || flag.Arg(0) == "vc":
		action, exitStatus = verifyChainCmdParse(flag.Args()[1:])
	default:
		flag.Usage()
	}
	if exitStatus != -1 {
		os.Exit(exitStatus)
	}

	return action
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

func verifyChainCmdParse(args []string) (func(), int) {
	flags := flag.NewFlagSet("verify-chain", flag.ExitOnError)
	roots := flags.StringSlice("root", []string{}, "")
	inters := flags.StringSlice("inter", []string{}, "")
	flags.Parse(args)

	if len(*roots) == 0 || len(flags.Args()) != 1 {
		fmt.Print(usage)
		return nil, 1
	}

	return func() {
		verifyChainFromFiles(*roots, *inters, flags.Arg(0))
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
