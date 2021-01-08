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
//generate-selfsigned | gs : generate a selfsigned PEM certificate.
//generate-ca         | gc : generate a PEM CA certificate.
//generate-inter      | gi : generate a PEM intermediate CA certificate.

func getAction() func() {
	if len(os.Args) == 1 {
		fmt.Print(usage)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "-h":
		fmt.Print(usage)
		os.Exit(0)
	case "-v":
		fmt.Println("certmin, " + version)
		os.Exit(0)
	case "skim":
		return skimCmdParse()
	case "s":
		return skimCmdParse()
	case "verify-key":
		return verifyKeyCmdParse()
	case "vk":
		return verifyKeyCmdParse()
	case "verify-chain":
		return verifyChainCmdParse()
	case "vc":
		return verifyChainCmdParse()
	default:
		fmt.Print(usage)
		os.Exit(1)
	}

	return func() {}
}

func skimCmdParse() func() {
	helpLong := flag.Bool("help", false, "")
	helpShort := flag.Bool("h", false, "")
	flag.Parse()

	if *helpLong || *helpShort || len(flag.Args()) == 1 {
		fmt.Print(usage)
		os.Exit(0)
	}

	return func() {
		skimCerts(flag.Args()[1:])
	}
}

func verifyChainCmdParse() func() {
	helpLong := flag.Bool("help", false, "")
	helpShort := flag.Bool("h", false, "")
	roots := flag.StringSlice("root", []string{}, "")
	inters := flag.StringSlice("inter", []string{}, "")
	flag.Parse()

	if *helpLong || *helpShort || len(*roots) == 0 || len(flag.Args()) != 2 {
		fmt.Print(usage)
		os.Exit(0)
	}

	return func() {
		verifyChainFromFiles(*roots, *inters, flag.Args()[1])
	}
}

func verifyKeyCmdParse() func() {
	helpLong := flag.Bool("help", false, "")
	helpShort := flag.Bool("h", false, "")
	flag.Parse()

	if *helpLong || *helpShort || len(flag.Args()) != 3 {
		fmt.Print(usage)
		os.Exit(0)
	}

	return func() {
		verifyCertAndKey(flag.Args()[1], flag.Args()[2])
	}
}
