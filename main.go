package main

import (
	"fmt"
	"github.com/fatih/color"
	"os"
)

const (
	version = "0.4.0"
	website = "https://github.com/nxadm/certmin"
)

func main() {
	action, msg, err := getAction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	if action == nil {
		fmt.Println(msg)
		os.Exit(0)
	}

	output, err := action()
	if output != "" {
		fmt.Println(output)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, color.RedString("error: %s\n"), err)
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
