package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	version = "0.2.0"
	website = "https://github.com/nxadm/certmin"
)

func main() {
	action, _ := getAction()
	action()
}

func keepAndPrintOutput(sb *strings.Builder, msg string, isErr bool) {
	if isErr {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	} else {
		fmt.Printf("%s\n", msg)
	}
	sb.WriteString("[" + msg + "]")
}
