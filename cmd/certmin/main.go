package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

const (
	version = "0.5.0"
	website = "https://github.com/nxadm/certmin"
)

type colourKeeper map[string]int

// Only colourise the 8 first subjects
func (colourKeeper *colourKeeper) colourise(msg string) string {
	colourStr := make(map[int]func(format string, a ...interface{}) string)
	colourStr[0] = color.GreenString
	colourStr[1] = color.BlueString
	colourStr[2] = color.MagentaString
	colourStr[3] = color.CyanString
	colourStr[4] = color.HiGreenString
	colourStr[5] = color.HiBlueString
	colourStr[6] = color.HiMagentaString
	colourStr[7] = color.HiCyanString
	if idx, ok := (*colourKeeper)[msg]; ok {
		return colourStr[idx](msg)
	}
	if len(*colourKeeper) < 8 {
		idx := len(*colourKeeper)
		(*colourKeeper)[msg] = idx
		return colourStr[idx](msg)
	}
	return msg
}

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
