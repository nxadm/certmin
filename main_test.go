package main

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestKeepAndPrintOutput(t *testing.T) {
	var sb strings.Builder
	keepAndPrintOutput(&sb, "valid", false)
	keepAndPrintOutput(&sb, "invalid", true)
	assert.Contains(t, sb.String(), "[valid]")
	assert.Contains(t, sb.String(), "[invalid]")
}
