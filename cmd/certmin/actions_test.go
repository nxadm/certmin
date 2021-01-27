package main

import (
	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestSkimCerts(t *testing.T) {
	color.NoColor = true
	var params Params
	output, err := skimCerts([]string{"t/myserver.crt"}, params)
	assert.Regexp(t, "Subject:\\s+CN=myserver", output)
	assert.Nil(t, err)

	_, err = skimCerts([]string{"main.go"}, params)
	assert.NotNil(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		output, err = skimCerts([]string{"https://github.com"}, params)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com:443"}, params)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com"}, params)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)
	}
	color.NoColor = false
}

func TestVerifyChain(t *testing.T) {
	var params Params
	params.roots = []string{"t/cert-and-chain.crt"}
	output, err := verifyChain([]string{"t/cert-and-chain.crt"}, params)
	assert.Contains(t, output, "its chain match")
	assert.Nil(t, err)

	params.roots = []string{"t/myserver.crt"}
	output, err = verifyChain([]string{"t/cert-and-chain.crt"}, params)
	assert.Contains(t, output, "its chain do not match")
	assert.Nil(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		params.roots = nil
		output, err = verifyChain([]string{"github.com"}, params)
		assert.Contains(t, output, "its chain do not match")
		assert.Nil(t, err)
	}
}

func TestVerifyKey(t *testing.T) {
	var params Params
	params.roots = []string{"t/cert-and-chain.crt"}
	output, err := verifyKey("t/myserver.key", []string{"t/myserver.crt"}, params)
	assert.Contains(t, output, "its key match")
	assert.Nil(t, err)

	output, err = verifyKey("t/myserver.key", []string{"t/myserver-fromca2.crt"}, params)
	assert.Contains(t, output, "do not match")
	assert.Nil(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		output, err = verifyKey("t/myserver.key", []string{"google.com"}, params)
		assert.Contains(t, output, "do not match")
		assert.Nil(t, err)
	}
}
