package main

import (
	"fmt"
	"github.com/fatih/color"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestColourise(t *testing.T) {
	colourKeeper := make(colourKeeper)
	assert.NotEmpty(t, colourKeeper.colourise("0"))
	assert.NotEmpty(t, colourKeeper.colourise("1"))
	assert.NotEmpty(t, colourKeeper.colourise("2"))
	assert.NotEmpty(t, colourKeeper.colourise("3"))
	assert.NotEmpty(t, colourKeeper.colourise("4"))
	assert.NotEmpty(t, colourKeeper.colourise("5"))
	assert.NotEmpty(t, colourKeeper.colourise("6"))
	assert.NotEmpty(t, colourKeeper.colourise("7"))
	assert.Equal(t, "8", colourKeeper.colourise("8"))
}

func TestSkimCerts(t *testing.T) {
	color.NoColor = true
	output, err := skimCerts([]string{"t/myserver.crt"}, false)
	assert.Regexp(t, "Subject:\\s+CN=myserver", output)
	assert.Nil(t, err)

	_, err = skimCerts([]string{"main.go"}, false)
	assert.NotNil(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		output, err = skimCerts([]string{"https://github.com"}, false)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com:443"}, false)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com"}, false)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)

		output, err = skimCerts([]string{"github.com"}, true)
		assert.Regexp(t, "Subject:\\s+CN=github.com", output)
		assert.Nil(t, err)
	}
	color.NoColor = false
}

func TestVerifyChain(t *testing.T) {
	output, err := verifyChain(
		[]string{"t/ca.crt"}, nil, "t/myserver.crt", false)
	assert.Contains(t, output, "the certificate and the chain match")
	assert.Nil(t, err)

	output, err = verifyChain(nil, nil, "", false)
	assert.NotNil(t, err)

	output, err = verifyChain(
		[]string{"t/empty.crt"}, nil, "t/myserver.crt", false)
	assert.Contains(t, output, "the certificate and the chain do not match")
	assert.Nil(t, err)

	output, err = verifyChain([]string{"t/ca.crt"}, nil, "t/chain.crt", false)
	assert.NotNil(t, err)

	output, err = verifyChain(
		[]string{"t/ca.crt"}, nil, "t/myserver-fromca2.crt", false)
	assert.Contains(t, output, "the certificate and the chain do not match")
	assert.Nil(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		output, err = verifyChain(nil, nil, "github.com", true)
		assert.Contains(t, output, "the certificate and the chain match")
		assert.Nil(t, err)

		output, err = verifyChain([]string{"t/ca.crt"}, nil, "github.com", false)
		assert.Contains(t, output, "the certificate and the chain do not match")
		assert.Nil(t, err)
	}
}

func TestVerifyKey(t *testing.T) {
	output, err := verifyKey("t/myserver.crt", "t/myserver.key")
	fmt.Println(output)
	assert.Contains(t, output, "the certificate and key match")
	assert.Nil(t, err)

	output, err = verifyKey("t/myserver.crt", "t/myserver-fromca2.key")
	assert.Contains(t, output, "the certificate and key do not match")
	assert.Nil(t, err)
}
