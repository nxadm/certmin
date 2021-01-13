package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

//
//var (
//	testSerials = []string{
//		"1",
//		"76359301477803385872276235234032301461",
//		"290123421899608141648701916708796095456",
//	}
//)
//
func TestSkimCerts(t *testing.T) {
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
}

func TestVerifyChain(t *testing.T) {
	output, err := verifyChain(
		[]string{"t/ca.crt"}, nil, "t/myserver.crt", false)
	assert.Contains(t, output, "the certificate matches the chain")
	assert.Nil(t, err)

	output, err = verifyChain(nil, nil, "", false)
	assert.NotNil(t, err)

	output, err = verifyChain(
		[]string{"t/empty.crt"}, nil, "t/myserver.crt", false)
	assert.Contains(t, output, "the certificate does not match the chain")
	assert.Nil(t, err)

	output, err = verifyChain([]string{"t/ca.crt"}, nil, "t/chain.crt", false)
	assert.NotNil(t, err)

	output, err = verifyChain(
		[]string{"t/ca.crt"}, nil, "t/myserver-fromca2.crt", false)
	assert.Contains(t, output, "the certificate does not match the chain")
	assert.Nil(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		output, err = verifyChain(nil, nil, "github.com", true)
		assert.Contains(t, output, "the certificate matches the chain")
		assert.Nil(t, err)

		output, err = verifyChain([]string{"t/ca.crt"}, nil, "github.com", false)
		assert.Contains(t, output, "the certificate does not match the chain")
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
