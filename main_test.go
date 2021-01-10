package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testSerials = []string{
		"1",
		"76359301477803385872276235234032301461",
		"290123421899608141648701916708796095456",
	}
)

//func verifyChainFromFiles(rootFiles, intermediateFiles []string, certFile string) {
func TestVerifyChainFromFiles(t *testing.T) {

}

func TestSplitMultiCertFile(t *testing.T) {
	certs, err := splitMultiCertFile("t/chain.crt")
	assert.NoError(t, err)
	for idx, serial := range testSerials {
		assert.Equal(t, serial, certs[idx].SerialNumber.String())
	}

	_, err = splitMultiCertFile("/dev/null")
	assert.Error(t, err)
	_, err = splitMultiCertFile(strings.Join(testSerials, ""))
	assert.Error(t, err)
	_, err = splitMultiCertFile("t/empty.crt")
	assert.Error(t, err)
}
