package main

import (
	"os"
	"strings"
	"testing"
	"text/tabwriter"

	"github.com/nxadm/certmin"
	"github.com/stretchr/testify/assert"
)

func TestColorKeeper_Colourise(t *testing.T) {
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

func TestAppendToCertTree(t *testing.T) {
	certs, err := certmin.DecodeCertFile("t/cert-and-chain.crt", "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Equal(t, 4, len(certs))

	certs2, err := appendToCertTree(certs, []string{"t/myserver.crt", "t/myserver.crt"})
	assert.NoError(t, err)
	assert.NotNil(t, certs2)
	assert.Equal(t, 5, len(certs2))
}

func TestGetCerts(t *testing.T) {
	var sb strings.Builder
	certs, err := getCerts("", &sb)
	assert.Error(t, err)
	assert.Nil(t, certs)

	certs, err = getCerts("t/myserver.crt", &sb)
	assert.NoError(t, err)
	if assert.NotNil(t, certs) {
		assert.Contains(t, certs[0].Subject.CommonName, "myserver")
	}

	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err = getCerts("github.com:443", &sb)
		assert.NoError(t, err)
		if assert.NotNil(t, certs) {
			assert.Contains(t, certs[0].Subject.CommonName, "github")
		}
	}
}

func TestGetLocation(t *testing.T) {
	loc, remote, err := getLocation("util.go")
	assert.NoError(t, err)
	assert.Equal(t, "util.go", loc)
	assert.False(t, remote)

	loc, remote, err = getLocation("foo/fa")
	assert.NoError(t, err)
	assert.Equal(t, "foo/fa", loc)
	assert.True(t, remote)
}

//func printCert(cert *x509.Certificate, w *tabwriter.Writer, colourKeeper colourKeeper) {
func TestPrintCert(t *testing.T) {
	certs, err := certmin.DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 0, 1, ' ', tabwriter.StripEscape)
	colourKeeper := make(colourKeeper)
	printCert(certs[0], w, colourKeeper)
	w.Flush()
	assert.Contains(t, sb.String(), "CN=myserver")
}

func TestPromptForKeyPassword(t *testing.T) {
	t.SkipNow()
}

func TestSerialAsHex(t *testing.T) {
	certs, err := certmin.DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	assert.Equal(t, "ab:4c:df:e9:a2:13:46:9e:6f:ff:36:1d:90:29:5e:be", serialAsHex(certs[0].SerialNumber))
}

func TestWriteCertFiles(t *testing.T) {
	certs, err := certmin.DecodeCertFile("t/cert-and-chain.crt", "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	output, err := writeCertFiles(certs, true)
	assert.NoError(t, err)
	assert.Contains(t, output, ".crt")
}
